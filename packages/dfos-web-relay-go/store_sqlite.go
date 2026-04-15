package relay

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS operations (
	cid TEXT PRIMARY KEY,
	jws_token TEXT NOT NULL,
	chain_type TEXT NOT NULL,
	chain_id TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS identity_chains (
	did TEXT PRIMARY KEY,
	log JSON NOT NULL,
	head_cid TEXT NOT NULL,
	last_created_at TEXT NOT NULL,
	state JSON NOT NULL
);

CREATE TABLE IF NOT EXISTS content_chains (
	content_id TEXT PRIMARY KEY,
	genesis_cid TEXT NOT NULL,
	log JSON NOT NULL,
	last_created_at TEXT NOT NULL,
	state JSON NOT NULL
);

CREATE TABLE IF NOT EXISTS beacons (
	did TEXT PRIMARY KEY,
	jws_token TEXT NOT NULL,
	beacon_cid TEXT NOT NULL,
	payload JSON NOT NULL
);

CREATE TABLE IF NOT EXISTS countersignatures (
	operation_cid TEXT NOT NULL,
	jws_token TEXT NOT NULL,
	witness_did TEXT NOT NULL,
	UNIQUE(operation_cid, witness_did)
);

CREATE TABLE IF NOT EXISTS operation_log (
	seq INTEGER PRIMARY KEY AUTOINCREMENT,
	cid TEXT NOT NULL,
	jws_token TEXT NOT NULL,
	kind TEXT NOT NULL,
	chain_id TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS blobs (
	creator_did TEXT NOT NULL,
	document_cid TEXT NOT NULL,
	data BLOB NOT NULL,
	PRIMARY KEY (creator_did, document_cid)
);

CREATE INDEX IF NOT EXISTS idx_operation_log_cid ON operation_log(cid);

CREATE TABLE IF NOT EXISTS peer_cursors (
	peer_url TEXT PRIMARY KEY,
	cursor TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS relay_meta (
	key TEXT PRIMARY KEY,
	value BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS raw_ops (
	cid TEXT PRIMARY KEY,
	jws_token TEXT NOT NULL,
	status TEXT NOT NULL DEFAULT 'pending',
	error TEXT,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_raw_ops_status ON raw_ops(status);

DROP TABLE IF EXISTS pending_ops;

CREATE TABLE IF NOT EXISTS revocations (
	cid TEXT PRIMARY KEY,
	issuer_did TEXT NOT NULL,
	credential_cid TEXT NOT NULL,
	jws_token TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_revocations_issuer ON revocations(issuer_did);
CREATE UNIQUE INDEX IF NOT EXISTS idx_revocations_scope ON revocations(issuer_did, credential_cid);

CREATE TABLE IF NOT EXISTS public_credentials (
	cid TEXT PRIMARY KEY,
	issuer_did TEXT NOT NULL,
	att JSON NOT NULL,
	exp INTEGER NOT NULL,
	jws_token TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_public_credentials_exp ON public_credentials(exp);
`

// SQLiteStore is a durable Store backed by SQLite.
//
// The readOnly flag controls readerDB() behavior. When false (default for the
// ingestion store), readerDB() returns the active write transaction so that
// within-batch reads see uncommitted writes. When true (for the HTTP read
// store), readerDB() always returns the WAL read pool — safe for concurrent
// use while ingestion holds a write transaction.
type SQLiteStore struct {
	db       *sql.DB // write connection (single writer)
	readDB   *sql.DB // read connection pool (concurrent reads)
	tx       *sql.Tx // active write batch transaction, if any
	readOnly bool    // if true, readerDB() never returns tx
}

// writerDB returns the active transaction if one exists, otherwise the raw db.
func (s *SQLiteStore) writerDB() dbConn {
	if s.tx != nil {
		return s.tx
	}
	return s.db
}

// readerDB returns the read connection to use. For the ingestion store
// (readOnly=false), returns the active transaction if one exists so within-
// batch reads see uncommitted writes. For the HTTP read store (readOnly=true),
// always returns the WAL read pool.
func (s *SQLiteStore) readerDB() dbConn {
	if !s.readOnly && s.tx != nil {
		return s.tx
	}
	return s.readDB
}

// ReadStore returns a Store that shares this store's database connections but
// always reads from the WAL read pool, never from an active write transaction.
// Use this for HTTP handlers that run concurrently with ingestion.
func (s *SQLiteStore) ReadStore() *SQLiteStore {
	return &SQLiteStore{db: s.db, readDB: s.readDB, readOnly: true}
}

// dbConn is the common interface between *sql.DB and *sql.Tx.
type dbConn interface {
	Exec(query string, args ...any) (sql.Result, error)
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
}

// BeginWriteBatch starts a SQLite transaction for batching writes.
// Only safe to call when the caller holds exclusive write access (e.g. ingestMu).
func (s *SQLiteStore) BeginWriteBatch() error {
	if s.tx != nil {
		return fmt.Errorf("write batch already active")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	s.tx = tx
	return nil
}

// CommitWriteBatch commits the active write batch transaction.
func (s *SQLiteStore) CommitWriteBatch() error {
	if s.tx == nil {
		return fmt.Errorf("no write batch active")
	}
	err := s.tx.Commit()
	s.tx = nil
	return err
}

// RollbackWriteBatch rolls back the active write batch transaction.
func (s *SQLiteStore) RollbackWriteBatch() error {
	if s.tx == nil {
		return nil
	}
	err := s.tx.Rollback()
	s.tx = nil
	return err
}

// NewSQLiteStore opens or creates a SQLite database at the given path
// and initializes the schema. Use ":memory:" for an ephemeral database.
func NewSQLiteStore(path string) (*SQLiteStore, error) {
	// Write connection — single writer, serialized
	writeDB, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	writeDB.SetMaxOpenConns(1)

	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA cache_size=-20000",
	} {
		if _, err := writeDB.Exec(pragma); err != nil {
			writeDB.Close()
			return nil, fmt.Errorf("%s: %w", pragma, err)
		}
	}

	// Read connection — separate pool for concurrent reads (auth, queries)
	// WAL mode allows concurrent readers alongside a single writer
	readDB, err := sql.Open("sqlite", path)
	if err != nil {
		writeDB.Close()
		return nil, fmt.Errorf("open sqlite read: %w", err)
	}
	readDB.SetMaxOpenConns(4)

	for _, pragma := range []string{
		"PRAGMA busy_timeout=5000",
		"PRAGMA cache_size=-20000",
	} {
		if _, err := readDB.Exec(pragma); err != nil {
			writeDB.Close()
			readDB.Close()
			return nil, fmt.Errorf("read %s: %w", pragma, err)
		}
	}

	// create tables (on write connection)
	if _, err := writeDB.Exec(schema); err != nil {
		writeDB.Close()
		readDB.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}

	return &SQLiteStore{db: writeDB, readDB: readDB}, nil
}

// Close closes the underlying database connection.
func (s *SQLiteStore) Close() error {
	s.readDB.Close()
	return s.db.Close()
}

// ---------------------------------------------------------------------------
// operations
// ---------------------------------------------------------------------------

func (s *SQLiteStore) GetOperation(cid string) (*StoredOperation, error) {
	row := s.readerDB().QueryRow("SELECT cid, jws_token, chain_type, chain_id FROM operations WHERE cid = ?", cid)
	var op StoredOperation
	err := row.Scan(&op.CID, &op.JWSToken, &op.ChainType, &op.ChainID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &op, nil
}

func (s *SQLiteStore) PutOperation(op StoredOperation) error {
	_, err := s.writerDB().Exec(
		"INSERT OR REPLACE INTO operations (cid, jws_token, chain_type, chain_id) VALUES (?, ?, ?, ?)",
		op.CID, op.JWSToken, op.ChainType, op.ChainID,
	)
	return err
}

// ---------------------------------------------------------------------------
// identity chains
// ---------------------------------------------------------------------------

func (s *SQLiteStore) GetIdentityChain(did string) (*StoredIdentityChain, error) {
	row := s.readerDB().QueryRow("SELECT did, log, head_cid, last_created_at, state FROM identity_chains WHERE did = ?", did)
	var chain StoredIdentityChain
	var logJSON, stateJSON []byte
	err := row.Scan(&chain.DID, &logJSON, &chain.HeadCID, &chain.LastCreatedAt, &stateJSON)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(logJSON, &chain.Log); err != nil {
		return nil, fmt.Errorf("unmarshal identity log: %w", err)
	}
	if err := json.Unmarshal(stateJSON, &chain.State); err != nil {
		return nil, fmt.Errorf("unmarshal identity state: %w", err)
	}
	return &chain, nil
}

func (s *SQLiteStore) PutIdentityChain(chain StoredIdentityChain) error {
	logJSON, err := json.Marshal(chain.Log)
	if err != nil {
		return err
	}
	stateJSON, err := json.Marshal(chain.State)
	if err != nil {
		return err
	}
	_, err = s.writerDB().Exec(
		"INSERT OR REPLACE INTO identity_chains (did, log, head_cid, last_created_at, state) VALUES (?, ?, ?, ?, ?)",
		chain.DID, logJSON, chain.HeadCID, chain.LastCreatedAt, stateJSON,
	)
	return err
}

// ---------------------------------------------------------------------------
// content chains
// ---------------------------------------------------------------------------

func (s *SQLiteStore) GetContentChain(contentID string) (*StoredContentChain, error) {
	row := s.readerDB().QueryRow("SELECT content_id, genesis_cid, log, last_created_at, state FROM content_chains WHERE content_id = ?", contentID)
	var chain StoredContentChain
	var logJSON, stateJSON []byte
	err := row.Scan(&chain.ContentID, &chain.GenesisCID, &logJSON, &chain.LastCreatedAt, &stateJSON)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(logJSON, &chain.Log); err != nil {
		return nil, fmt.Errorf("unmarshal content log: %w", err)
	}
	if err := json.Unmarshal(stateJSON, &chain.State); err != nil {
		return nil, fmt.Errorf("unmarshal content state: %w", err)
	}
	return &chain, nil
}

func (s *SQLiteStore) PutContentChain(chain StoredContentChain) error {
	logJSON, err := json.Marshal(chain.Log)
	if err != nil {
		return err
	}
	stateJSON, err := json.Marshal(chain.State)
	if err != nil {
		return err
	}
	_, err = s.writerDB().Exec(
		"INSERT OR REPLACE INTO content_chains (content_id, genesis_cid, log, last_created_at, state) VALUES (?, ?, ?, ?, ?)",
		chain.ContentID, chain.GenesisCID, logJSON, chain.LastCreatedAt, stateJSON,
	)
	return err
}

// ---------------------------------------------------------------------------
// beacons
// ---------------------------------------------------------------------------

func (s *SQLiteStore) GetBeacon(did string) (*StoredBeacon, error) {
	row := s.readerDB().QueryRow("SELECT did, jws_token, beacon_cid, payload FROM beacons WHERE did = ?", did)
	var beacon StoredBeacon
	var payloadJSON []byte
	err := row.Scan(&beacon.DID, &beacon.JWSToken, &beacon.BeaconCID, &payloadJSON)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(payloadJSON, &beacon.Payload); err != nil {
		return nil, fmt.Errorf("unmarshal beacon payload: %w", err)
	}
	return &beacon, nil
}

func (s *SQLiteStore) PutBeacon(beacon StoredBeacon) error {
	payloadJSON, err := json.Marshal(beacon.Payload)
	if err != nil {
		return err
	}
	_, err = s.writerDB().Exec(
		"INSERT OR REPLACE INTO beacons (did, jws_token, beacon_cid, payload) VALUES (?, ?, ?, ?)",
		beacon.DID, beacon.JWSToken, beacon.BeaconCID, payloadJSON,
	)
	return err
}

// ---------------------------------------------------------------------------
// listing
// ---------------------------------------------------------------------------

func (s *SQLiteStore) ListIdentityChains() ([]StoredIdentityChain, error) {
	rows, err := s.readerDB().Query("SELECT did, log, head_cid, last_created_at, state FROM identity_chains")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var chains []StoredIdentityChain
	for rows.Next() {
		var chain StoredIdentityChain
		var logJSON, stateJSON []byte
		if err := rows.Scan(&chain.DID, &logJSON, &chain.HeadCID, &chain.LastCreatedAt, &stateJSON); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(logJSON, &chain.Log); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(stateJSON, &chain.State); err != nil {
			return nil, err
		}
		chains = append(chains, chain)
	}
	if chains == nil {
		chains = []StoredIdentityChain{}
	}
	return chains, rows.Err()
}

func (s *SQLiteStore) ListContentChains() ([]StoredContentChain, error) {
	rows, err := s.readerDB().Query("SELECT content_id, genesis_cid, log, last_created_at, state FROM content_chains")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var chains []StoredContentChain
	for rows.Next() {
		var chain StoredContentChain
		var logJSON, stateJSON []byte
		if err := rows.Scan(&chain.ContentID, &chain.GenesisCID, &logJSON, &chain.LastCreatedAt, &stateJSON); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(logJSON, &chain.Log); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(stateJSON, &chain.State); err != nil {
			return nil, err
		}
		chains = append(chains, chain)
	}
	if chains == nil {
		chains = []StoredContentChain{}
	}
	return chains, rows.Err()
}

func (s *SQLiteStore) ListBeacons() ([]StoredBeacon, error) {
	rows, err := s.readerDB().Query("SELECT did, jws_token, beacon_cid, payload FROM beacons")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var beacons []StoredBeacon
	for rows.Next() {
		var beacon StoredBeacon
		var payloadJSON []byte
		if err := rows.Scan(&beacon.DID, &beacon.JWSToken, &beacon.BeaconCID, &payloadJSON); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(payloadJSON, &beacon.Payload); err != nil {
			return nil, err
		}
		beacons = append(beacons, beacon)
	}
	if beacons == nil {
		beacons = []StoredBeacon{}
	}
	return beacons, rows.Err()
}

// ---------------------------------------------------------------------------
// blobs
// ---------------------------------------------------------------------------

func (s *SQLiteStore) GetBlob(key BlobKey) ([]byte, error) {
	row := s.readerDB().QueryRow("SELECT data FROM blobs WHERE creator_did = ? AND document_cid = ?", key.CreatorDID, key.DocumentCID)
	var data []byte
	err := row.Scan(&data)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (s *SQLiteStore) PutBlob(key BlobKey, data []byte) error {
	_, err := s.writerDB().Exec(
		"INSERT OR REPLACE INTO blobs (creator_did, document_cid, data) VALUES (?, ?, ?)",
		key.CreatorDID, key.DocumentCID, data,
	)
	return err
}

// ---------------------------------------------------------------------------
// countersignatures
// ---------------------------------------------------------------------------

func (s *SQLiteStore) GetCountersignatures(operationCID string) ([]string, error) {
	rows, err := s.readerDB().Query("SELECT jws_token FROM countersignatures WHERE operation_cid = ?", operationCID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []string
	for rows.Next() {
		var token string
		if err := rows.Scan(&token); err != nil {
			return nil, err
		}
		tokens = append(tokens, token)
	}
	if tokens == nil {
		return []string{}, nil
	}
	return tokens, rows.Err()
}

func (s *SQLiteStore) AddCountersignature(operationCID string, jwsToken string) error {
	// extract witness DID from kid header for dedup
	witnessDID := ""
	header, _, err := dfos.DecodeJWSUnsafe(jwsToken)
	if err == nil && header != nil {
		kid := header.Kid
		if idx := strings.Index(kid, "#"); idx >= 0 {
			witnessDID = kid[:idx]
		} else {
			witnessDID = kid
		}
	}

	// INSERT OR IGNORE deduplicates by (operation_cid, witness_did)
	_, err = s.writerDB().Exec(
		"INSERT OR IGNORE INTO countersignatures (operation_cid, jws_token, witness_did) VALUES (?, ?, ?)",
		operationCID, jwsToken, witnessDID,
	)
	return err
}

// ---------------------------------------------------------------------------
// operation log
// ---------------------------------------------------------------------------

func (s *SQLiteStore) AppendToLog(entry LogEntry) error {
	_, err := s.writerDB().Exec(
		"INSERT INTO operation_log (cid, jws_token, kind, chain_id) VALUES (?, ?, ?, ?)",
		entry.CID, entry.JWSToken, entry.Kind, entry.ChainID,
	)
	return err
}

func (s *SQLiteStore) ReadLog(after string, limit int) ([]LogEntry, string, error) {
	var rows *sql.Rows
	var err error

	if after != "" {
		// find the seq of the cursor CID, then fetch after it
		rows, err = s.readerDB().Query(
			`SELECT cid, jws_token, kind, chain_id FROM operation_log
			 WHERE seq > (SELECT COALESCE((SELECT seq FROM operation_log WHERE cid = ? LIMIT 1), 999999999))
			 ORDER BY seq ASC LIMIT ?`,
			after, limit,
		)
	} else {
		rows, err = s.readerDB().Query(
			"SELECT cid, jws_token, kind, chain_id FROM operation_log ORDER BY seq ASC LIMIT ?",
			limit,
		)
	}
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()

	var entries []LogEntry
	for rows.Next() {
		var e LogEntry
		if err := rows.Scan(&e.CID, &e.JWSToken, &e.Kind, &e.ChainID); err != nil {
			return nil, "", err
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	if entries == nil {
		entries = []LogEntry{}
	}

	var cursor string
	if len(entries) == limit {
		cursor = entries[len(entries)-1].CID
	}

	return entries, cursor, nil
}

// GetIdentityStateAtCID replays the identity chain from genesis to the target CID.
// For SQLite, this could use snapshots in the future; for now it replays fully.
func (s *SQLiteStore) GetIdentityStateAtCID(did, cid string) (*IdentityStateAtCID, error) {
	chain, err := s.GetIdentityChain(did)
	if err != nil || chain == nil {
		return nil, err
	}

	type opInfo struct {
		jws         string
		previousCID string
	}
	opsByCID := make(map[string]opInfo)
	for _, jws := range chain.Log {
		header, payload, err := dfos.DecodeJWSUnsafe(jws)
		if err != nil || header == nil {
			continue
		}
		prevCID, _ := payload["previousOperationCID"].(string)
		opsByCID[header.CID] = opInfo{jws: jws, previousCID: prevCID}
	}

	if _, ok := opsByCID[cid]; !ok {
		return nil, nil
	}

	var path []string
	currentCID := cid
	for currentCID != "" {
		op, ok := opsByCID[currentCID]
		if !ok {
			return nil, nil
		}
		path = append([]string{op.jws}, path...)
		currentCID = op.previousCID
	}

	result, err := dfos.VerifyIdentityChain(path)
	if err != nil {
		return nil, err
	}

	targetOp := opsByCID[cid]
	_, targetPayload, _ := dfos.DecodeJWSUnsafe(targetOp.jws)
	lastCreatedAt, _ := targetPayload["createdAt"].(string)

	return &IdentityStateAtCID{State: result.State, LastCreatedAt: lastCreatedAt}, nil
}

func (s *SQLiteStore) GetContentStateAtCID(contentID, cid string) (*ContentStateAtCID, error) {
	chain, err := s.GetContentChain(contentID)
	if err != nil || chain == nil {
		return nil, err
	}

	type opInfo struct {
		jws         string
		previousCID string
	}
	opsByCID := make(map[string]opInfo)
	for _, jws := range chain.Log {
		header, payload, err := dfos.DecodeJWSUnsafe(jws)
		if err != nil || header == nil {
			continue
		}
		prevCID, _ := payload["previousOperationCID"].(string)
		opsByCID[header.CID] = opInfo{jws: jws, previousCID: prevCID}
	}

	if _, ok := opsByCID[cid]; !ok {
		return nil, nil
	}

	var path []string
	currentCID := cid
	for currentCID != "" {
		op, ok := opsByCID[currentCID]
		if !ok {
			return nil, nil
		}
		path = append([]string{op.jws}, path...)
		currentCID = op.previousCID
	}

	resolveKey := CreateKeyResolver(s)
	result, err := dfos.VerifyContentChain(path, resolveKey, true)
	if err != nil {
		return nil, err
	}

	targetOp := opsByCID[cid]
	_, targetPayload, _ := dfos.DecodeJWSUnsafe(targetOp.jws)
	lastCreatedAt, _ := targetPayload["createdAt"].(string)

	return &ContentStateAtCID{State: result.State, LastCreatedAt: lastCreatedAt}, nil
}

func (s *SQLiteStore) GetPeerCursor(peerURL string) (string, error) {
	row := s.readerDB().QueryRow("SELECT cursor FROM peer_cursors WHERE peer_url = ?", peerURL)
	var cursor string
	err := row.Scan(&cursor)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return cursor, nil
}

func (s *SQLiteStore) SetPeerCursor(peerURL string, cursor string) error {
	_, err := s.writerDB().Exec(
		"INSERT OR REPLACE INTO peer_cursors (peer_url, cursor) VALUES (?, ?)",
		peerURL, cursor,
	)
	return err
}

// ---------------------------------------------------------------------------
// relay metadata (key persistence, etc.)
// ---------------------------------------------------------------------------

// GetMeta returns the value for a metadata key, or nil if not found.
func (s *SQLiteStore) GetMeta(key string) ([]byte, error) {
	row := s.readerDB().QueryRow("SELECT value FROM relay_meta WHERE key = ?", key)
	var value []byte
	err := row.Scan(&value)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return value, nil
}

// SetMeta stores a metadata key-value pair (upsert).
func (s *SQLiteStore) SetMeta(key string, value []byte) error {
	_, err := s.writerDB().Exec(
		"INSERT OR REPLACE INTO relay_meta (key, value) VALUES (?, ?)",
		key, value,
	)
	return err
}

// ---------------------------------------------------------------------------
// raw ops
// ---------------------------------------------------------------------------

// PutRawOp stores a JWS token in the content-addressed raw op store.
// Idempotent — ignores duplicates.
func (s *SQLiteStore) PutRawOp(cid string, jwsToken string) error {
	_, err := s.writerDB().Exec(
		"INSERT OR IGNORE INTO raw_ops (cid, jws_token) VALUES (?, ?)",
		cid, jwsToken,
	)
	return err
}

// GetUnsequencedOps returns JWS tokens for ops that haven't been sequenced yet.
func (s *SQLiteStore) GetUnsequencedOps(limit int) ([]string, error) {
	rows, err := s.readerDB().Query(
		"SELECT jws_token FROM raw_ops WHERE status = 'pending' ORDER BY created_at ASC LIMIT ?",
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tokens []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

// MarkOpsSequenced marks the given CIDs as successfully sequenced.
func (s *SQLiteStore) MarkOpsSequenced(cids []string) error {
	w := s.writerDB()
	for _, cid := range cids {
		w.Exec("UPDATE raw_ops SET status = 'sequenced' WHERE cid = ?", cid)
	}
	return nil
}

// MarkOpRejected marks a CID as permanently rejected with a reason.
func (s *SQLiteStore) MarkOpRejected(cid string, reason string) error {
	_, err := s.writerDB().Exec(
		"UPDATE raw_ops SET status = 'rejected', error = ? WHERE cid = ?",
		reason, cid,
	)
	return err
}

// CountUnsequenced returns the number of pending (unsequenced) raw ops.
func (s *SQLiteStore) CountUnsequenced() (int, error) {
	var count int
	err := s.readerDB().QueryRow("SELECT COUNT(*) FROM raw_ops WHERE status = 'pending'").Scan(&count)
	return count, err
}

// ---------------------------------------------------------------------------
// revocations (stub)
// ---------------------------------------------------------------------------

func (s *SQLiteStore) GetRevocations(issuerDID string) ([]string, error) {
	rows, err := s.readerDB().Query("SELECT credential_cid FROM revocations WHERE issuer_did = ?", issuerDID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cids := []string{}
	for rows.Next() {
		var cid string
		if err := rows.Scan(&cid); err != nil {
			return nil, err
		}
		cids = append(cids, cid)
	}
	return cids, rows.Err()
}

func (s *SQLiteStore) AddRevocation(revocation StoredRevocation) error {
	_, err := s.writerDB().Exec(
		"INSERT OR IGNORE INTO revocations (cid, issuer_did, credential_cid, jws_token) VALUES (?, ?, ?, ?)",
		revocation.CID, revocation.IssuerDID, revocation.CredentialCID, revocation.JWSToken,
	)
	return err
}

func (s *SQLiteStore) IsCredentialRevoked(issuerDID string, credentialCID string) (bool, error) {
	var exists int
	err := s.readerDB().QueryRow(
		"SELECT 1 FROM revocations WHERE issuer_did = ? AND credential_cid = ? LIMIT 1",
		issuerDID, credentialCID,
	).Scan(&exists)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// ---------------------------------------------------------------------------
// public credentials (standing authorization)
// ---------------------------------------------------------------------------

func (s *SQLiteStore) GetPublicCredentials(resource string) ([]string, error) {
	// Build a query that unnests the att JSON array and matches on resource.
	// We handle two cases:
	//   1. Exact match on resource
	//   2. chain:* matches any chain: resource
	var query string
	var args []any

	if strings.HasPrefix(resource, "chain:") {
		query = `SELECT DISTINCT pc.jws_token FROM public_credentials pc, json_each(pc.att) je
			WHERE json_extract(je.value, '$.resource') = ?
			   OR json_extract(je.value, '$.resource') = 'chain:*'`
		args = []any{resource}
	} else {
		query = `SELECT DISTINCT pc.jws_token FROM public_credentials pc, json_each(pc.att) je
			WHERE json_extract(je.value, '$.resource') = ?`
		args = []any{resource}
	}

	rows, err := s.readerDB().Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tokens := []string{}
	for rows.Next() {
		var token string
		if err := rows.Scan(&token); err != nil {
			return nil, err
		}
		tokens = append(tokens, token)
	}
	return tokens, rows.Err()
}

func (s *SQLiteStore) AddPublicCredential(credential StoredPublicCredential) error {
	attJSON, err := json.Marshal(credential.Att)
	if err != nil {
		return err
	}
	_, err = s.writerDB().Exec(
		"INSERT OR IGNORE INTO public_credentials (cid, issuer_did, att, exp, jws_token) VALUES (?, ?, ?, ?, ?)",
		credential.CID, credential.IssuerDID, attJSON, credential.Exp, credential.JWSToken,
	)
	return err
}

func (s *SQLiteStore) RemovePublicCredential(credentialCID string) error {
	_, err := s.writerDB().Exec("DELETE FROM public_credentials WHERE cid = ?", credentialCID)
	return err
}

// ---------------------------------------------------------------------------
// documents
// ---------------------------------------------------------------------------

func (s *SQLiteStore) GetDocuments(contentID string, after string, limit int) ([]StoredDocument, string, error) {
	chain, err := s.GetContentChain(contentID)
	if err != nil {
		return nil, "", err
	}
	if chain == nil {
		return []StoredDocument{}, "", nil
	}

	// build entries from chain log
	type docEntry struct {
		operationCID string
		documentCID  *string
		signerDID    string
		createdAt    string
	}
	var entries []docEntry
	for _, jws := range chain.Log {
		header, payload, err := dfos.DecodeJWSUnsafe(jws)
		if err != nil || header == nil {
			continue
		}
		opCID := header.CID
		signerDID, _ := payload["did"].(string)
		createdAt, _ := payload["createdAt"].(string)
		var docCID *string
		if d, ok := payload["documentCID"].(string); ok {
			docCID = &d
		}
		entries = append(entries, docEntry{
			operationCID: opCID,
			documentCID:  docCID,
			signerDID:    signerDID,
			createdAt:    createdAt,
		})
	}

	// apply cursor pagination
	startIdx := 0
	if after != "" {
		found := false
		for i, e := range entries {
			if e.operationCID == after {
				startIdx = i + 1
				found = true
				break
			}
		}
		if !found {
			startIdx = len(entries)
		}
	}

	end := startIdx + limit
	if end > len(entries) {
		end = len(entries)
	}
	page := entries[startIdx:end]

	// build StoredDocument slice, reading blobs for each entry
	docs := make([]StoredDocument, 0, len(page))
	for _, e := range page {
		var document any
		if e.documentCID != nil {
			data, err := s.GetBlob(BlobKey{CreatorDID: chain.State.CreatorDID, DocumentCID: *e.documentCID})
			if err != nil {
				return nil, "", fmt.Errorf("read blob: %w", err)
			}
			if data != nil {
				_ = json.Unmarshal(data, &document)
			}
		}
		docs = append(docs, StoredDocument{
			OperationCID: e.operationCID,
			DocumentCID:  e.documentCID,
			Document:     document,
			SignerDID:    e.signerDID,
			CreatedAt:    e.createdAt,
		})
	}

	var cursor string
	if len(page) == limit {
		cursor = page[len(page)-1].operationCID
	}

	return docs, cursor, nil
}

// ---------------------------------------------------------------------------
// admin
// ---------------------------------------------------------------------------

// ResetPeerCursors clears all peer cursors, forcing a full re-sync.
func (s *SQLiteStore) ResetPeerCursors() error {
	_, err := s.writerDB().Exec("DELETE FROM peer_cursors")
	return err
}

// ResetSequencer marks all non-rejected raw ops as pending for re-sequencing.
func (s *SQLiteStore) ResetSequencer() error {
	_, err := s.writerDB().Exec("UPDATE raw_ops SET status = 'pending' WHERE status != 'rejected'")
	return err
}
