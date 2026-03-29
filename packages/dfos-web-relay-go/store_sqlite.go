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
`

// SQLiteStore is a durable Store backed by SQLite.
type SQLiteStore struct {
	db     *sql.DB // write connection (single writer)
	readDB *sql.DB // read connection pool (concurrent reads)
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
	row := s.readDB.QueryRow("SELECT cid, jws_token, chain_type, chain_id FROM operations WHERE cid = ?", cid)
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
	_, err := s.db.Exec(
		"INSERT OR REPLACE INTO operations (cid, jws_token, chain_type, chain_id) VALUES (?, ?, ?, ?)",
		op.CID, op.JWSToken, op.ChainType, op.ChainID,
	)
	return err
}

// ---------------------------------------------------------------------------
// identity chains
// ---------------------------------------------------------------------------

func (s *SQLiteStore) GetIdentityChain(did string) (*StoredIdentityChain, error) {
	row := s.readDB.QueryRow("SELECT did, log, head_cid, last_created_at, state FROM identity_chains WHERE did = ?", did)
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
	_, err = s.db.Exec(
		"INSERT OR REPLACE INTO identity_chains (did, log, head_cid, last_created_at, state) VALUES (?, ?, ?, ?, ?)",
		chain.DID, logJSON, chain.HeadCID, chain.LastCreatedAt, stateJSON,
	)
	return err
}

// ---------------------------------------------------------------------------
// content chains
// ---------------------------------------------------------------------------

func (s *SQLiteStore) GetContentChain(contentID string) (*StoredContentChain, error) {
	row := s.readDB.QueryRow("SELECT content_id, genesis_cid, log, last_created_at, state FROM content_chains WHERE content_id = ?", contentID)
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
	_, err = s.db.Exec(
		"INSERT OR REPLACE INTO content_chains (content_id, genesis_cid, log, last_created_at, state) VALUES (?, ?, ?, ?, ?)",
		chain.ContentID, chain.GenesisCID, logJSON, chain.LastCreatedAt, stateJSON,
	)
	return err
}

// ---------------------------------------------------------------------------
// beacons
// ---------------------------------------------------------------------------

func (s *SQLiteStore) GetBeacon(did string) (*StoredBeacon, error) {
	row := s.readDB.QueryRow("SELECT did, jws_token, beacon_cid, payload FROM beacons WHERE did = ?", did)
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
	_, err = s.db.Exec(
		"INSERT OR REPLACE INTO beacons (did, jws_token, beacon_cid, payload) VALUES (?, ?, ?, ?)",
		beacon.DID, beacon.JWSToken, beacon.BeaconCID, payloadJSON,
	)
	return err
}

// ---------------------------------------------------------------------------
// blobs
// ---------------------------------------------------------------------------

func (s *SQLiteStore) GetBlob(key BlobKey) ([]byte, error) {
	row := s.readDB.QueryRow("SELECT data FROM blobs WHERE creator_did = ? AND document_cid = ?", key.CreatorDID, key.DocumentCID)
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
	_, err := s.db.Exec(
		"INSERT OR REPLACE INTO blobs (creator_did, document_cid, data) VALUES (?, ?, ?)",
		key.CreatorDID, key.DocumentCID, data,
	)
	return err
}

// ---------------------------------------------------------------------------
// countersignatures
// ---------------------------------------------------------------------------

func (s *SQLiteStore) GetCountersignatures(operationCID string) ([]string, error) {
	rows, err := s.readDB.Query("SELECT jws_token FROM countersignatures WHERE operation_cid = ?", operationCID)
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
	_, err = s.db.Exec(
		"INSERT OR IGNORE INTO countersignatures (operation_cid, jws_token, witness_did) VALUES (?, ?, ?)",
		operationCID, jwsToken, witnessDID,
	)
	return err
}

// ---------------------------------------------------------------------------
// operation log
// ---------------------------------------------------------------------------

func (s *SQLiteStore) AppendToLog(entry LogEntry) error {
	_, err := s.db.Exec(
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
		rows, err = s.readDB.Query(
			`SELECT cid, jws_token, kind, chain_id FROM operation_log
			 WHERE seq > (SELECT COALESCE((SELECT seq FROM operation_log WHERE cid = ? LIMIT 1), 999999999))
			 ORDER BY seq ASC LIMIT ?`,
			after, limit,
		)
	} else {
		rows, err = s.readDB.Query(
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
	row := s.readDB.QueryRow("SELECT cursor FROM peer_cursors WHERE peer_url = ?", peerURL)
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
	_, err := s.db.Exec(
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
	row := s.readDB.QueryRow("SELECT value FROM relay_meta WHERE key = ?", key)
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
	_, err := s.db.Exec(
		"INSERT OR REPLACE INTO relay_meta (key, value) VALUES (?, ?)",
		key, value,
	)
	return err
}
