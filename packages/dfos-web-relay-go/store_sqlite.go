package relay

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
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
CREATE INDEX IF NOT EXISTS idx_revocations_credential ON revocations(credential_cid);

CREATE TABLE IF NOT EXISTS public_credentials (
	cid TEXT PRIMARY KEY,
	issuer_did TEXT NOT NULL,
	att JSON NOT NULL,
	exp INTEGER NOT NULL,
	jws_token TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_public_credentials_exp ON public_credentials(exp);

-- index (v0) materialized projection: flat-column rows the ingestion pipeline
-- maintains incrementally so a /index/v0 page costs O(page), not O(corpus).
CREATE TABLE IF NOT EXISTS index_identity (
	did TEXT PRIMARY KEY,
	head_cid TEXT NOT NULL,
	op_count INTEGER NOT NULL,
	genesis_at TEXT NOT NULL,
	head_at TEXT NOT NULL,
	is_deleted INTEGER NOT NULL,
	profile_anchor TEXT,
	profile_public_read INTEGER,
	profile_doc_schema TEXT,
	profile_name TEXT,
	has_public_profile INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_index_identity_anchor ON index_identity(profile_anchor);
CREATE INDEX IF NOT EXISTS idx_index_identity_public ON index_identity(has_public_profile, did);

CREATE TABLE IF NOT EXISTS index_content (
	content_id TEXT PRIMARY KEY,
	genesis_cid TEXT NOT NULL,
	head_cid TEXT NOT NULL,
	creator_did TEXT NOT NULL,
	is_deleted INTEGER NOT NULL,
	op_count INTEGER NOT NULL,
	genesis_at TEXT NOT NULL,
	head_at TEXT NOT NULL,
	current_document_cid TEXT,
	public_read INTEGER NOT NULL,
	doc_schema TEXT
);
CREATE INDEX IF NOT EXISTS idx_index_content_creator ON index_content(creator_did, content_id);
CREATE INDEX IF NOT EXISTS idx_index_content_schema ON index_content(doc_schema, content_id);
CREATE INDEX IF NOT EXISTS idx_index_content_doccid ON index_content(current_document_cid);

CREATE TABLE IF NOT EXISTS index_countersign (
	cid TEXT PRIMARY KEY,
	witness_did TEXT NOT NULL,
	target_cid TEXT NOT NULL,
	relation TEXT,
	jws_token TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_index_countersign_witness ON index_countersign(witness_did, cid);

CREATE TABLE IF NOT EXISTS index_meta (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
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

func (s *SQLiteStore) DeleteBlob(key BlobKey) error {
	// Idempotent: deleting a missing row affects zero rows and returns no error.
	_, err := s.writerDB().Exec(
		"DELETE FROM blobs WHERE creator_did = ? AND document_cid = ?",
		key.CreatorDID, key.DocumentCID,
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

// ListCountersignatures enumerates every stored countersignature (all
// witnesses), sorted by CID. Used ONLY by the index-projection rebuild path.
func (s *SQLiteStore) ListCountersignatures() ([]StoredCountersignature, error) {
	rows, err := s.readerDB().Query("SELECT operation_cid, jws_token FROM countersignatures")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := []StoredCountersignature{}
	for rows.Next() {
		var targetCID, token string
		if err := rows.Scan(&targetCID, &token); err != nil {
			return nil, err
		}
		row := countersignatureFromToken(targetCID, token)
		if row == nil {
			continue
		}
		result = append(result, *row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CID < result[j].CID })
	return result, nil
}

// ---------------------------------------------------------------------------
// index (v0) materialized projection
// ---------------------------------------------------------------------------

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullStr(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

// scanner is the common Scan interface between *sql.Row and *sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

func scanIndexIdentityRow(sc scanner) (indexIdentityRow, error) {
	var row indexIdentityRow
	var isDeleted int
	var anchor, docSchema, name sql.NullString
	var publicRead sql.NullInt64
	if err := sc.Scan(
		&row.DID, &row.HeadCID, &row.OpCount, &row.GenesisAt, &row.HeadAt, &isDeleted,
		&anchor, &publicRead, &docSchema, &name,
	); err != nil {
		return row, err
	}
	row.IsDeleted = isDeleted != 0
	// A projected profile always carries an anchor (profileProjection returns nil
	// otherwise), so anchor validity is exactly profile presence.
	if anchor.Valid {
		profile := &indexProfile{
			Anchor:     anchor.String,
			PublicRead: publicRead.Valid && publicRead.Int64 != 0,
		}
		if docSchema.Valid {
			v := docSchema.String
			profile.DocSchema = &v
		}
		if name.Valid {
			v := name.String
			profile.Name = &v
		}
		row.Profile = profile
	}
	return row, nil
}

const indexIdentityCols = "did, head_cid, op_count, genesis_at, head_at, is_deleted, profile_anchor, profile_public_read, profile_doc_schema, profile_name"

func scanIndexContentRow(sc scanner) (indexContentRow, error) {
	var row indexContentRow
	var isDeleted, publicRead int
	var currentDocCID, docSchema sql.NullString
	if err := sc.Scan(
		&row.ContentID, &row.GenesisCID, &row.HeadCID, &row.CreatorDID, &isDeleted,
		&row.OpCount, &row.GenesisAt, &row.HeadAt, &currentDocCID, &publicRead, &docSchema,
	); err != nil {
		return row, err
	}
	row.IsDeleted = isDeleted != 0
	row.PublicRead = publicRead != 0
	if currentDocCID.Valid {
		v := currentDocCID.String
		row.CurrentDocumentCID = &v
	}
	if docSchema.Valid {
		v := docSchema.String
		row.DocSchema = &v
	}
	return row, nil
}

const indexContentCols = "content_id, genesis_cid, head_cid, creator_did, is_deleted, op_count, genesis_at, head_at, current_document_cid, public_read, doc_schema"

func (s *SQLiteStore) PutIndexIdentityRow(row indexIdentityRow) error {
	var anchor, docSchema, name any
	var publicRead any
	hasPublicProfile := 0
	if row.Profile != nil {
		anchor = row.Profile.Anchor
		publicRead = boolToInt(row.Profile.PublicRead)
		docSchema = nullStr(row.Profile.DocSchema)
		name = nullStr(row.Profile.Name)
		if row.Profile.PublicRead {
			hasPublicProfile = 1
		}
	}
	_, err := s.writerDB().Exec(
		`INSERT OR REPLACE INTO index_identity
		 (did, head_cid, op_count, genesis_at, head_at, is_deleted,
		  profile_anchor, profile_public_read, profile_doc_schema, profile_name, has_public_profile)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		row.DID, row.HeadCID, row.OpCount, row.GenesisAt, row.HeadAt, boolToInt(row.IsDeleted),
		anchor, publicRead, docSchema, name, hasPublicProfile,
	)
	return err
}

func (s *SQLiteStore) PutIndexContentRow(row indexContentRow) error {
	_, err := s.writerDB().Exec(
		`INSERT OR REPLACE INTO index_content
		 (content_id, genesis_cid, head_cid, creator_did, is_deleted, op_count,
		  genesis_at, head_at, current_document_cid, public_read, doc_schema)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		row.ContentID, row.GenesisCID, row.HeadCID, row.CreatorDID, boolToInt(row.IsDeleted), row.OpCount,
		row.GenesisAt, row.HeadAt, nullStr(row.CurrentDocumentCID), boolToInt(row.PublicRead), nullStr(row.DocSchema),
	)
	return err
}

func (s *SQLiteStore) PutIndexCountersignatureRow(row storedIndexCountersignature) error {
	_, err := s.writerDB().Exec(
		`INSERT OR REPLACE INTO index_countersign (cid, witness_did, target_cid, relation, jws_token)
		 VALUES (?, ?, ?, ?, ?)`,
		row.CID, row.WitnessDID, row.TargetCID, nullStr(row.Relation), row.JWSToken,
	)
	return err
}

func (s *SQLiteStore) QueryIndexIdentities(q IndexIdentityQuery) ([]indexIdentityRow, error) {
	where := []string{}
	args := []any{}
	if q.HasPublicProfile != nil {
		where = append(where, "has_public_profile = ?")
		args = append(args, boolToInt(*q.HasPublicProfile))
	}
	if q.After != "" {
		where = append(where, "did > ?")
		args = append(args, q.After)
	}
	query := "SELECT " + indexIdentityCols + " FROM index_identity"
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY did LIMIT ?"
	args = append(args, q.Limit)

	rows, err := s.readerDB().Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []indexIdentityRow{}
	for rows.Next() {
		row, err := scanIndexIdentityRow(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func (s *SQLiteStore) QueryIndexContent(q IndexContentQuery) ([]indexContentRow, error) {
	where := []string{}
	args := []any{}
	if q.Creator != "" {
		where = append(where, "creator_did = ?")
		args = append(args, q.Creator)
	}
	if q.DocSchema != nil {
		where = append(where, "doc_schema = ?")
		args = append(args, *q.DocSchema)
	}
	if q.DocumentCID != nil {
		where = append(where, "current_document_cid = ?")
		args = append(args, *q.DocumentCID)
	}
	if q.PublicRead != nil {
		where = append(where, "public_read = ?")
		args = append(args, boolToInt(*q.PublicRead))
	}
	if q.After != "" {
		where = append(where, "content_id > ?")
		args = append(args, q.After)
	}
	query := "SELECT " + indexContentCols + " FROM index_content"
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY content_id LIMIT ?"
	args = append(args, q.Limit)

	rows, err := s.readerDB().Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []indexContentRow{}
	for rows.Next() {
		row, err := scanIndexContentRow(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func (s *SQLiteStore) QueryIndexCountersignatures(q IndexCountersignatureQuery) ([]indexCountersignatureRow, error) {
	query := "SELECT cid, target_cid, relation, jws_token FROM index_countersign WHERE witness_did = ?"
	args := []any{q.Witness}
	if q.After != "" {
		query += " AND cid > ?"
		args = append(args, q.After)
	}
	query += " ORDER BY cid LIMIT ?"
	args = append(args, q.Limit)

	rows, err := s.readerDB().Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []indexCountersignatureRow{}
	for rows.Next() {
		var row indexCountersignatureRow
		var relation sql.NullString
		if err := rows.Scan(&row.CID, &row.TargetCID, &relation, &row.JWSToken); err != nil {
			return nil, err
		}
		if relation.Valid {
			v := relation.String
			row.Relation = &v
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func (s *SQLiteStore) GetIndexIdentityDIDsByProfileAnchor(contentID string) ([]string, error) {
	rows, err := s.readerDB().Query("SELECT did FROM index_identity WHERE profile_anchor = ?", contentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	dids := []string{}
	for rows.Next() {
		var did string
		if err := rows.Scan(&did); err != nil {
			return nil, err
		}
		dids = append(dids, did)
	}
	return dids, rows.Err()
}

func (s *SQLiteStore) GetIndexContentIDsByDocumentCID(documentCID string) ([]string, error) {
	rows, err := s.readerDB().Query("SELECT content_id FROM index_content WHERE current_document_cid = ?", documentCID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	contentIds := []string{}
	for rows.Next() {
		var contentID string
		if err := rows.Scan(&contentID); err != nil {
			return nil, err
		}
		contentIds = append(contentIds, contentID)
	}
	return contentIds, rows.Err()
}

// --- RebuildableIndexStore ---

func (s *SQLiteStore) GetIndexProjectionVersion() (int, error) {
	var value string
	err := s.readerDB().QueryRow("SELECT value FROM index_meta WHERE key = 'projection_version'").Scan(&value)
	if err == sql.ErrNoRows {
		return 0, nil // never stamped — fresh or pre-projection DB
	}
	if err != nil {
		return 0, err
	}
	v, err := strconv.Atoi(value)
	if err != nil {
		return 0, nil // unparseable → treat as unstamped, forcing a rebuild
	}
	return v, nil
}

func (s *SQLiteStore) SetIndexProjectionVersion(v int) error {
	_, err := s.writerDB().Exec(
		"INSERT OR REPLACE INTO index_meta (key, value) VALUES ('projection_version', ?)",
		strconv.Itoa(v),
	)
	return err
}

func (s *SQLiteStore) ClearIndexProjection() error {
	for _, table := range []string{"index_identity", "index_content", "index_countersign"} {
		if _, err := s.writerDB().Exec("DELETE FROM " + table); err != nil {
			return err
		}
	}
	return nil
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

	// Return a resume cursor whenever the page has entries — NOT only when it's
	// full. Gating on len==limit meant the final partial page returned an empty
	// cursor, so a caught-up puller never advanced past it and re-fetched the whole
	// tail (up to a full page) every sync cycle forever — pure anti-entropy chatter
	// (re-decode + re-hash of already-sequenced ops, dedup-dropped). With a cursor on
	// the final page, the puller advances to the head; its next fetch (seq > last)
	// returns an empty page and it stops. New ops resume forward from there.
	var cursor string
	if len(entries) > 0 {
		cursor = entries[len(entries)-1].CID
	}

	return entries, cursor, nil
}

func (s *SQLiteStore) RelayStats() (*RelayStats, error) {
	db := s.readerDB()

	var opCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM operation_log").Scan(&opCount); err != nil {
		return nil, err
	}

	counts := newKindCounts()
	rows, err := db.Query("SELECT kind, COUNT(*) FROM operation_log GROUP BY kind")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var kind string
		var count int
		if err := rows.Scan(&kind, &count); err != nil {
			return nil, err
		}
		if b := kindBucket(kind); b != "" {
			counts[b] = count
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var headCID *string
	var head string
	if err := db.QueryRow("SELECT cid FROM operation_log ORDER BY seq DESC LIMIT 1").Scan(&head); err != nil {
		if err != sql.ErrNoRows {
			return nil, err
		}
	} else {
		headCID = &head
	}

	var oldestOpAt *string
	var jwsToken string
	if err := db.QueryRow("SELECT jws_token FROM operation_log ORDER BY seq ASC LIMIT 1").Scan(&jwsToken); err != nil {
		if err != sql.ErrNoRows {
			return nil, err
		}
	} else {
		_, payload, err := dfos.DecodeJWSUnsafe(jwsToken)
		if err == nil {
			if createdAt, ok := payload["createdAt"].(string); ok {
				oldestOpAt = &createdAt
			}
		}
	}

	return &RelayStats{
		OpCount:      opCount,
		CountsByKind: counts,
		OldestOpAt:   oldestOpAt,
		HeadCID:      headCID,
	}, nil
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

// MarkOpsSequenced marks the given CIDs as successfully sequenced. Propagates
// the first Exec error so callers can avoid gossiping ops whose sequenced
// status was never persisted.
func (s *SQLiteStore) MarkOpsSequenced(cids []string) error {
	w := s.writerDB()
	for _, cid := range cids {
		if _, err := w.Exec("UPDATE raw_ops SET status = 'sequenced' WHERE cid = ?", cid); err != nil {
			return err
		}
	}
	return nil
}

// MarkOpRejected permanently drops a raw op that failed verification.
//
// A permanent rejection is deterministic — the op re-verifies the same way — so
// the row has no recovery value. Keeping it let an unauthenticated submitter grow
// raw_ops without bound by mutating one byte per op to mint a fresh CID (the
// store is content-addressed, so distinct bytes are distinct rows). Deleting caps
// that durable-growth vector while leaving accepted/sequenced and dependency-
// pending ops (store-first crash safety) untouched — callers route only permanent
// rejections here (isPermanentRejection), never dependency-pending ops.
func (s *SQLiteStore) MarkOpRejected(cid string, reason string) error {
	_, err := s.writerDB().Exec("DELETE FROM raw_ops WHERE cid = ?", cid)
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

func (s *SQLiteStore) GetRevocationForCredential(credentialCID string) (*StoredRevocation, error) {
	// deterministic across stores/twins: smallest issuerDID wins on a
	// (theoretical) multi-issuer collision
	var rev StoredRevocation
	err := s.readerDB().QueryRow(
		"SELECT cid, issuer_did, credential_cid, jws_token FROM revocations WHERE credential_cid = ? ORDER BY issuer_did ASC LIMIT 1",
		credentialCID,
	).Scan(&rev.CID, &rev.IssuerDID, &rev.CredentialCID, &rev.JWSToken)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &rev, nil
}

func (s *SQLiteStore) GetRevocationsByIssuer(issuerDID string) ([]StoredRevocation, error) {
	rows, err := s.readerDB().Query(
		"SELECT cid, issuer_did, credential_cid, jws_token FROM revocations WHERE issuer_did = ?",
		issuerDID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	revs := []StoredRevocation{}
	for rows.Next() {
		var rev StoredRevocation
		if err := rows.Scan(&rev.CID, &rev.IssuerDID, &rev.CredentialCID, &rev.JWSToken); err != nil {
			return nil, err
		}
		revs = append(revs, rev)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	type revocationWithCreatedAt struct {
		revocation StoredRevocation
		createdAt  string
	}
	decorated := make([]revocationWithCreatedAt, 0, len(revs))
	for _, rev := range revs {
		createdAt := ""
		if _, payload, err := dfos.DecodeJWSUnsafe(rev.JWSToken); err == nil {
			if value, ok := payload["createdAt"].(string); ok {
				createdAt = value
			}
		}
		decorated = append(decorated, revocationWithCreatedAt{revocation: rev, createdAt: createdAt})
	}
	sort.Slice(decorated, func(i, j int) bool {
		if decorated[i].createdAt != decorated[j].createdAt {
			return decorated[i].createdAt < decorated[j].createdAt
		}
		return decorated[i].revocation.CredentialCID < decorated[j].revocation.CredentialCID
	})
	result := make([]StoredRevocation, 0, len(decorated))
	for _, rev := range decorated {
		result = append(result, rev.revocation)
	}
	return result, nil
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
