package relay

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	dfos "github.com/metalabel/dfos/packages/dfos-protocol-go"
	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS operations (
	cid TEXT PRIMARY KEY,
	jws_token TEXT NOT NULL,
	chain_type TEXT NOT NULL,
	chain_id TEXT NOT NULL,
	ingested_at TEXT NOT NULL
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
	created_at TEXT NOT NULL,
	ingested_at TEXT NOT NULL,
	UNIQUE(operation_cid, witness_did)
);

CREATE TABLE IF NOT EXISTS operation_log (
	seq INTEGER PRIMARY KEY AUTOINCREMENT,
	cid TEXT NOT NULL,
	jws_token TEXT NOT NULL,
	kind TEXT NOT NULL,
	chain_id TEXT NOT NULL,
	created_at TEXT NOT NULL,
	ingested_at TEXT NOT NULL
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
	origin TEXT NOT NULL DEFAULT 'direct',
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
	jws_token TEXT NOT NULL,
	created_at TEXT
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

CREATE TABLE IF NOT EXISTS signing_requests (
	cid TEXT PRIMARY KEY,
	request_token TEXT NOT NULL,
	requester_did TEXT NOT NULL,
	subject_did TEXT NOT NULL,
	payload_typ TEXT NOT NULL,
	payload_bytes BLOB NOT NULL,
	expires_at TEXT NOT NULL,
	deposited_at TEXT NOT NULL,
	declined INTEGER NOT NULL DEFAULT 0,
	response_token TEXT
);
CREATE INDEX IF NOT EXISTS idx_signing_requests_subject_pending
	ON signing_requests(subject_did, deposited_at, cid);
CREATE INDEX IF NOT EXISTS idx_signing_requests_expiry ON signing_requests(expires_at);

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
CREATE INDEX IF NOT EXISTS idx_index_identity_genesis ON index_identity(genesis_at, did);
CREATE INDEX IF NOT EXISTS idx_index_identity_head ON index_identity(head_at, did);

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
	doc_schema TEXT,
	title TEXT
);
CREATE INDEX IF NOT EXISTS idx_index_content_creator ON index_content(creator_did, content_id);
CREATE INDEX IF NOT EXISTS idx_index_content_schema ON index_content(doc_schema, content_id);
CREATE INDEX IF NOT EXISTS idx_index_content_doccid ON index_content(current_document_cid);
CREATE INDEX IF NOT EXISTS idx_index_content_genesis ON index_content(genesis_at, content_id);
CREATE INDEX IF NOT EXISTS idx_index_content_head ON index_content(head_at, content_id);

CREATE TABLE IF NOT EXISTS index_credit (
	content_id TEXT NOT NULL,
	position INTEGER NOT NULL,
	did TEXT NOT NULL,
	role TEXT,
	has_claim INTEGER NOT NULL,
	PRIMARY KEY (content_id, position)
);
CREATE INDEX IF NOT EXISTS idx_index_credit_did ON index_credit(did, content_id, position);
CREATE INDEX IF NOT EXISTS idx_index_credit_role ON index_credit(role, content_id, position);

CREATE TABLE IF NOT EXISTS index_artifact (
	cid TEXT PRIMARY KEY,
	signer_did TEXT NOT NULL,
	created_at TEXT NOT NULL,
	ingested_at TEXT NOT NULL,
	doc_schema TEXT
);
CREATE INDEX IF NOT EXISTS idx_index_artifact_signer ON index_artifact(signer_did, cid);
CREATE INDEX IF NOT EXISTS idx_index_artifact_schema ON index_artifact(doc_schema, cid);
CREATE INDEX IF NOT EXISTS idx_index_artifact_created ON index_artifact(created_at, cid);
CREATE INDEX IF NOT EXISTS idx_index_artifact_ingested ON index_artifact(ingested_at, cid);

CREATE TABLE IF NOT EXISTS content_signers (
	content_id TEXT NOT NULL,
	did TEXT NOT NULL,
	PRIMARY KEY (content_id, did)
);
CREATE INDEX IF NOT EXISTS idx_content_signers_did ON content_signers(did, content_id);

CREATE TABLE IF NOT EXISTS index_countersign (
	cid TEXT PRIMARY KEY,
	witness_did TEXT NOT NULL,
	target_cid TEXT NOT NULL,
	relation TEXT,
	jws_token TEXT NOT NULL,
	created_at TEXT NOT NULL,
	ingested_at TEXT NOT NULL
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
	if err := ensureColumn(writeDB, "index_content", "title", "TEXT"); err != nil {
		writeDB.Close()
		readDB.Close()
		return nil, err
	}
	if err := ensureColumn(writeDB, "raw_ops", "origin", "TEXT NOT NULL DEFAULT 'direct'"); err != nil {
		writeDB.Close()
		readDB.Close()
		return nil, err
	}
	for _, column := range []struct{ table, name string }{
		{"operations", "ingested_at"},
		{"operation_log", "created_at"},
		{"operation_log", "ingested_at"},
		{"countersignatures", "created_at"},
		{"countersignatures", "ingested_at"},
		{"index_countersign", "created_at"},
		{"index_countersign", "ingested_at"},
	} {
		if err := ensureColumn(writeDB, column.table, column.name, "TEXT"); err != nil {
			writeDB.Close()
			readDB.Close()
			return nil, err
		}
	}
	if _, err := writeDB.Exec(
		`UPDATE operations SET ingested_at = COALESCE(
			(SELECT ingested_at FROM operation_log WHERE operation_log.cid = operations.cid LIMIT 1), ?
		) WHERE ingested_at IS NULL OR ingested_at = ''`,
		time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
	); err != nil {
		writeDB.Close()
		readDB.Close()
		return nil, err
	}
	if err := backfillIndexTimestamps(writeDB); err != nil {
		writeDB.Close()
		readDB.Close()
		return nil, err
	}
	for _, statement := range []string{
		"CREATE INDEX IF NOT EXISTS idx_operation_log_created ON operation_log(created_at, cid)",
		"CREATE INDEX IF NOT EXISTS idx_operation_log_ingested ON operation_log(ingested_at, cid)",
		"CREATE INDEX IF NOT EXISTS idx_operation_log_kind ON operation_log(kind, ingested_at, cid)",
		"CREATE INDEX IF NOT EXISTS idx_operation_log_chain ON operation_log(chain_id, ingested_at, cid)",
		"CREATE INDEX IF NOT EXISTS idx_index_countersign_created ON index_countersign(witness_did, created_at, cid)",
		"CREATE INDEX IF NOT EXISTS idx_index_countersign_ingested ON index_countersign(witness_did, ingested_at, cid)",
		"CREATE INDEX IF NOT EXISTS idx_index_countersign_relation ON index_countersign(witness_did, relation, cid)",
	} {
		if _, err := writeDB.Exec(statement); err != nil {
			writeDB.Close()
			readDB.Close()
			return nil, err
		}
	}
	// The CREATE TABLE above is a no-op on an existing database, so a relay
	// upgrading in place needs the column added. Pre-existing rows come back NULL
	// and resolve lazily from their stored token on read (see
	// storedRevocationCreatedAt) — no backfill pass.
	if err := ensureColumn(writeDB, "revocations", "created_at", "TEXT"); err != nil {
		writeDB.Close()
		readDB.Close()
		return nil, err
	}

	return &SQLiteStore{db: writeDB, readDB: readDB}, nil
}

// backfillIndexTimestamps upgrades pre-index-recency databases. Author time is
// recovered from the already-accepted JWS; relay time comes from raw_ops, whose
// created_at records first receipt. If an old deployment pruned that raw row,
// upgrade time is the only honest relay-local fallback available.
func backfillIndexTimestamps(db *sql.DB) error {
	type operationBackfill struct {
		seq        int64
		cid        string
		jwsToken   string
		createdAt  sql.NullString
		ingestedAt sql.NullString
	}
	rows, err := db.Query("SELECT seq, cid, jws_token, created_at, ingested_at FROM operation_log WHERE created_at IS NULL OR ingested_at IS NULL")
	if err != nil {
		return err
	}
	operations := []operationBackfill{}
	for rows.Next() {
		var row operationBackfill
		if err := rows.Scan(&row.seq, &row.cid, &row.jwsToken, &row.createdAt, &row.ingestedAt); err != nil {
			rows.Close()
			return err
		}
		operations = append(operations, row)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, row := range operations {
		createdAt := row.createdAt.String
		if !row.createdAt.Valid {
			createdAt = operationCreatedAt(row.jwsToken)
		}
		ingestedAt := row.ingestedAt.String
		if !row.ingestedAt.Valid {
			ingestedAt = rawOpIngestedAt(db, row.cid)
		}
		if _, err := db.Exec("UPDATE operation_log SET created_at = ?, ingested_at = ? WHERE seq = ?", createdAt, ingestedAt, row.seq); err != nil {
			return err
		}
	}

	type countersignBackfill struct {
		rowID      int64
		jwsToken   string
		createdAt  sql.NullString
		ingestedAt sql.NullString
	}
	rows, err = db.Query("SELECT rowid, jws_token, created_at, ingested_at FROM countersignatures WHERE created_at IS NULL OR ingested_at IS NULL")
	if err != nil {
		return err
	}
	countersigns := []countersignBackfill{}
	for rows.Next() {
		var row countersignBackfill
		if err := rows.Scan(&row.rowID, &row.jwsToken, &row.createdAt, &row.ingestedAt); err != nil {
			rows.Close()
			return err
		}
		countersigns = append(countersigns, row)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, row := range countersigns {
		createdAt := row.createdAt.String
		cid := ""
		if header, payload, err := dfos.DecodeJWSUnsafe(row.jwsToken); err == nil {
			if header != nil {
				cid = header.CID
			}
			if !row.createdAt.Valid && payload != nil {
				createdAt, _ = payload["createdAt"].(string)
			}
		}
		ingestedAt := row.ingestedAt.String
		if !row.ingestedAt.Valid {
			ingestedAt = rawOpIngestedAt(db, cid)
		}
		if _, err := db.Exec("UPDATE countersignatures SET created_at = ?, ingested_at = ? WHERE rowid = ?", createdAt, ingestedAt, row.rowID); err != nil {
			return err
		}
	}
	return nil
}

func rawOpIngestedAt(db *sql.DB, cid string) string {
	var raw string
	if cid != "" && db.QueryRow("SELECT created_at FROM raw_ops WHERE cid = ?", cid).Scan(&raw) == nil {
		for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05"} {
			if parsed, err := time.Parse(layout, raw); err == nil {
				return parsed.UTC().Format("2006-01-02T15:04:05.000Z")
			}
		}
	}
	return time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
}

func ensureColumn(db *sql.DB, table, column, columnType string) error {
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return fmt.Errorf("inspect %s columns: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull int
		var defaultValue any
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			return err
		}
		if name == column {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = db.Exec("ALTER TABLE " + table + " ADD COLUMN " + column + " " + columnType)
	if err != nil {
		return fmt.Errorf("add %s.%s: %w", table, column, err)
	}
	return nil
}

// Close closes the underlying database connection.
func (s *SQLiteStore) Close() error {
	s.readDB.Close()
	return s.db.Close()
}

// ---------------------------------------------------------------------------
// signing mailbox
// ---------------------------------------------------------------------------

func scanSignRequest(row interface{ Scan(...any) error }) (*StoredSignRequest, error) {
	var request StoredSignRequest
	var declined int
	var response sql.NullString
	err := row.Scan(
		&request.CID, &request.Request, &request.RequesterDID, &request.SubjectDID,
		&request.PayloadTyp, &request.PayloadBytes, &request.ExpiresAt,
		&request.DepositedAt, &declined, &response,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	request.Declined = declined != 0
	if response.Valid {
		request.Response = response.String
	}
	return &request, nil
}

const selectSignRequest = `SELECT cid, request_token, requester_did, subject_did,
	payload_typ, payload_bytes, expires_at, deposited_at, declined, response_token
	FROM signing_requests`

func (s *SQLiteStore) GetSignRequest(cid string, now time.Time) (*StoredSignRequest, error) {
	if err := s.PruneExpiredSignRequests(now); err != nil {
		return nil, err
	}
	return scanSignRequest(s.readerDB().QueryRow(
		selectSignRequest+" WHERE cid = ? AND expires_at > ?", cid, now.UTC().Format(signingTimeFormat),
	))
}

func (s *SQLiteStore) PruneExpiredSignRequests(now time.Time) error {
	_, err := s.writerDB().Exec("DELETE FROM signing_requests WHERE expires_at <= ?", now.UTC().Format(signingTimeFormat))
	return err
}

func (s *SQLiteStore) PutSignRequest(request StoredSignRequest, now time.Time) (SigningPutResult, error) {
	if err := s.PruneExpiredSignRequests(now); err != nil {
		return SigningConflict, err
	}
	existing, err := s.GetSignRequest(request.CID, now)
	if err != nil {
		return SigningConflict, err
	}
	if existing != nil {
		if existing.Request == request.Request {
			return SigningIdentical, nil
		}
		return SigningConflict, nil
	}
	// Keep the capacity check and insertion in one writer statement so concurrent
	// deposits cannot both observe the last free slot.
	result, err := s.writerDB().Exec(`INSERT OR IGNORE INTO signing_requests
		(cid, request_token, requester_did, subject_did, payload_typ, payload_bytes, expires_at, deposited_at, declined)
		SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?
		WHERE (SELECT COUNT(*) FROM signing_requests
			WHERE subject_did = ? AND expires_at > ? AND response_token IS NULL) < ?`,
		request.CID, request.Request, request.RequesterDID, request.SubjectDID, request.PayloadTyp,
		request.PayloadBytes, request.ExpiresAt, request.DepositedAt, boolToInt(request.Declined),
		request.SubjectDID, now.UTC().Format(signingTimeFormat), MaxPendingSignRequestsPerMailbox,
	)
	if err != nil {
		return SigningConflict, err
	}
	if affected, _ := result.RowsAffected(); affected == 1 {
		return SigningCreated, nil
	}
	existing, err = s.GetSignRequest(request.CID, now)
	if err != nil {
		return SigningConflict, err
	}
	if existing != nil && existing.Request == request.Request {
		return SigningIdentical, nil
	}
	if existing == nil {
		return SigningAtCapacity, nil
	}
	return SigningConflict, nil
}

func (s *SQLiteStore) ListPendingSignRequests(subjectDID, after string, limit int, now time.Time) ([]StoredSignRequest, string, error) {
	if err := s.PruneExpiredSignRequests(now); err != nil {
		return nil, "", err
	}
	query := selectSignRequest + ` WHERE subject_did = ? AND expires_at > ? AND response_token IS NULL`
	args := []any{subjectDID, now.UTC().Format(signingTimeFormat)}
	if after != "" {
		cursor, ok := decodeSigningCursor(after)
		if !ok || cursor.SubjectDID != subjectDID {
			return nil, "", ErrInvalidSigningCursor
		}
		query += " AND (deposited_at > ? OR (deposited_at = ? AND cid > ?))"
		args = append(args, cursor.DepositedAt, cursor.DepositedAt, cursor.CID)
	}
	query += " ORDER BY deposited_at ASC, cid ASC LIMIT ?"
	args = append(args, limit)
	rows, err := s.readerDB().Query(query, args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	requests := make([]StoredSignRequest, 0)
	for rows.Next() {
		request, err := scanSignRequest(rows)
		if err != nil {
			return nil, "", err
		}
		requests = append(requests, *request)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	cursor := ""
	if len(requests) == limit && len(requests) > 0 {
		last := requests[len(requests)-1]
		cursor = encodeSigningCursor(signingCursor{SubjectDID: subjectDID, DepositedAt: last.DepositedAt, CID: last.CID})
	}
	return requests, cursor, nil
}

func (s *SQLiteStore) PutSignResponse(cid, response string, now time.Time) (SigningPutResult, error) {
	if err := s.PruneExpiredSignRequests(now); err != nil {
		return SigningConflict, err
	}
	result, err := s.writerDB().Exec(`UPDATE signing_requests SET response_token = ?
		WHERE cid = ? AND expires_at > ? AND response_token IS NULL`,
		response, cid, now.UTC().Format(signingTimeFormat))
	if err != nil {
		return SigningConflict, err
	}
	if affected, _ := result.RowsAffected(); affected == 1 {
		return SigningCreated, nil
	}
	existing, err := s.GetSignRequest(cid, now)
	if err != nil {
		return SigningConflict, err
	}
	if existing == nil {
		return SigningNotFound, nil
	}
	if existing.Response == response {
		return SigningIdentical, nil
	}
	return SigningConflict, nil
}

func (s *SQLiteStore) DeclineSignRequest(cid string, now time.Time) (SigningPutResult, error) {
	if err := s.PruneExpiredSignRequests(now); err != nil {
		return SigningConflict, err
	}
	result, err := s.writerDB().Exec(`UPDATE signing_requests SET declined = 1
		WHERE cid = ? AND expires_at > ? AND response_token IS NULL`,
		cid, now.UTC().Format(signingTimeFormat))
	if err != nil {
		return SigningConflict, err
	}
	if affected, _ := result.RowsAffected(); affected == 1 {
		return SigningCreated, nil
	}
	existing, err := s.GetSignRequest(cid, now)
	if err != nil {
		return SigningConflict, err
	}
	if existing == nil {
		return SigningNotFound, nil
	}
	return SigningConflict, nil
}

// ---------------------------------------------------------------------------
// operations
// ---------------------------------------------------------------------------

func (s *SQLiteStore) GetOperation(cid string) (*StoredOperation, error) {
	row := s.readerDB().QueryRow("SELECT cid, jws_token, chain_type, chain_id, ingested_at FROM operations WHERE cid = ?", cid)
	var op StoredOperation
	err := row.Scan(&op.CID, &op.JWSToken, &op.ChainType, &op.ChainID, &op.IngestedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &op, nil
}

func (s *SQLiteStore) PutOperation(op StoredOperation) error {
	if op.IngestedAt == "" {
		op.IngestedAt = time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	}
	_, err := s.writerDB().Exec(
		"INSERT OR REPLACE INTO operations (cid, jws_token, chain_type, chain_id, ingested_at) VALUES (?, ?, ?, ?, ?)",
		op.CID, op.JWSToken, op.ChainType, op.ChainID, op.IngestedAt,
	)
	return err
}

func (s *SQLiteStore) ListArtifactOperations() ([]StoredOperation, error) {
	rows, err := s.readerDB().Query("SELECT cid, jws_token, chain_type, chain_id, ingested_at FROM operations WHERE chain_type = 'artifact' ORDER BY cid")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []StoredOperation{}
	for rows.Next() {
		var op StoredOperation
		if err := rows.Scan(&op.CID, &op.JWSToken, &op.ChainType, &op.ChainID, &op.IngestedAt); err != nil {
			return nil, err
		}
		result = append(result, op)
	}
	return result, rows.Err()
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
	header, payload, err := dfos.DecodeJWSUnsafe(jwsToken)
	if err == nil && header != nil {
		kid := header.Kid
		if idx := strings.Index(kid, "#"); idx >= 0 {
			witnessDID = kid[:idx]
		} else {
			witnessDID = kid
		}
	}
	createdAt := ""
	if payload != nil {
		createdAt, _ = payload["createdAt"].(string)
	}
	ingestedAt := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")

	// INSERT OR IGNORE deduplicates by (operation_cid, witness_did)
	_, err = s.writerDB().Exec(
		"INSERT OR IGNORE INTO countersignatures (operation_cid, jws_token, witness_did, created_at, ingested_at) VALUES (?, ?, ?, ?, ?)",
		operationCID, jwsToken, witnessDID, createdAt, ingestedAt,
	)
	return err
}

// ListCountersignatures enumerates every stored countersignature (all
// witnesses), sorted by CID. Used ONLY by the index-projection rebuild path.
func (s *SQLiteStore) ListCountersignatures() ([]StoredCountersignature, error) {
	rows, err := s.readerDB().Query("SELECT operation_cid, jws_token, created_at, ingested_at FROM countersignatures")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := []StoredCountersignature{}
	for rows.Next() {
		var targetCID, token, createdAt, ingestedAt string
		if err := rows.Scan(&targetCID, &token, &createdAt, &ingestedAt); err != nil {
			return nil, err
		}
		row := countersignatureFromToken(targetCID, token)
		if row == nil {
			continue
		}
		row.CreatedAt = createdAt
		row.IngestedAt = ingestedAt
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
	var currentDocCID, docSchema, title sql.NullString
	if err := sc.Scan(
		&row.ContentID, &row.GenesisCID, &row.HeadCID, &row.CreatorDID, &isDeleted,
		&row.OpCount, &row.GenesisAt, &row.HeadAt, &currentDocCID, &publicRead, &docSchema, &title,
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
	if title.Valid {
		v := title.String
		row.Title = &v
	}
	return row, nil
}

const indexContentCols = "content_id, genesis_cid, head_cid, creator_did, is_deleted, op_count, genesis_at, head_at, current_document_cid, public_read, doc_schema, title"

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
		  genesis_at, head_at, current_document_cid, public_read, doc_schema, title)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		row.ContentID, row.GenesisCID, row.HeadCID, row.CreatorDID, boolToInt(row.IsDeleted), row.OpCount,
		row.GenesisAt, row.HeadAt, nullStr(row.CurrentDocumentCID), boolToInt(row.PublicRead), nullStr(row.DocSchema), nullStr(row.Title),
	)
	return err
}

func putIndexCreditRows(db dbConn, contentID string, rows []indexCreditRow) error {
	if _, err := db.Exec("DELETE FROM index_credit WHERE content_id = ?", contentID); err != nil {
		return err
	}
	for _, row := range rows {
		if _, err := db.Exec(
			`INSERT INTO index_credit (content_id, position, did, role, has_claim)
			 VALUES (?, ?, ?, ?, ?)`,
			contentID, row.Position, row.DID, nullStr(row.Role), boolToInt(row.HasClaim),
		); err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLiteStore) PutIndexCreditRows(contentID string, rows []indexCreditRow) error {
	if s.tx != nil {
		return putIndexCreditRows(s.tx, contentID, rows)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if err := putIndexCreditRows(tx, contentID, rows); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) PutIndexArtifactRow(row indexArtifactRow) error {
	_, err := s.writerDB().Exec(
		`INSERT OR REPLACE INTO index_artifact
		 (cid, signer_did, created_at, ingested_at, doc_schema) VALUES (?, ?, ?, ?, ?)`,
		row.CID, row.SignerDID, row.CreatedAt, row.IngestedAt, nullStr(row.DocSchema),
	)
	return err
}

func (s *SQLiteStore) PutIndexContentSigner(contentID string, did string) error {
	_, err := s.writerDB().Exec(
		"INSERT OR IGNORE INTO content_signers (content_id, did) VALUES (?, ?)",
		contentID, did,
	)
	return err
}

func (s *SQLiteStore) PutIndexCountersignatureRow(row storedIndexCountersignature) error {
	_, err := s.writerDB().Exec(
		`INSERT OR REPLACE INTO index_countersign
		 (cid, witness_did, target_cid, relation, jws_token, created_at, ingested_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		row.CID, row.WitnessDID, row.TargetCID, nullStr(row.Relation), row.JWSToken, row.CreatedAt, row.IngestedAt,
	)
	return err
}

func (s *SQLiteStore) QueryIndexIdentities(q IndexIdentityQuery) ([]indexIdentityRow, error) {
	where := []string{}
	args := []any{}
	if q.DID != "" {
		where = append(where, "did = ?")
		args = append(args, q.DID)
	}
	if q.HasPublicProfile != nil {
		where = append(where, "has_public_profile = ?")
		args = append(args, boolToInt(*q.HasPublicProfile))
	}
	if q.NameContains != "" {
		// Match only rows whose name is servable (public). The gated builder stores a
		// null name for non-public rows, but requiring has_public_profile also closes
		// the oracle on any row a pre-gate builder persisted: a non-public name can
		// never be confirmed by row-presence.
		where = append(where, "has_public_profile = 1 AND profile_name IS NOT NULL AND instr(lower(profile_name), lower(?)) > 0")
		args = append(args, q.NameContains)
	}
	if q.Order == "" && q.After != "" {
		where = append(where, "did > ?")
		args = append(args, q.After)
	}
	if q.Order != "" && q.OrderedAfter != nil {
		col := "head_at"
		if q.Order == "genesisAt.desc" {
			col = "genesis_at"
		}
		where = append(where, "("+col+" < ? OR ("+col+" = ? AND did > ?))")
		args = append(args, q.OrderedAfter.Timestamp, q.OrderedAfter.Timestamp, q.OrderedAfter.Key)
	}
	query := "SELECT " + indexIdentityCols + " FROM index_identity"
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	if q.Order == "genesisAt.desc" {
		query += " ORDER BY genesis_at DESC, did ASC LIMIT ?"
	} else if q.Order == "headAt.desc" {
		query += " ORDER BY head_at DESC, did ASC LIMIT ?"
	} else {
		query += " ORDER BY did LIMIT ?"
	}
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
	if q.ContentID != nil {
		where = append(where, "content_id = ?")
		args = append(args, *q.ContentID)
	}
	if q.Creator != "" {
		where = append(where, "creator_did = ?")
		args = append(args, q.Creator)
	}
	if q.Signer != "" {
		where = append(where, "EXISTS (SELECT 1 FROM content_signers WHERE content_signers.content_id = index_content.content_id AND content_signers.did = ?)")
		args = append(args, q.Signer)
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
	if q.IsDeleted != nil {
		where = append(where, "is_deleted = ?")
		args = append(args, boolToInt(*q.IsDeleted))
	}
	if q.TitleContains != "" {
		where = append(where, "public_read = 1 AND title IS NOT NULL AND instr(lower(title), lower(?)) > 0")
		args = append(args, q.TitleContains)
	}
	if q.Order == "" && q.After != "" {
		where = append(where, "content_id > ?")
		args = append(args, q.After)
	}
	if q.Order != "" && q.OrderedAfter != nil {
		col := "head_at"
		if q.Order == "genesisAt.desc" {
			col = "genesis_at"
		}
		where = append(where, "("+col+" < ? OR ("+col+" = ? AND content_id > ?))")
		args = append(args, q.OrderedAfter.Timestamp, q.OrderedAfter.Timestamp, q.OrderedAfter.Key)
	}
	query := "SELECT " + indexContentCols + " FROM index_content"
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	if q.Order == "genesisAt.desc" {
		query += " ORDER BY genesis_at DESC, content_id ASC LIMIT ?"
	} else if q.Order == "headAt.desc" {
		query += " ORDER BY head_at DESC, content_id ASC LIMIT ?"
	} else {
		query += " ORDER BY content_id LIMIT ?"
	}
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

func (s *SQLiteStore) QueryIndexCredits(q IndexCreditQuery) ([]indexCreditRow, error) {
	where := []string{}
	args := []any{}
	if q.DID != nil {
		where = append(where, "did = ?")
		args = append(args, *q.DID)
	}
	if q.ContentID != nil {
		where = append(where, "content_id = ?")
		args = append(args, *q.ContentID)
	}
	if q.Role != nil {
		where = append(where, "role = ?")
		args = append(args, *q.Role)
	}
	if q.After != nil {
		where = append(where, "(content_id > ? OR (content_id = ? AND position > ?))")
		args = append(args, q.After.ContentID, q.After.ContentID, q.After.Position)
	}
	query := "SELECT content_id, did, role, position, has_claim FROM index_credit"
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY content_id ASC, position ASC LIMIT ?"
	args = append(args, q.Limit)
	rows, err := s.readerDB().Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []indexCreditRow{}
	for rows.Next() {
		var row indexCreditRow
		var role sql.NullString
		var hasClaim int
		if err := rows.Scan(&row.ContentID, &row.DID, &role, &row.Position, &hasClaim); err != nil {
			return nil, err
		}
		if role.Valid {
			value := role.String
			row.Role = &value
		}
		row.HasClaim = hasClaim != 0
		result = append(result, row)
	}
	return result, rows.Err()
}

func (s *SQLiteStore) QueryIndexArtifacts(q IndexArtifactQuery) ([]indexArtifactRow, error) {
	where := []string{}
	args := []any{}
	if q.CID != nil {
		where = append(where, "cid = ?")
		args = append(args, *q.CID)
	}
	if q.Signer != "" {
		where = append(where, "signer_did = ?")
		args = append(args, q.Signer)
	}
	if q.DocSchema != nil {
		where = append(where, "doc_schema = ?")
		args = append(args, *q.DocSchema)
	}
	if q.Order == "" && q.After != "" {
		where = append(where, "cid > ?")
		args = append(args, q.After)
	}
	if q.Order != "" && q.OrderedAfter != nil {
		column := "ingested_at"
		if q.Order == "createdAt.desc" {
			column = "created_at"
		}
		where = append(where, "("+column+" < ? OR ("+column+" = ? AND cid > ?))")
		args = append(args, q.OrderedAfter.Timestamp, q.OrderedAfter.Timestamp, q.OrderedAfter.Key)
	}
	query := "SELECT cid, signer_did, created_at, ingested_at, doc_schema FROM index_artifact"
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	if q.Order == "createdAt.desc" {
		query += " ORDER BY created_at DESC, cid ASC LIMIT ?"
	} else if q.Order == "ingestedAt.desc" {
		query += " ORDER BY ingested_at DESC, cid ASC LIMIT ?"
	} else {
		query += " ORDER BY cid LIMIT ?"
	}
	args = append(args, q.Limit)
	rows, err := s.readerDB().Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []indexArtifactRow{}
	for rows.Next() {
		var row indexArtifactRow
		var docSchema sql.NullString
		if err := rows.Scan(&row.CID, &row.SignerDID, &row.CreatedAt, &row.IngestedAt, &docSchema); err != nil {
			return nil, err
		}
		if docSchema.Valid {
			value := docSchema.String
			row.DocSchema = &value
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func (s *SQLiteStore) QueryIndexCountersignatures(q IndexCountersignatureQuery) ([]indexCountersignatureRow, error) {
	query := "SELECT cid, target_cid, relation, jws_token, created_at, ingested_at FROM index_countersign WHERE witness_did = ?"
	args := []any{q.Witness}
	if q.Relation != nil {
		query += " AND relation = ?"
		args = append(args, *q.Relation)
	}
	if q.Order == "" && q.After != "" {
		query += " AND cid > ?"
		args = append(args, q.After)
	}
	if q.Order != "" && q.OrderedAfter != nil {
		column := "ingested_at"
		if q.Order == "createdAt.desc" {
			column = "created_at"
		}
		query += " AND (" + column + " < ? OR (" + column + " = ? AND cid > ?))"
		args = append(args, q.OrderedAfter.Timestamp, q.OrderedAfter.Timestamp, q.OrderedAfter.Key)
	}
	if q.Order == "createdAt.desc" {
		query += " ORDER BY created_at DESC, cid ASC LIMIT ?"
	} else if q.Order == "ingestedAt.desc" {
		query += " ORDER BY ingested_at DESC, cid ASC LIMIT ?"
	} else {
		query += " ORDER BY cid LIMIT ?"
	}
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
		if err := rows.Scan(&row.CID, &row.TargetCID, &relation, &row.JWSToken, &row.CreatedAt, &row.IngestedAt); err != nil {
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

func (s *SQLiteStore) QueryIndexCredentials(q IndexCredentialQuery) ([]indexCredentialRow, error) {
	where := []string{}
	args := []any{}
	if q.Issuer != "" {
		where = append(where, "issuer_did = ?")
		args = append(args, q.Issuer)
	}
	if q.Resource != nil {
		if strings.HasPrefix(*q.Resource, "chain:") {
			where = append(where, `EXISTS (
				SELECT 1 FROM json_each(public_credentials.att) je
				WHERE json_extract(je.value, '$.resource') = ?
				   OR json_extract(je.value, '$.resource') = 'chain:*'
			)`)
			args = append(args, *q.Resource)
		} else {
			where = append(where, `EXISTS (
				SELECT 1 FROM json_each(public_credentials.att) je
				WHERE json_extract(je.value, '$.resource') = ?
			)`)
			args = append(args, *q.Resource)
		}
	}
	if q.Action != nil {
		where = append(where, `EXISTS (
			SELECT 1 FROM json_each(public_credentials.att) je
			WHERE json_extract(je.value, '$.action') = ?
		)`)
		args = append(args, *q.Action)
	}
	if q.After != "" {
		where = append(where, "cid > ?")
		args = append(args, q.After)
	}
	query := "SELECT cid, issuer_did, att, exp, jws_token FROM public_credentials"
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY cid LIMIT ?"
	args = append(args, q.Limit)

	rows, err := s.readerDB().Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []indexCredentialRow{}
	for rows.Next() {
		var row indexCredentialRow
		var attJSON string
		if err := rows.Scan(&row.CID, &row.IssuerDID, &attJSON, &row.Exp, &row.JWSToken); err != nil {
			return nil, err
		}
		row.Aud = "*"
		if err := json.Unmarshal([]byte(attJSON), &row.Att); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func (s *SQLiteStore) QueryIndexOperations(q IndexOperationQuery) ([]indexOperationRow, error) {
	where := []string{}
	args := []any{}
	if q.Kind != "" {
		where = append(where, "kind = ?")
		args = append(args, q.Kind)
	}
	if q.ChainID != nil {
		where = append(where, "chain_id = ?")
		args = append(args, *q.ChainID)
	}
	if q.OrderedAfter != nil {
		column := "ingested_at"
		if q.Order == "createdAt.desc" {
			column = "created_at"
		}
		where = append(where, "("+column+" < ? OR ("+column+" = ? AND cid > ?))")
		args = append(args, q.OrderedAfter.Timestamp, q.OrderedAfter.Timestamp, q.OrderedAfter.Key)
	}
	query := "SELECT cid, kind, chain_id, created_at, ingested_at FROM operation_log"
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	if q.Order == "createdAt.desc" {
		query += " ORDER BY created_at DESC, cid ASC LIMIT ?"
	} else {
		query += " ORDER BY ingested_at DESC, cid ASC LIMIT ?"
	}
	args = append(args, q.Limit)
	rows, err := s.readerDB().Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []indexOperationRow{}
	for rows.Next() {
		var row indexOperationRow
		if err := rows.Scan(&row.CID, &row.Kind, &row.ChainID, &row.CreatedAt, &row.IngestedAt); err != nil {
			return nil, err
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
	for _, table := range []string{"index_identity", "index_content", "index_credit", "content_signers", "index_countersign", "index_artifact"} {
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
	createdAt := operationCreatedAt(entry.JWSToken)
	ingestedAt := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	_, err := s.writerDB().Exec(
		"INSERT INTO operation_log (cid, jws_token, kind, chain_id, created_at, ingested_at) VALUES (?, ?, ?, ?, ?, ?)",
		entry.CID, entry.JWSToken, entry.Kind, entry.ChainID, createdAt, ingestedAt,
	)
	return err
}

func (s *SQLiteStore) ReadLog(after string, limit int) ([]LogEntry, string, error) {
	var rows *sql.Rows
	var err error

	if after != "" {
		// Relay-local cursor: resolve the cursor CID's seq first — a CID this
		// log never issued is a caller error the route answers with 400.
		var afterSeq int64
		if err := s.readerDB().QueryRow(
			"SELECT seq FROM operation_log WHERE cid = ? LIMIT 1", after,
		).Scan(&afterSeq); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, "", ErrUnknownLogCursor
			}
			return nil, "", err
		}
		rows, err = s.readerDB().Query(
			`SELECT cid, jws_token, kind, chain_id FROM operation_log
			 WHERE seq > ? ORDER BY seq ASC LIMIT ?`,
			afterSeq, limit,
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

	// `next` only on a FULL page — a partial page means caught up (the shared
	// list envelope's contract, matching the production relay's paging). The
	// puller retains its last persisted cursor on null and re-fetches the final
	// partial page next cycle; the re-fetch dedups cheaply, and the bounded
	// reconcile scrubber remains the backstop. Mirrors MemoryStore.ReadLog.
	var next string
	if len(entries) == limit {
		next = entries[len(entries)-1].CID
	}

	return entries, next, nil
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

	// Historical replay is a VALIDITY decision — authorization enforced, revocation
	// evaluated AS OF each op's own createdAt, identity deletion retroactive and
	// therefore unconditional. See the MemoryStore twin.
	resolveKey := CreateKeyResolver(s)
	isRevoked := dfos.WithRevocationChecker(func(issuerDID, credentialCID string, asOfUnix int64) (bool, error) {
		return s.IsCredentialRevoked(issuerDID, credentialCID, asOfUnix)
	})
	isDeleted := dfos.WithIdentityDeletedChecker(func(did string) (bool, error) {
		identity, err := s.GetIdentityChain(did)
		if err != nil {
			return false, err
		}
		return identity != nil && identity.State.IsDeleted, nil
	})
	result, err := dfos.VerifyContentChain(path, resolveKey, true, isRevoked, isDeleted)
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
func (s *SQLiteStore) PutRawOp(cid string, jwsToken string, origins ...OpOrigin) error {
	origin := OpOriginDirect
	if len(origins) > 0 && origins[0] == OpOriginPeer {
		origin = OpOriginPeer
	}
	_, err := s.writerDB().Exec(
		"INSERT OR IGNORE INTO raw_ops (cid, jws_token, origin) VALUES (?, ?, ?)",
		cid, jwsToken, origin,
	)
	return err
}

// GetUnsequencedOps returns JWS tokens for ops that haven't been sequenced yet.
func (s *SQLiteStore) GetUnsequencedOps(limit int) ([]PendingOp, error) {
	rows, err := s.readerDB().Query(
		"SELECT jws_token, origin FROM raw_ops WHERE status = 'pending' ORDER BY created_at ASC LIMIT ?",
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var pending []PendingOp
	for rows.Next() {
		var op PendingOp
		if err := rows.Scan(&op.JWSToken, &op.Origin); err != nil {
			return nil, err
		}
		if op.Origin != OpOriginPeer {
			op.Origin = OpOriginDirect
		}
		pending = append(pending, op)
	}
	return pending, rows.Err()
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

// AddRevocation stores a revocation, keeping the one with the EARLIEST as-of
// boundary when the (issuer_did, credential_cid) pair already has one — see
// revocationSupersedes. `INSERT OR IGNORE` alone would make the boundary depend on
// which of two distinct revocations for the same credential arrived first.
//
// The comparison happens in Go (not as an ON CONFLICT expression) so both stores
// share one implementation of the rule, including the legacy-NULL-column fallback
// and the CID tiebreak. Writes here are serialized through the single writer
// connection, so the read-compare-write is not racing another writer.
func (s *SQLiteStore) AddRevocation(revocation StoredRevocation) error {
	w := s.writerDB()

	var existing StoredRevocation
	var existingCreatedAt sql.NullString
	err := s.readerDB().QueryRow(
		"SELECT cid, jws_token, created_at FROM revocations WHERE issuer_did = ? AND credential_cid = ? LIMIT 1",
		revocation.IssuerDID, revocation.CredentialCID,
	).Scan(&existing.CID, &existing.JWSToken, &existingCreatedAt)
	switch {
	case err == sql.ErrNoRows:
		_, err = w.Exec(
			"INSERT OR IGNORE INTO revocations (cid, issuer_did, credential_cid, jws_token, created_at) VALUES (?, ?, ?, ?, ?)",
			revocation.CID, revocation.IssuerDID, revocation.CredentialCID, revocation.JWSToken, revocation.CreatedAt,
		)
		return err
	case err != nil:
		return err
	}

	existing.CreatedAt = existingCreatedAt.String
	if !revocationSupersedes(revocation, existing) {
		return nil
	}

	// Replace the row wholesale rather than UPDATE-ing cid in place: cid is the
	// PRIMARY KEY, and delete-then-insert keeps the artifact, its boundary, and the
	// key consistent in one step.
	if _, err := w.Exec(
		"DELETE FROM revocations WHERE issuer_did = ? AND credential_cid = ?",
		revocation.IssuerDID, revocation.CredentialCID,
	); err != nil {
		return err
	}
	_, err = w.Exec(
		"INSERT INTO revocations (cid, issuer_did, credential_cid, jws_token, created_at) VALUES (?, ?, ?, ?, ?)",
		revocation.CID, revocation.IssuerDID, revocation.CredentialCID, revocation.JWSToken, revocation.CreatedAt,
	)
	return err
}

func (s *SQLiteStore) IsCredentialRevoked(issuerDID string, credentialCID string, asOfUnix int64) (bool, error) {
	// The (issuer_did, credential_cid) unique index makes this at most one row, so
	// selecting the boundary columns and comparing in Go is as cheap as the old
	// SELECT 1 and keeps the as-of rule in one place across both stores.
	var createdAt sql.NullString
	var jwsToken string
	err := s.readerDB().QueryRow(
		"SELECT created_at, jws_token FROM revocations WHERE issuer_did = ? AND credential_cid = ? LIMIT 1",
		issuerDID, credentialCID,
	).Scan(&createdAt, &jwsToken)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	// asOfUnix <= 0 is the timeless (freshness) question — see the Store contract.
	if asOfUnix <= 0 {
		return true, nil
	}
	revokedAt, ok := revocationCreatedAtUnix(storedRevocationCreatedAt(createdAt.String, jwsToken))
	return !ok || revokedAt <= asOfUnix, nil
}

func (s *SQLiteStore) GetRevocationForCredential(credentialCID string) (*StoredRevocation, error) {
	// deterministic across stores/twins: smallest issuerDID wins on a
	// (theoretical) multi-issuer collision
	var rev StoredRevocation
	var createdAt sql.NullString
	err := s.readerDB().QueryRow(
		"SELECT cid, issuer_did, credential_cid, jws_token, created_at FROM revocations WHERE credential_cid = ? ORDER BY issuer_did ASC LIMIT 1",
		credentialCID,
	).Scan(&rev.CID, &rev.IssuerDID, &rev.CredentialCID, &rev.JWSToken, &createdAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	rev.CreatedAt = storedRevocationCreatedAt(createdAt.String, rev.JWSToken)
	return &rev, nil
}

func (s *SQLiteStore) GetRevocationsByIssuer(issuerDID string) ([]StoredRevocation, error) {
	rows, err := s.readerDB().Query(
		"SELECT cid, issuer_did, credential_cid, jws_token, created_at FROM revocations WHERE issuer_did = ?",
		issuerDID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	revs := []StoredRevocation{}
	for rows.Next() {
		var rev StoredRevocation
		var createdAt sql.NullString
		if err := rows.Scan(&rev.CID, &rev.IssuerDID, &rev.CredentialCID, &rev.JWSToken, &createdAt); err != nil {
			return nil, err
		}
		rev.CreatedAt = storedRevocationCreatedAt(createdAt.String, rev.JWSToken)
		revs = append(revs, rev)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	sort.Slice(revs, func(i, j int) bool { return revs[i].CredentialCID < revs[j].CredentialCID })
	return revs, nil
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

func (s *SQLiteStore) GetPublicCredentialByCID(cid string) (*StoredPublicCredential, error) {
	var credential StoredPublicCredential
	var attJSON string
	err := s.readerDB().QueryRow(
		"SELECT cid, issuer_did, att, exp, jws_token FROM public_credentials WHERE cid = ?",
		cid,
	).Scan(&credential.CID, &credential.IssuerDID, &attJSON, &credential.Exp, &credential.JWSToken)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(attJSON), &credential.Att); err != nil {
		return nil, err
	}
	return &credential, nil
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
