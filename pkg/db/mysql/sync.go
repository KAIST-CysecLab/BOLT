package mysql

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	trivydb "github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/log"
	mysqldriver "github.com/go-sql-driver/mysql"
	bolt "go.etcd.io/bbolt"
)

var snapshotTables = []string{"vulnerabilities", "vulnerability_advisories", "bolt_db_auxiliary", "bolt_db_metadata"}

var snapshotDefinitions = map[string]string{
	"vulnerabilities": `(
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
        vulnerability_id BLOB NOT NULL, value LONGBLOB NOT NULL
    ) ENGINE=InnoDB`,
	"vulnerability_advisories": `(
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
        vulnerability_id BLOB NOT NULL, platform BLOB NOT NULL,
        segment BLOB NOT NULL, package BLOB NOT NULL, value LONGBLOB NOT NULL,
        source_name BLOB NOT NULL, bucket_hash BINARY(32) NOT NULL,
        bucket_path LONGBLOB NOT NULL
    ) ENGINE=InnoDB`,
	"bolt_db_auxiliary": `(
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
        bucket_hash BINARY(32) NOT NULL, bucket_path LONGBLOB NOT NULL,
        entry_key BLOB NOT NULL, entry_kind TINYINT NOT NULL, value LONGBLOB NOT NULL
    ) ENGINE=InnoDB`,
	"bolt_db_metadata": `(id TINYINT NOT NULL PRIMARY KEY, value LONGBLOB NOT NULL) ENGINE=InnoDB`,
}

var snapshotIndexes = map[string]string{
	"vulnerabilities": "ADD KEY v_vulnerability_id_idx (vulnerability_id(255))",
	"vulnerability_advisories": `ADD KEY va_source_package_idx (platform(191), segment(128), package(255)),
        ADD KEY va_source_idx (source_name(191)),
        ADD KEY va_bucket_package_idx (bucket_hash, package(255)),
        ADD KEY va_vulnerability_id_idx (vulnerability_id(255))`,
	"bolt_db_auxiliary": "ADD KEY bolt_aux_entry_idx (bucket_hash, entry_key(255), entry_kind)",
}

// Sync imports an entire verified snapshot into private staging tables and
// publishes all tables in one atomic MySQL RENAME. It never falls back to BoltDB
// after a MySQL error. Existing live tables become uniquely named backups and
// are retained for operator-controlled rollback; only this run's failed staging
// tables are automatically removed.
func Sync(ctx context.Context, dsn string, snapshot Snapshot) (SyncResult, error) {
	if err := validateSnapshot(snapshot); err != nil {
		return SyncResult{}, err
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return SyncResult{}, fmt.Errorf("open MySQL for snapshot: %w", err)
	}
	defer db.Close()
	return syncSnapshot(ctx, db, snapshot)
}

func validateSnapshot(snapshot Snapshot) error {
	if snapshot.Repository == "" {
		return fmt.Errorf("snapshot repository is required")
	}
	digest, ok := strings.CutPrefix(snapshot.Digest, "sha256:")
	decoded, err := hex.DecodeString(digest)
	if !ok || err != nil || len(decoded) != sha256.Size {
		return fmt.Errorf("snapshot must have a sha256 OCI digest")
	}
	if snapshot.Metadata.Version != trivydb.SchemaVersion {
		return fmt.Errorf("unsupported snapshot schema %d (expected %d)", snapshot.Metadata.Version, trivydb.SchemaVersion)
	}
	if snapshot.Metadata.UpdatedAt.IsZero() {
		return fmt.Errorf("snapshot UpdatedAt is required")
	}
	info, err := os.Stat(snapshot.DBPath)
	if err != nil {
		return fmt.Errorf("stat snapshot database: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("snapshot database must be a regular file")
	}
	return nil
}

func syncSnapshot(ctx context.Context, db *sql.DB, snapshot Snapshot) (SyncResult, error) {
	// GET_LOCK is connection-scoped. Keep this same connection throughout the
	// import so a pooled connection cannot accidentally release the lock early.
	conn, err := db.Conn(ctx)
	if err != nil {
		return SyncResult{}, fmt.Errorf("connect to MySQL: %w", err)
	}
	defer conn.Close()
	var database string
	if err := conn.QueryRowContext(ctx, "SELECT DATABASE()").Scan(&database); err != nil {
		return SyncResult{}, fmt.Errorf("snapshot import requires a selected MySQL database: %w", err)
	}
	if database == "" {
		return SyncResult{}, fmt.Errorf("snapshot import requires a selected MySQL database")
	}
	lockDigest := sha256.Sum256([]byte(database))
	lockName := "bolt-db-sync:" + hex.EncodeToString(lockDigest[:20])
	var locked sql.NullInt64
	if err := conn.QueryRowContext(ctx, "SELECT GET_LOCK(?, 60)", lockName).Scan(&locked); err != nil {
		return SyncResult{}, fmt.Errorf("lock snapshot import: %w", err)
	}
	if !locked.Valid || locked.Int64 != 1 {
		return SyncResult{}, fmt.Errorf("another MySQL snapshot import holds the update lock")
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.ExecContext(cleanupCtx, "DO RELEASE_LOCK(?)", lockName)
	}()

	current, err := readStoredSnapshot(ctx, conn)
	if err != nil {
		return SyncResult{}, err
	}
	if current != nil {
		if snapshot.Metadata.UpdatedAt.Before(current.Metadata.UpdatedAt) {
			return SyncResult{}, fmt.Errorf("refusing older snapshot updated at %s; installed snapshot is %s", snapshot.Metadata.UpdatedAt.UTC(), current.Metadata.UpdatedAt.UTC())
		}
		if current.Digest == snapshot.Digest {
			return SyncResult{Vulnerabilities: current.Vulnerabilities, Advisories: current.Advisories, Digest: current.Digest}, nil
		}
	}
	log.InfoContext(ctx, "Importing official vulnerability snapshot into MySQL", "digest", snapshot.Digest)

	input, err := bolt.Open(snapshot.DBPath, 0400, &bolt.Options{ReadOnly: true, Timeout: time.Second})
	if err != nil {
		return SyncResult{}, fmt.Errorf("open snapshot BoltDB: %w", err)
	}
	defer input.Close()
	var token [6]byte
	if _, err := rand.Read(token[:]); err != nil {
		return SyncResult{}, fmt.Errorf("generate staging name: %w", err)
	}
	suffix := hex.EncodeToString(token[:])
	staging := make(map[string]string)
	created := []string{}
	published := false
	defer func() {
		if published || len(created) == 0 {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		// These names are created by this invocation only. Never DROP a live
		// table or a backup left by an earlier import.
		_, _ = conn.ExecContext(cleanupCtx, "DROP TABLE IF EXISTS "+strings.Join(created, ", "))
	}()
	for _, table := range snapshotTables {
		name := "`" + table + "_stage_" + suffix + "`"
		if _, err := conn.ExecContext(ctx, "CREATE TABLE "+name+" "+snapshotDefinitions[table]); err != nil {
			return SyncResult{}, fmt.Errorf("create %s staging table: %w", table, err)
		}
		staging[table] = name
		created = append(created, name)
	}

	batches := map[string]*snapshotBatch{
		"vulnerabilities":          {conn: conn, table: staging["vulnerabilities"], columns: "vulnerability_id,value", width: 2},
		"vulnerability_advisories": {conn: conn, table: staging["vulnerability_advisories"], columns: "vulnerability_id,platform,segment,package,value,source_name,bucket_hash,bucket_path", width: 8},
		"bolt_db_auxiliary":        {conn: conn, table: staging["bolt_db_auxiliary"], columns: "bucket_hash,bucket_path,entry_key,entry_kind,value", width: 5},
	}
	if err := walkSnapshot(ctx, input, func(record snapshotRecord) error {
		return batches[record.table].add(ctx, record.args)
	}); err != nil {
		return SyncResult{}, fmt.Errorf("import snapshot records: %w", err)
	}
	for _, table := range snapshotTables[:3] {
		batch := batches[table]
		if err := batch.flush(ctx); err != nil {
			return SyncResult{}, err
		}
		if _, err := conn.ExecContext(ctx, "ALTER TABLE "+staging[table]+" "+snapshotIndexes[table]); err != nil {
			return SyncResult{}, fmt.Errorf("index %s staging table: %w", table, err)
		}
		var rows int64
		if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+staging[table]).Scan(&rows); err != nil {
			return SyncResult{}, fmt.Errorf("verify %s row count: %w", table, err)
		}
		if rows != batch.total {
			return SyncResult{}, fmt.Errorf("%s row count mismatch: imported %d, stored %d", table, batch.total, rows)
		}
		log.InfoContext(ctx, "MySQL snapshot table indexed and verified", "table", table, "rows", rows)
	}
	result := SyncResult{Changed: true, Vulnerabilities: batches["vulnerabilities"].total, Advisories: batches["vulnerability_advisories"].total, Digest: snapshot.Digest}
	if result.Vulnerabilities == 0 || result.Advisories == 0 {
		return SyncResult{}, fmt.Errorf("refusing empty vulnerability/advisory snapshot")
	}
	record, err := json.Marshal(storedSnapshot{
		Snapshot: snapshot, Vulnerabilities: result.Vulnerabilities, Advisories: result.Advisories,
		Auxiliary: batches["bolt_db_auxiliary"].total, ImportedAt: time.Now().UTC(), Format: snapshotFormat,
	})
	if err != nil {
		return SyncResult{}, fmt.Errorf("encode snapshot metadata: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "INSERT INTO "+staging["bolt_db_metadata"]+" (id,value) VALUES (1,?)", record); err != nil {
		return SyncResult{}, fmt.Errorf("save snapshot metadata: %w", err)
	}

	var renames []string
	for _, table := range snapshotTables {
		var exists int
		if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?", table).Scan(&exists); err != nil {
			return SyncResult{}, fmt.Errorf("inspect live %s table: %w", table, err)
		}
		if exists != 0 {
			renames = append(renames, "`"+table+"` TO `"+table+"_backup_"+suffix+"`")
		}
		renames = append(renames, staging[table]+" TO `"+table+"`")
	}
	if _, err := conn.ExecContext(ctx, "RENAME TABLE "+strings.Join(renames, ", ")); err != nil {
		return SyncResult{}, fmt.Errorf("publish complete snapshot: %w", err)
	}
	published = true
	log.InfoContext(ctx, "Published complete MySQL vulnerability snapshot", "vulnerabilities", result.Vulnerabilities, "advisories", result.Advisories, "backup_suffix", suffix)
	return result, nil
}

type snapshotQueryer interface {
	QueryRowContext(context.Context, string, ...interface{}) *sql.Row
}

func readStoredSnapshot(ctx context.Context, q snapshotQueryer) (*storedSnapshot, error) {
	var raw []byte
	err := q.QueryRowContext(ctx, "SELECT value FROM bolt_db_metadata WHERE id = 1").Scan(&raw)
	var mysqlErr *mysqldriver.MySQLError
	if errors.As(err, &mysqlErr) && mysqlErr.Number == 1146 {
		return nil, nil // Legacy SQL dump, before managed snapshots.
	}
	if err != nil {
		return nil, fmt.Errorf("read installed snapshot metadata: %w", err)
	}
	var record storedSnapshot
	if err := json.Unmarshal(raw, &record); err != nil {
		return nil, fmt.Errorf("decode installed snapshot metadata: %w", err)
	}
	if record.Format != snapshotFormat || record.Metadata.UpdatedAt.IsZero() || record.Digest == "" {
		return nil, fmt.Errorf("invalid installed snapshot metadata")
	}
	return &record, nil
}

type snapshotBatch struct {
	conn    *sql.Conn
	table   string
	columns string
	width   int
	args    []interface{}
	rows    int
	bytes   int
	total   int64
	lastLog time.Time
}

func (b *snapshotBatch) add(ctx context.Context, args []interface{}) error {
	// Copy BoltDB slices before the read transaction ends. The memory bound is
	// 500 rows or about one MiB per table, plus the largest individual record.
	for _, arg := range args {
		if raw, ok := arg.([]byte); ok {
			arg = append([]byte{}, raw...)
			b.bytes += len(raw)
		}
		b.args = append(b.args, arg)
	}
	b.rows++
	if b.rows >= 500 || b.bytes >= 1<<20 {
		return b.flush(ctx)
	}
	return nil
}

func (b *snapshotBatch) flush(ctx context.Context) error {
	if b.rows == 0 {
		return nil
	}
	row := "(" + strings.TrimSuffix(strings.Repeat("?,", b.width), ",") + ")"
	query := "INSERT INTO " + b.table + " (" + b.columns + ") VALUES " + strings.TrimSuffix(strings.Repeat(row+",", b.rows), ",")
	result, err := b.conn.ExecContext(ctx, query, b.args...)
	if err != nil {
		return fmt.Errorf("insert snapshot batch into %s: %w", b.table, err)
	}
	n, err := result.RowsAffected()
	if err != nil || n != int64(b.rows) {
		return fmt.Errorf("snapshot batch row count mismatch in %s: want %d, got %d (%v)", b.table, b.rows, n, err)
	}
	b.total += n
	if b.lastLog.IsZero() {
		b.lastLog = time.Now()
	} else if time.Since(b.lastLog) >= 30*time.Second {
		log.InfoContext(ctx, "Loading MySQL snapshot records", "table", b.table, "rows", b.total)
		b.lastLog = time.Now()
	}
	b.rows, b.bytes = 0, 0
	b.args = nil
	return nil
}
