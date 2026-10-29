package mysql

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
)

// This driver models the publication boundary, including a populated legacy
// database. It fails the test if an import modifies a live table before RENAME.
type snapshotSQL struct {
	current     *storedSnapshot
	metadataErr error
	statements  []string
	counts      map[string]int64
	live        map[string]bool
	failExec    string
	lock        int64
	connections int
	published   bool
	released    bool
	insertSizes []int
	metadata    []byte
}

func newSnapshotSQL(t *testing.T) (*sql.DB, *snapshotSQL) {
	t.Helper()
	state := &snapshotSQL{counts: map[string]int64{}, live: map[string]bool{"vulnerabilities": true, "vulnerability_advisories": true}, lock: 1}
	db := sql.OpenDB(state)
	t.Cleanup(func() { _ = db.Close() })
	return db, state
}

func (s *snapshotSQL) Connect(context.Context) (driver.Conn, error) {
	s.connections++
	return &snapshotSQLConn{s}, nil
}
func (s *snapshotSQL) Driver() driver.Driver { return advisoryDriver{} }

type snapshotSQLConn struct{ state *snapshotSQL }

func (c *snapshotSQLConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (c *snapshotSQLConn) Close() error { return nil }
func (c *snapshotSQLConn) Begin() (driver.Tx, error) {
	return nil, errors.New("unexpected transaction")
}
func (c *snapshotSQLConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	s := c.state
	s.statements = append(s.statements, query)
	row := func(value driver.Value) (driver.Rows, error) {
		return &advisoryRows{columns: []string{"value"}, values: [][]driver.Value{{value}}}, nil
	}
	switch {
	case query == "SELECT DATABASE()":
		return row("isolated_test_database")
	case strings.Contains(query, "GET_LOCK"):
		return row(s.lock)
	case strings.Contains(query, "FROM bolt_db_metadata"):
		if s.metadataErr != nil {
			return nil, s.metadataErr
		}
		if s.current == nil {
			return nil, &mysqldriver.MySQLError{Number: 1146, Message: "table does not exist"}
		}
		raw, _ := json.Marshal(s.current)
		return row(raw)
	case strings.Contains(query, "FROM information_schema.tables"):
		if s.live[args[0].Value.(string)] {
			return row(int64(1))
		}
		return row(int64(0))
	case strings.HasPrefix(query, "SELECT COUNT(*) FROM `"):
		name := strings.Trim(strings.Fields(query)[3], "`")
		return row(s.counts[name])
	default:
		return nil, fmt.Errorf("unexpected query: %s", query)
	}
}
func (c *snapshotSQLConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	s := c.state
	s.statements = append(s.statements, query)
	if s.failExec != "" && strings.Contains(query, s.failExec) {
		return nil, errors.New("injected MySQL failure")
	}
	switch {
	case strings.HasPrefix(query, "DO RELEASE_LOCK"):
		s.released = true
	case strings.HasPrefix(query, "CREATE TABLE "):
		name := strings.Trim(strings.Fields(query)[2], "`")
		if !strings.Contains(name, "_stage_") {
			return nil, errors.New("created live table")
		}
		s.counts[name] = 0
	case strings.HasPrefix(query, "INSERT INTO "):
		name := strings.Trim(strings.Fields(query)[2], "`")
		if !strings.Contains(name, "_stage_") {
			return nil, errors.New("inserted into live table")
		}
		n := strings.Count(query, "),(") + 1
		s.counts[name] += int64(n)
		s.insertSizes = append(s.insertSizes, n)
		if strings.HasPrefix(name, "bolt_db_metadata_stage_") {
			s.metadata = args[0].Value.([]byte)
		}
		return driver.RowsAffected(n), nil
	case strings.HasPrefix(query, "ALTER TABLE "):
		if !strings.Contains(strings.Fields(query)[2], "_stage_") {
			return nil, errors.New("altered live table")
		}
	case strings.HasPrefix(query, "DROP TABLE IF EXISTS "):
		if strings.Contains(query, "_backup_") || strings.Count(query, "_stage_") != len(s.counts) {
			return nil, errors.New("unsafe cleanup")
		}
	case strings.HasPrefix(query, "RENAME TABLE "):
		if s.published {
			return nil, errors.New("published in multiple operations")
		}
		for _, table := range snapshotTables {
			if !strings.Contains(query, " TO `"+table+"`") {
				return nil, fmt.Errorf("missing publication for %s", table)
			}
			if s.live[table] && !strings.Contains(query, "`"+table+"` TO `"+table+"_backup_") {
				return nil, fmt.Errorf("missing backup for %s", table)
			}
		}
		s.published = true
	default:
		return nil, fmt.Errorf("unexpected exec: %s", query)
	}
	return driver.RowsAffected(0), nil
}

func TestSyncPublishesWholeSnapshotAndRetainsLegacyBackup(t *testing.T) {
	var extra []snapshotEntry
	for i := 0; i < 1000; i++ {
		extra = append(extra, snapshotEntry{[]string{"conan::Vendor Database", "zlib"}, fmt.Sprintf("CVE-%04d", i), []byte(`{"Future":true}`)})
	}
	snapshot := fixtureSnapshot(t, extra...)
	db, state := newSnapshotSQL(t)
	result, err := syncSnapshot(context.Background(), db, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if result != (SyncResult{Changed: true, Vulnerabilities: 1, Advisories: 1001, Digest: snapshot.Digest}) {
		t.Fatalf("result = %+v", result)
	}
	if !state.published || !state.released || state.connections != 1 {
		t.Fatalf("publication=%v released=%v connections=%d", state.published, state.released, state.connections)
	}
	var installed storedSnapshot
	if err := json.Unmarshal(state.metadata, &installed); err != nil {
		t.Fatal(err)
	}
	if installed.Digest != snapshot.Digest || installed.Advisories != 1001 || installed.Auxiliary != 1 || installed.Format != snapshotFormat {
		t.Fatalf("metadata = %+v", installed)
	}
	if bytes := string(state.metadata); strings.Contains(bytes, snapshot.DBPath) {
		t.Fatal("local database path leaked into metadata")
	}
	fullBatches := 0
	for _, n := range state.insertSizes {
		if n > 500 {
			t.Fatalf("unbounded batch: %d", n)
		}
		if n == 500 {
			fullBatches++
		}
	}
	if fullBatches != 2 {
		t.Fatalf("expected bounded streaming, batches = %v", state.insertSizes)
	}
	for _, statement := range state.statements {
		if strings.HasPrefix(statement, "DROP") {
			t.Fatalf("successful import removed retained data: %s", statement)
		}
	}
}

func TestSyncFailuresLeaveLiveTablesUntouched(t *testing.T) {
	for _, failure := range []string{"CREATE TABLE `vulnerability_advisories_stage_", "INSERT INTO", "ALTER TABLE", "RENAME TABLE"} {
		t.Run(failure, func(t *testing.T) {
			db, state := newSnapshotSQL(t)
			state.failExec = failure
			_, err := syncSnapshot(context.Background(), db, fixtureSnapshot(t))
			if err == nil || !strings.Contains(err.Error(), "injected MySQL failure") {
				t.Fatalf("error = %v", err)
			}
			if state.published || !state.released {
				t.Fatalf("published=%v released=%v", state.published, state.released)
			}
			cleaned := false
			for _, statement := range state.statements {
				if strings.HasPrefix(statement, "DROP TABLE") {
					cleaned = strings.Count(statement, "_stage_") == len(state.counts) && !strings.Contains(statement, "_backup_")
				}
			}
			if !cleaned {
				t.Fatalf("failed staging was not cleaned: %v", state.statements)
			}
		})
	}
}

func TestSyncNoOpAndOlderSnapshot(t *testing.T) {
	for _, older := range []bool{false, true} {
		t.Run(fmt.Sprintf("older=%v", older), func(t *testing.T) {
			snapshot := fixtureSnapshot(t)
			db, state := newSnapshotSQL(t)
			state.current = &storedSnapshot{Snapshot: snapshot, Vulnerabilities: 15, Advisories: 30, Format: snapshotFormat}
			if older {
				snapshot.Metadata.UpdatedAt = snapshot.Metadata.UpdatedAt.Add(-time.Hour)
			}
			result, err := syncSnapshot(context.Background(), db, snapshot)
			if older {
				if err == nil || !strings.Contains(err.Error(), "refusing older snapshot") {
					t.Fatalf("error = %v", err)
				}
			} else if err != nil || !reflect.DeepEqual(result, SyncResult{Digest: snapshot.Digest, Vulnerabilities: 15, Advisories: 30}) {
				t.Fatalf("result=%+v error=%v", result, err)
			}
			for _, statement := range state.statements {
				if strings.Contains(statement, "_stage_") || strings.HasPrefix(statement, "RENAME") {
					t.Fatalf("unexpected mutation: %s", statement)
				}
			}
			if !state.released {
				t.Fatal("update lock not released")
			}
		})
	}
}

func TestSyncPropagatesMetadataErrorAndLockContention(t *testing.T) {
	for _, failure := range []string{"metadata", "lock"} {
		t.Run(failure, func(t *testing.T) {
			db, state := newSnapshotSQL(t)
			if failure == "metadata" {
				state.metadataErr = errors.New("permission denied")
			} else {
				state.lock = 0
			}
			if _, err := syncSnapshot(context.Background(), db, fixtureSnapshot(t)); err == nil {
				t.Fatal("expected failure")
			}
			for _, statement := range state.statements {
				if strings.Contains(statement, "_stage_") {
					t.Fatalf("unexpected mutation: %s", statement)
				}
			}
		})
	}
}
