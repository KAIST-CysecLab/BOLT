package mysql

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/types"
)

// A connector keeps these tests independent of a MySQL server and avoids adding
// another SQL mocking dependency. It checks the actual query and bound values.
type advisoryQuery func(string, []driver.NamedValue) (driver.Rows, error)

func (q advisoryQuery) Connect(context.Context) (driver.Conn, error) { return advisoryConn{q}, nil }
func (q advisoryQuery) Driver() driver.Driver                        { return advisoryDriver{} }

type advisoryDriver struct{}

func (advisoryDriver) Open(string) (driver.Conn, error) { return nil, errors.New("use connector") }

type advisoryConn struct{ query advisoryQuery }

func (advisoryConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (advisoryConn) Close() error              { return nil }
func (advisoryConn) Begin() (driver.Tx, error) { return nil, errors.New("unexpected transaction") }
func (c advisoryConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	return c.query(query, args)
}

type advisoryRows struct {
	columns []string
	values  [][]driver.Value
	err     error
	closed  bool
}

func (r *advisoryRows) Columns() []string {
	if r.columns != nil {
		return r.columns
	}
	return []string{"vulnerability_id", "platform", "segment", "value"}
}
func (r *advisoryRows) Close() error { r.closed = true; return nil }
func (r *advisoryRows) Next(dest []driver.Value) error {
	if len(r.values) == 0 {
		if r.err != nil {
			return r.err
		}
		return io.EOF
	}
	copy(dest, r.values[0])
	r.values = r.values[1:]
	return nil
}

func queryConfig(t *testing.T, query advisoryQuery) *Config {
	t.Helper()
	db := sql.OpenDB(query)
	t.Cleanup(func() { _ = db.Close() })
	return &Config{db: db}
}

func sourceRows(values ...[]driver.Value) *advisoryRows {
	return &advisoryRows{columns: []string{"platform", "segment"}, values: values}
}

func TestGetAdvisories(t *testing.T) {
	const bucketPredicate = "((platform = ? AND segment = ?))"
	for _, tc := range []struct {
		name       string
		source     string
		predicate  string
		args       []interface{}
		buckets    [][]driver.Value
		pattern    string
		rows       [][]driver.Value
		wantIDs    []string
		wantSource []*types.DataSource
	}{
		{
			name: "OS release remains an exact query", source: "alpine 3.18",
			predicate: "platform = ? AND segment = ?", args: []interface{}{"alpine", "3.18", "zlib"},
			rows:       [][]driver.Value{{"CVE-OS", "alpine", "3.18", `{"FixedVersion":"1.2.13-r1"}`}},
			wantIDs:    []string{"CVE-OS"},
			wantSource: []*types.DataSource{{ID: "alpine", Name: "Alpine Secdb", URL: "https://secdb.alpinelinux.org/"}},
		},
		{
			name: "ecosystem prefix spans advisory buckets", source: "conan::",
			predicate: "((platform = ? AND segment = ?) OR (platform = ? AND segment = ?))",
			args:      []interface{}{"conan::GitLab", "Advisory Database Community", "conan::Vendor", "Advisory Database", "zlib"},
			buckets:   [][]driver.Value{{"conan::GitLab", "Advisory Database Community"}, {"conan::Vendor", "Advisory Database"}}, pattern: "conan::%",
			rows: [][]driver.Value{
				{"CVE-GLAD", "conan::GitLab", "Advisory Database Community", `{"VulnerableVersions":["<1.2.13"]}`},
				{"CVE-VENDOR", "conan::Vendor", "Advisory Database", `{"VulnerableVersions":["<1.3.1"]}`},
			},
			wantIDs: []string{"CVE-GLAD", "CVE-VENDOR"},
			wantSource: []*types.DataSource{
				{ID: "glad", Name: "GitLab Advisory Database Community", URL: "https://gitlab.com/gitlab-org/advisories-community"},
				{ID: "conan::Vendor Advisory Database", Name: "conan::Vendor Advisory Database"},
			},
		},
		{
			name: "full language prefix retains spaces", source: "conan::GitLab Advisory Database",
			predicate: bucketPredicate, args: []interface{}{"conan::GitLab Advisory Database Community", "", "zlib"},
			buckets: [][]driver.Value{{"conan::GitLab Advisory Database Community", ""}}, pattern: "conan::GitLab%",
			rows:       [][]driver.Value{{"CVE-GLAD", "conan::GitLab Advisory Database Community", "", `{}`}},
			wantIDs:    []string{"CVE-GLAD"},
			wantSource: []*types.DataSource{{ID: "glad", Name: "GitLab Advisory Database Community", URL: "https://gitlab.com/gitlab-org/advisories-community"}},
		},
		{
			name: "prefix wildcard characters remain literal", source: "conan::Vendor_!%",
			predicate: bucketPredicate, args: []interface{}{"conan::Vendor_!%", "", "zlib"},
			buckets: [][]driver.Value{{"conan::Vendor_!%", ""}, {"conan::Vendor_other", ""}}, pattern: "conan::Vendor!_!!!%%",
		},
		{
			name: "embedded source metadata takes precedence", source: "conan::",
			predicate: bucketPredicate, args: []interface{}{"conan::GitLab", "Advisory Database Community", "zlib"},
			buckets: [][]driver.Value{{"conan::GitLab", "Advisory Database Community"}}, pattern: "conan::%",
			rows: [][]driver.Value{{"CVE-VENDOR", "conan::GitLab", "Advisory Database Community",
				`{"DataSource":{"ID":"custom","Name":"Verified vendor feed","URL":"https://example.test/advisories"}}`}},
			wantIDs:    []string{"CVE-VENDOR"},
			wantSource: []*types.DataSource{{ID: "custom", Name: "Verified vendor feed", URL: "https://example.test/advisories"}},
		},
		{
			name: "GHSA source metadata", source: "pip::",
			predicate: bucketPredicate, args: []interface{}{"pip::GitHub", "Security Advisory pip", "zlib"},
			buckets: [][]driver.Value{{"pip::GitHub", "Security Advisory pip"}}, pattern: "pip::%",
			rows:       [][]driver.Value{{"GHSA-TEST", "pip::GitHub", "Security Advisory pip", `{}`}},
			wantIDs:    []string{"GHSA-TEST"},
			wantSource: []*types.DataSource{{ID: "ghsa", Name: "GitHub Security Advisory pip", URL: "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Apip"}},
		},
		{
			name: "case insensitive SQL results cannot cross source boundaries", source: "conan::Vendor",
			predicate: bucketPredicate, args: []interface{}{"conan::Vendor", "", "zlib"},
			buckets: [][]driver.Value{{"Conan::Vendor", ""}, {"conan::vendor", ""}, {"conan::Vendor", ""}}, pattern: "conan::Vendor%",
			rows: [][]driver.Value{
				{"CVE-WRONG-CASE", "Conan::Vendor", "", `{}`},
				{"CVE-RIGHT-CASE", "conan::Vendor", "", `{}`},
			},
			wantIDs:    []string{"CVE-RIGHT-CASE"},
			wantSource: []*types.DataSource{{ID: "conan::Vendor", Name: "conan::Vendor"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows := &advisoryRows{values: tc.rows}
			bucketRows := sourceRows(tc.buckets...)
			discoveries := 0
			cfg := queryConfig(t, func(query string, args []driver.NamedValue) (driver.Rows, error) {
				if strings.Contains(query, "SELECT DISTINCT") {
					discoveries++
					if !strings.Contains(query, "BINARY platform AS platform, BINARY segment AS segment") || !strings.Contains(query, "WHERE platform LIKE ? ESCAPE '!'") {
						t.Fatalf("discovery must use an indexed platform prefix and retain case variants: %s", query)
					}
					if len(args) != 1 || args[0].Value != tc.pattern {
						t.Fatalf("discovery args = %v, want %q", args, tc.pattern)
					}
					return bucketRows, nil
				}
				if !strings.Contains(query, "WHERE "+tc.predicate+" AND package = ?") {
					t.Fatalf("unexpected source predicate: %s", query)
				}
				var gotArgs []interface{}
				for _, arg := range args {
					gotArgs = append(gotArgs, arg.Value)
				}
				if !reflect.DeepEqual(gotArgs, tc.args) {
					t.Fatalf("query args = %v, want %v", gotArgs, tc.args)
				}
				return rows, nil
			})
			advisories, err := cfg.GetAdvisories(tc.source, "zlib")
			if err != nil {
				t.Fatal(err)
			}
			if len(advisories) != len(tc.wantIDs) {
				t.Fatalf("advisories = %v, want IDs %v", advisories, tc.wantIDs)
			}
			for i, adv := range advisories {
				if adv.VulnerabilityID != tc.wantIDs[i] || !reflect.DeepEqual(adv.DataSource, tc.wantSource[i]) {
					t.Errorf("advisory = %#v (source %#v), want ID %s, source %#v", adv, adv.DataSource, tc.wantIDs[i], tc.wantSource[i])
				}
			}
			if !rows.closed {
				t.Error("rows were not closed")
			}
			wantDiscoveries := 0
			if strings.Contains(tc.source, "::") {
				wantDiscoveries = 1
				if !bucketRows.closed {
					t.Error("source rows were not closed")
				}
			}
			if discoveries != wantDiscoveries {
				t.Errorf("discoveries = %d, want %d", discoveries, wantDiscoveries)
			}
		})
	}
}

func TestGetAdvisoriesErrors(t *testing.T) {
	for _, tc := range []struct {
		name     string
		rows     *advisoryRows
		queryErr error
		wantErr  string
	}{
		{name: "query error", queryErr: errors.New("database unavailable"), wantErr: "failed to query advisories"},
		{name: "invalid JSON", rows: &advisoryRows{values: [][]driver.Value{{"CVE-BAD", "conan::GitLab", "Advisory Database Community", `{broken`}}}, wantErr: "failed to unmarshal advisory CVE-BAD"},
		{name: "scan error", rows: &advisoryRows{values: [][]driver.Value{{"CVE-BAD", nil, "", `{}`}}}, wantErr: "failed to scan advisory row"},
		{name: "read error discards partial results", rows: &advisoryRows{values: [][]driver.Value{{"CVE-PARTIAL", "alpine", "3.18", `{}`}}, err: errors.New("connection lost")}, wantErr: "failed to read advisory rows"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := queryConfig(t, func(string, []driver.NamedValue) (driver.Rows, error) {
				if tc.queryErr != nil {
					return nil, tc.queryErr
				}
				return tc.rows, nil
			})
			got, err := cfg.GetAdvisories("alpine 3.18", "zlib")
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tc.wantErr)
			}
			if got != nil {
				t.Fatalf("returned partial advisories on failure: %v", got)
			}
			if tc.rows != nil && !tc.rows.closed {
				t.Error("rows were not closed after error")
			}
		})
	}
}

func TestParseSource(t *testing.T) {
	for _, tc := range []struct{ source, platform, segment string }{
		{"alpine 3.18", "alpine", "3.18"},
		{"debian", "debian", ""},
		{"conan::GitLab Advisory Database Community", "conan::GitLab", "Advisory Database Community"},
		{"  pip::GitHub\tSecurity Advisory pip  ", "pip::GitHub", "Security Advisory pip"},
		{"", "", ""},
	} {
		platform, segment := parseSource(tc.source)
		if platform != tc.platform || segment != tc.segment {
			t.Errorf("parseSource(%q) = (%q, %q), want (%q, %q)", tc.source, platform, segment, tc.platform, tc.segment)
		}
	}
}

func TestGetAdvisoriesCachesSourceDiscoveryConcurrently(t *testing.T) {
	var discoveries, lookups atomic.Int32
	cfg := queryConfig(t, func(query string, args []driver.NamedValue) (driver.Rows, error) {
		if strings.Contains(query, "SELECT DISTINCT") {
			discoveries.Add(1)
			return sourceRows([]driver.Value{"conan::GitLab Advisory Database Community", ""}), nil
		}
		lookups.Add(1)
		if !strings.Contains(query, "WHERE ((platform = ? AND segment = ?)) AND package = ?") ||
			len(args) != 3 || args[0].Value != "conan::GitLab Advisory Database Community" || args[1].Value != "" {
			return nil, errors.New("package lookup did not use the exact indexed bucket")
		}
		return &advisoryRows{}, nil
	})
	const calls = 16
	errs := make(chan error, calls)
	var wg sync.WaitGroup
	for i := 0; i < calls; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := cfg.GetAdvisories("conan::", "zlib")
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if discoveries.Load() != 1 || lookups.Load() != calls {
		t.Fatalf("discovery queries = %d, package queries = %d; want 1 and %d", discoveries.Load(), lookups.Load(), calls)
	}
}

func TestGetAdvisoriesEmptySourceCacheIsPerConfig(t *testing.T) {
	discoveries := 0
	query := func(query string, _ []driver.NamedValue) (driver.Rows, error) {
		if !strings.Contains(query, "SELECT DISTINCT") {
			return nil, errors.New("missing source should not query package rows")
		}
		discoveries++
		return sourceRows(), nil
	}
	first, second := queryConfig(t, query), queryConfig(t, query)
	for _, cfg := range []*Config{first, first, second, second} {
		got, err := cfg.GetAdvisories("unknown::", "zlib")
		if err != nil || len(got) != 0 {
			t.Fatalf("advisories = %v, error = %v, want no advisory or error", got, err)
		}
	}
	if discoveries != 2 {
		t.Fatalf("discovery queries = %d, want one per Config", discoveries)
	}
}

func TestGetAdvisoriesDoesNotCacheFailedSourceDiscovery(t *testing.T) {
	for _, tc := range []struct {
		name     string
		rows     *advisoryRows
		queryErr error
		wantErr  string
	}{
		{name: "query error", queryErr: errors.New("database unavailable"), wantErr: "failed to discover advisory sources"},
		{name: "scan error", rows: sourceRows([]driver.Value{nil, ""}), wantErr: "failed to scan advisory source"},
		{name: "read error", rows: &advisoryRows{columns: []string{"platform", "segment"},
			values: [][]driver.Value{{"conan::GitLab Advisory Database Community", ""}}, err: errors.New("connection lost")}, wantErr: "failed to read advisory sources"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			discoveries := 0
			cfg := queryConfig(t, func(query string, _ []driver.NamedValue) (driver.Rows, error) {
				if !strings.Contains(query, "SELECT DISTINCT") {
					return nil, errors.New("partial discovery must not be used for package lookups")
				}
				discoveries++
				if discoveries > 1 {
					return sourceRows(), nil
				}
				if tc.queryErr != nil {
					return nil, tc.queryErr
				}
				return tc.rows, nil
			})
			got, err := cfg.GetAdvisories("conan::", "zlib")
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) || got != nil {
				t.Fatalf("first lookup = (%v, %v), want error containing %q", got, err, tc.wantErr)
			}
			got, err = cfg.GetAdvisories("conan::", "zlib")
			if err != nil || len(got) != 0 || discoveries != 2 {
				t.Fatalf("retry = (%v, %v), discoveries = %d, want successful empty discovery on retry", got, err, discoveries)
			}
			if tc.rows != nil && !tc.rows.closed {
				t.Error("source rows were not closed after failure")
			}
		})
	}
}
