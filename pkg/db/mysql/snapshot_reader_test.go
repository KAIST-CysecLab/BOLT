package mysql

import (
	"bytes"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aquasecurity/trivy-db/pkg/metadata"
	"github.com/aquasecurity/trivy-db/pkg/types"
)

func managedTestConfig(cfg *Config) *Config {
	cfg.checkSnapshots, cfg.managedSnapshot = true, true
	cfg.snapshotCheckedAt = time.Now()
	return cfg
}

func TestSnapshotForEachUsesBucketPathAndOriginalMetadata(t *testing.T) {
	const source = "conan::Vendor_!%"
	first, last := source+" A", source+" Z"
	var discovered int
	cfg := managedTestConfig(queryConfig(t, func(query string, args []driver.NamedValue) (driver.Rows, error) {
		if strings.HasPrefix(query, "SELECT entry_key FROM bolt_db_auxiliary") {
			discovered++
			if len(args) != 3 || args[2].Value != "conan::Vendor!_!!!%%" {
				t.Fatalf("wildcard prefix not escaped: %v", args)
			}
			return &advisoryRows{columns: []string{"source_name"}, values: [][]driver.Value{{first}, {last}, {"conan::VendorXwrong"}}}, nil
		}
		if !strings.Contains(query, "a.bucket_hash = ? AND a.bucket_path = ?") || !strings.Contains(query, "LEFT JOIN bolt_db_auxiliary") {
			t.Fatalf("missing exact indexed path/source metadata join: %s", query)
		}
		// sources is a nested bucket path. Its second item must not become an
		// alternative source root (the old SQL implementation did that).
		if len(args) != 7 || !bytes.Equal(args[3].Value.([]byte), encodeBucketPath([]string{first, "nested/path"})) ||
			!bytes.Equal(args[5].Value.([]byte), encodeBucketPath([]string{last, "nested/path"})) ||
			!bytes.Equal(args[6].Value.([]byte), []byte("@Scope/CaseSensitive")) {
			t.Fatalf("wrong bucket path arguments: %v", args)
		}
		return &advisoryRows{columns: []string{"vulnerability_id", "source_name", "value", "source"}, values: [][]driver.Value{
			{"CVE-SHARED", last, `{"VulnerableVersions":["<2.0"],"NewField":42}`, `{"ID":"vendor-z","Name":"Exact vendor name","URL":"https://example.test/original"}`},
			{"CVE-SHARED", first, `{"VulnerableVersions":["<1.0"]}`, `{"ID":"vendor-a"}`},
		}}, nil
	}))
	for i := 0; i < 2; i++ {
		values, err := cfg.ForEachAdvisory([]string{source, "nested/path"}, "@Scope/CaseSensitive")
		if err != nil {
			t.Fatal(err)
		}
		v := values["CVE-SHARED"]
		if len(values) != 1 || !bytes.Contains(v.Content, []byte(`"NewField":42`)) ||
			v.Source != (types.DataSource{ID: "vendor-z", Name: "Exact vendor name", URL: "https://example.test/original"}) {
			t.Fatalf("raw advisory/source or duplicate semantics changed: %#v", values)
		}
	}
	if discovered != 1 {
		t.Fatalf("prefix lookups not cached: %d", discovered)
	}
}

func TestSnapshotGetAdvisoriesAndCPEs(t *testing.T) {
	cfg := managedTestConfig(queryConfig(t, func(query string, args []driver.NamedValue) (driver.Rows, error) {
		if strings.Contains(query, "FROM vulnerability_advisories a") {
			if !bytes.Equal(args[3].Value.([]byte), encodeBucketPath([]string{"Azure Linux 3.0"})) {
				t.Fatalf("source name split or normalized: %v", args)
			}
			return &advisoryRows{columns: []string{"id", "source", "raw", "metadata"}, values: [][]driver.Value{
				{"CVE-2", "Azure Linux 3.0", `{"FixedVersion":"2.0","DataSource":{"ID":"embedded","Name":"Embedded"}}`, `{"ID":"azure","Name":"Official source"}`},
				{"CVE-1", "Azure Linux 3.0", `{"FixedVersion":"1.0"}`, `{"ID":"azure","Name":"Official source","URL":"https://example.test/feed"}`},
			}}, nil
		}
		if strings.Contains(query, "FROM bolt_db_auxiliary") {
			var path [][]byte
			if err := json.Unmarshal(args[1].Value.([]byte), &path); err != nil {
				t.Fatal(err)
			}
			if string(path[0]) != "Red Hat CPE" || (string(path[1]) != "repository" && string(path[1]) != "nvr") {
				t.Fatalf("incorrect CPE path: %q", path)
			}
			return &advisoryRows{columns: []string{"value"}, values: [][]driver.Value{{`[1,7]`}}}, nil
		}
		return nil, errors.New("unexpected query")
	}))
	advisories, err := cfg.GetAdvisories("Azure Linux 3.0", "zlib")
	if err != nil {
		t.Fatal(err)
	}
	if len(advisories) != 2 || advisories[0].VulnerabilityID != "CVE-1" || advisories[0].DataSource.URL != "https://example.test/feed" || advisories[1].DataSource.ID != "azure" {
		t.Fatalf("advisories = %#v", advisories)
	}
	for _, lookup := range []func(string) ([]int, error){cfg.RedHatRepoToCPEs, cfg.RedHatNVRToCPEs} {
		indices, err := lookup("literal/key")
		if err != nil || !reflect.DeepEqual(indices, []int{1, 7}) {
			t.Fatalf("indices=%v error=%v", indices, err)
		}
	}
}

func TestSnapshotReaderReturnsDatabaseFailures(t *testing.T) {
	cfg := managedTestConfig(queryConfig(t, func(string, []driver.NamedValue) (driver.Rows, error) { return nil, errors.New("permission denied") }))
	if _, err := cfg.GetAdvisories("ubuntu 24.04", "zlib"); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("error=%v", err)
	}
	if _, err := cfg.ForEachAdvisory(nil, "zlib"); err == nil {
		t.Fatal("accepted empty bucket path")
	}
	if _, err := cfg.RedHatNVRToCPEs("zlib"); err == nil {
		t.Fatal("ignored CPE read failure")
	}
}

func TestSnapshotVulnerabilityDetailsAbsentInOptimizedDB(t *testing.T) {
	cfg := queryConfig(t, func(query string, args []driver.NamedValue) (driver.Rows, error) {
		if !strings.Contains(query, "FROM bolt_db_auxiliary") ||
			!bytes.Equal(args[1].Value.([]byte), encodeBucketPath([]string{"vulnerability-detail", "CVE-TEST"})) {
			t.Fatalf("unexpected detail lookup: %s, %v", query, args)
		}
		return &advisoryRows{columns: []string{"entry_key", "value"}}, nil
	})
	values, err := cfg.GetVulnerabilityDetail("CVE-TEST")
	if err != nil || values != nil {
		t.Fatalf("official optimized DB should return nil, nil; got %v, %v", values, err)
	}
}

func TestSnapshotGenerationRefreshInvalidatesSourceCache(t *testing.T) {
	var reads int
	cfg := queryConfig(t, func(query string, _ []driver.NamedValue) (driver.Rows, error) {
		reads++
		if !strings.Contains(query, "FROM bolt_db_metadata") {
			t.Fatalf("unexpected query: %s", query)
		}
		raw, _ := json.Marshal(storedSnapshot{Format: snapshotFormat, Snapshot: Snapshot{Digest: "new-digest", Metadata: metadata.Metadata{UpdatedAt: time.Now()}}})
		return &advisoryRows{columns: []string{"value"}, values: [][]driver.Value{{raw}}}, nil
	})
	cfg.checkSnapshots = true
	cfg.snapshotDigest = "old-digest"
	cfg.snapshotCheckedAt = time.Now().Add(-2 * time.Minute)
	cfg.sourceBuckets = map[string][]advisoryBucket{"old": {{platform: "old"}}}
	cfg.managedSourceBuckets = map[string][]string{"old": {"old"}}
	for i := 0; i < 2; i++ {
		managed, err := cfg.usesSnapshot()
		if err != nil || !managed {
			t.Fatalf("managed=%v error=%v", managed, err)
		}
	}
	if reads != 1 || len(cfg.sourceBuckets) != 0 || len(cfg.managedSourceBuckets) != 0 {
		t.Fatalf("reads=%d stale caches=%v/%v", reads, cfg.sourceBuckets, cfg.managedSourceBuckets)
	}
}
