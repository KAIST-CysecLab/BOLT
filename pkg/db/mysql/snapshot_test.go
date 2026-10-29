package mysql

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aquasecurity/trivy-db/pkg/metadata"
	bolt "go.etcd.io/bbolt"
)

type snapshotEntry struct {
	path []string
	key  string
	raw  []byte
}

func fixtureSnapshot(t *testing.T, extra ...snapshotEntry) Snapshot {
	t.Helper()
	path := filepath.Join(t.TempDir(), "trivy.db")
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	entries := append([]snapshotEntry{
		{[]string{"vulnerability"}, "CVE-TEST", []byte(` {"Title":"test","FutureField":{"keep":true}} `)},
		{[]string{"data-source"}, "conan::Vendor Database", []byte(`{"ID":"vendor","Name":"Original source","URL":"https://example.test/feed","Future":42}`)},
		{[]string{"conan::Vendor Database", "zlib"}, "CVE-TEST", []byte(`{"VulnerableVersions":["<1.2.13"],"Custom":{"Future":{"keep":true}}}`)},
	}, extra...)
	err = db.Update(func(tx *bolt.Tx) error {
		for _, entry := range entries {
			b, err := tx.CreateBucketIfNotExists([]byte(entry.path[0]))
			if err != nil {
				return err
			}
			for _, name := range entry.path[1:] {
				b, err = b.CreateBucketIfNotExists([]byte(name))
				if err != nil {
					return err
				}
			}
			if entry.key != "" {
				if err := b.Put([]byte(entry.key), entry.raw); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	return Snapshot{
		Repository: "ghcr.io/aquasecurity/trivy-db:2", Digest: "sha256:" + strings.Repeat("a", 64), DBPath: path,
		Metadata: metadata.Metadata{Version: 2, UpdatedAt: time.Date(2026, 10, 2, 1, 0, 0, 0, time.UTC)},
	}
}

func TestWalkSnapshotPreservesPayloadsAndBuckets(t *testing.T) {
	longPackage := "@Scope/" + strings.Repeat("package", 170)
	unknownRaw := []byte{0, 1, 255, 254}
	snapshot := fixtureSnapshot(t,
		snapshotEntry{[]string{"conan::Vendor Database", "nested/source", longPackage}, "GHSA-CASE", []byte(`{"UnknownFutureField":true}`)},
		snapshotEntry{[]string{"Red Hat CPE", "repository"}, "rhel/9 repo", []byte(`[1,9]`)},
		snapshotEntry{[]string{"Red Hat CPE", "nvr"}, "zlib-1.2.13-1", []byte(`[9]`)},
		snapshotEntry{[]string{"Red Hat CPE", "cpe"}, "9", []byte(`"cpe:/o:redhat:enterprise_linux:9"`)},
		snapshotEntry{[]string{"unknown future", string([]byte{255, 254})}, "raw", unknownRaw},
		snapshotEntry{[]string{"unknown future", "empty"}, "", nil},
	)
	db, err := bolt.Open(snapshot.DBPath, 0400, &bolt.Options{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	counts := map[string]int{}
	foundLong, foundRaw, foundEmpty, foundSource, foundVuln := false, false, false, false, false
	err = walkSnapshot(context.Background(), db, func(record snapshotRecord) error {
		counts[record.table]++
		switch record.table {
		case "vulnerabilities":
			foundVuln = bytes.Equal(record.args[1].([]byte), []byte(` {"Title":"test","FutureField":{"keep":true}} `))
		case "vulnerability_advisories":
			if string(record.args[3].([]byte)) == longPackage {
				foundLong = bytes.Equal(record.args[7].([]byte), encodeBucketPath([]string{"conan::Vendor Database", "nested/source"})) &&
					bytes.Equal(record.args[4].([]byte), []byte(`{"UnknownFutureField":true}`))
			}
		case "bolt_db_auxiliary":
			if string(record.args[2].([]byte)) == "raw" {
				foundRaw = bytes.Equal(record.args[4].([]byte), unknownRaw)
				var parts [][]byte
				if err := json.Unmarshal(record.args[1].([]byte), &parts); err != nil || !bytes.Equal(parts[1], []byte{255, 254}) {
					t.Fatalf("binary bucket path was changed: %v, %v", parts, err)
				}
			}
			if record.args[3] == 1 {
				foundEmpty = bytes.Equal(record.args[1].([]byte), encodeBucketPath([]string{"unknown future", "empty"}))
			}
			if string(record.args[2].([]byte)) == "conan::Vendor Database" {
				foundSource = bytes.Contains(record.args[4].([]byte), []byte(`"Future":42`))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !foundLong || !foundRaw || !foundEmpty || !foundSource || !foundVuln {
		t.Fatalf("data lost: long=%v raw=%v empty=%v source=%v vulnerability=%v", foundLong, foundRaw, foundEmpty, foundSource, foundVuln)
	}
	if !reflect.DeepEqual(counts, map[string]int{"vulnerabilities": 1, "vulnerability_advisories": 2, "bolt_db_auxiliary": 6}) {
		t.Fatalf("counts = %v", counts)
	}
}

func TestWalkSnapshotRejectsInvalidJSONAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		raw    []byte
		cancel bool
	}{
		{"invalid advisory", []byte(`{broken`), false},
		{"cancellation", []byte(`{}`), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := fixtureSnapshot(t, snapshotEntry{[]string{"conan::Vendor Database", "broken"}, "CVE-BROKEN", tc.raw})
			db, err := bolt.Open(snapshot.DBPath, 0400, &bolt.Options{ReadOnly: true})
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancel {
				cancel()
			}
			if err := walkSnapshot(ctx, db, func(snapshotRecord) error { return nil }); err == nil {
				t.Fatal("expected failed import")
			}
		})
	}
}

func TestValidateSnapshot(t *testing.T) {
	snapshot := fixtureSnapshot(t)
	if err := validateSnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Snapshot){
		func(s *Snapshot) { s.Digest = "tag:latest" },
		func(s *Snapshot) { s.Metadata.Version = 99 },
		func(s *Snapshot) { s.Metadata.UpdatedAt = time.Time{} },
		func(s *Snapshot) { s.DBPath = filepath.Dir(s.DBPath) },
		func(s *Snapshot) { s.Repository = "" },
	} {
		copy := snapshot
		mutate(&copy)
		if err := validateSnapshot(copy); err == nil {
			t.Fatalf("accepted invalid snapshot: %+v", copy)
		}
	}
	if err := os.Remove(snapshot.DBPath); err != nil {
		t.Fatal(err)
	}
	if err := validateSnapshot(snapshot); err == nil {
		t.Fatal("accepted missing database")
	}
}
