package mysql

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aquasecurity/trivy-db/pkg/metadata"
	bolt "go.etcd.io/bbolt"
)

// Snapshot identifies the complete, verified official database to import.
// Digest is the OCI manifest digest; DBPath is a local, uncompressed trivy.db.
type Snapshot struct {
	Repository string            `json:"repository"`
	Digest     string            `json:"digest"`
	DBPath     string            `json:"-"`
	DBSHA256   string            `json:"db_sha256"`
	DBSize     int64             `json:"db_size"`
	Metadata   metadata.Metadata `json:"metadata"`
}

type SyncResult struct {
	Changed         bool   `json:"changed"`
	Vulnerabilities int64  `json:"vulnerabilities"`
	Advisories      int64  `json:"advisories"`
	Digest          string `json:"digest"`
}

type storedSnapshot struct {
	Snapshot
	Vulnerabilities int64     `json:"vulnerabilities"`
	Advisories      int64     `json:"advisories"`
	Auxiliary       int64     `json:"auxiliary"`
	ImportedAt      time.Time `json:"imported_at"`
	Format          int       `json:"format"`
}

const snapshotFormat = 1

// A JSON array of byte strings (base64), rather than a delimiter, preserves
// arbitrary bucket names, including invalid UTF-8 and embedded delimiters.
func encodeBucketPath(path []string) []byte {
	parts := make([][]byte, len(path))
	for i, p := range path {
		parts[i] = []byte(p)
	}
	b, _ := json.Marshal(parts)
	return b
}

func bucketPathHash(path []byte) []byte {
	h := sha256.Sum256(path)
	return h[:]
}

type snapshotRecord struct {
	table string
	args  []interface{}
}

// walkSnapshot streams all leaf values. Known advisory trees are projected for
// indexed lookups; all other trees (including future source formats) survive in
// auxiliary storage. Raw payloads are never decoded into a versioned Go struct.
func walkSnapshot(ctx context.Context, db *bolt.DB, emit func(snapshotRecord) error) error {
	return db.View(func(tx *bolt.Tx) error {
		if tx.Bucket([]byte("vulnerability")) == nil || tx.Bucket([]byte("data-source")) == nil {
			return fmt.Errorf("official database must contain vulnerability and data-source buckets")
		}
		sources := make(map[string]bool)
		if err := tx.Bucket([]byte("data-source")).ForEach(func(k, v []byte) error {
			if v != nil {
				if !json.Valid(v) {
					return fmt.Errorf("invalid data-source JSON for %q", k)
				}
				sources[string(k)] = true
			}
			return nil
		}); err != nil {
			return err
		}
		var walk func(*bolt.Bucket, []string) error
		walk = func(b *bolt.Bucket, path []string) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			// Preserve empty buckets as well as raw leaf records. The current
			// official database does not rely on bucket sequence numbers.
			k, _ := b.Cursor().First()
			if k == nil {
				encoded := encodeBucketPath(path)
				return emit(snapshotRecord{"bolt_db_auxiliary", []interface{}{bucketPathHash(encoded), encoded, []byte{}, 1, []byte{}}})
			}
			return b.ForEach(func(k, v []byte) error {
				if err := ctx.Err(); err != nil {
					return err
				}
				if v == nil {
					return walk(b.Bucket(k), append(append([]string(nil), path...), string(k)))
				}
				if path[0] == "vulnerability" && len(path) == 1 {
					if !json.Valid(v) {
						return fmt.Errorf("invalid vulnerability JSON for %q", k)
					}
					return emit(snapshotRecord{"vulnerabilities", []interface{}{k, v}})
				}
				// Advisory source membership comes from the official data-source
				// bucket, not a fixed list of ecosystems or a CVE name heuristic.
				if sources[path[0]] && len(path) >= 2 {
					if !json.Valid(v) {
						return fmt.Errorf("invalid advisory JSON in %q for %q", path, k)
					}
					parents := path[:len(path)-1]
					encoded := encodeBucketPath(parents)
					platform, segment := splitSnapshotSource(path[0])
					return emit(snapshotRecord{"vulnerability_advisories", []interface{}{
						k, []byte(platform), []byte(segment), []byte(path[len(path)-1]), v,
						[]byte(path[0]), bucketPathHash(encoded), encoded,
					}})
				}
				encoded := encodeBucketPath(path)
				return emit(snapshotRecord{"bolt_db_auxiliary", []interface{}{bucketPathHash(encoded), encoded, k, 0, v}})
			})
		}
		return tx.ForEach(func(k []byte, b *bolt.Bucket) error {
			return walk(b, []string{string(k)})
		})
	})
}

// The compatibility columns are only a projection. Canonical source names and
// bucket paths remain available in full, with their original byte semantics.
func splitSnapshotSource(source string) (string, string) {
	if strings.Contains(source, "::") {
		return source, ""
	}
	platform, segment, _ := strings.Cut(source, " ")
	return platform, segment
}
