package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	trivydb "github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
)

const snapshotCacheTTL = time.Minute

// A long-running client notices an externally published generation within one
// minute. A scan requiring one immutable generation should reopen its client
// after the update, rather than run an updater concurrently with that scan.
func (c *Config) usesSnapshot() (bool, error) {
	if !c.checkSnapshots {
		return false, nil
	}
	c.snapshotMu.Lock()
	defer c.snapshotMu.Unlock()
	if !c.snapshotCheckedAt.IsZero() && time.Since(c.snapshotCheckedAt) < snapshotCacheTTL {
		return c.managedSnapshot, nil
	}
	record, err := readStoredSnapshot(context.Background(), c.db)
	if err != nil {
		return false, err
	}
	digest := ""
	if record != nil {
		digest = record.Digest
	}
	if c.snapshotDigest != digest {
		c.sourceMu.Lock()
		c.sourceBuckets = nil
		c.managedSourceBuckets = nil
		c.sourceCacheAt = time.Time{}
		c.sourceMu.Unlock()
	}
	c.snapshotDigest, c.managedSnapshot = digest, record != nil
	c.snapshotCheckedAt = time.Now()
	return c.managedSnapshot, nil
}

// Caller holds sourceMu.
func (c *Config) expireSourceCache() {
	if c.sourceCacheAt.IsZero() || time.Since(c.sourceCacheAt) >= snapshotCacheTTL {
		c.sourceBuckets = nil
		c.managedSourceBuckets = nil
		c.sourceCacheAt = time.Now()
	}
}

func (c *Config) snapshotRoots(source string) ([]string, error) {
	if !strings.Contains(source, "::") {
		return []string{source}, nil
	}
	c.sourceMu.Lock()
	defer c.sourceMu.Unlock()
	c.expireSourceCache()
	if roots, ok := c.managedSourceBuckets[source]; ok {
		return roots, nil
	}
	pattern := strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(source) + "%"
	// The official source registry is small and contains each complete bucket
	// name once. Reading it avoids scanning advisory rows or applying MySQL's
	// BLOB DISTINCT/sort prefix limit to arbitrarily long source names.
	path := encodeBucketPath([]string{"data-source"})
	rows, err := c.db.Query(`SELECT entry_key FROM bolt_db_auxiliary
        WHERE bucket_hash = ? AND bucket_path = ? AND entry_kind = 0
            AND entry_key LIKE ? ESCAPE '!'`, bucketPathHash(path), path, pattern)
	if err != nil {
		return nil, fmt.Errorf("discover snapshot sources: %w", err)
	}
	defer rows.Close()
	var roots []string
	for rows.Next() {
		var root string
		if err := rows.Scan(&root); err != nil {
			return nil, fmt.Errorf("read snapshot source: %w", err)
		}
		if strings.HasPrefix(root, source) {
			roots = append(roots, root)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read snapshot sources: %w", err)
	}
	sort.Strings(roots)
	if c.managedSourceBuckets == nil {
		c.managedSourceBuckets = make(map[string][]string)
	}
	c.managedSourceBuckets[source] = roots
	return roots, nil
}

func (c *Config) snapshotForEachAdvisory(sources []string, pkgName string) (map[string]trivydb.Value, error) {
	if len(sources) == 0 {
		return nil, fmt.Errorf("advisory source bucket path is required")
	}
	roots, err := c.snapshotRoots(sources[0])
	if err != nil {
		return nil, err
	}
	values := make(map[string]trivydb.Value)
	selectedRoots := make(map[string]string)
	if len(roots) == 0 {
		return values, nil
	}
	dataSourcePath := encodeBucketPath([]string{"data-source"})
	args := []interface{}{bucketPathHash(dataSourcePath), dataSourcePath}
	var conditions []string
	for _, root := range roots {
		path := append([]string{root}, sources[1:]...)
		encoded := encodeBucketPath(path)
		conditions = append(conditions, "(a.bucket_hash = ? AND a.bucket_path = ?)")
		args = append(args, bucketPathHash(encoded), encoded)
	}
	args = append(args, []byte(pkgName))
	rows, err := c.db.Query(`SELECT a.vulnerability_id, a.source_name, a.value, s.value
        FROM vulnerability_advisories a
        LEFT JOIN bolt_db_auxiliary s ON s.bucket_hash = ? AND s.bucket_path = ?
            AND s.entry_kind = 0 AND s.entry_key = a.source_name
        WHERE (`+strings.Join(conditions, " OR ")+`) AND a.package = ?
        ORDER BY a.source_name, a.vulnerability_id`, args...)
	if err != nil {
		return nil, fmt.Errorf("query snapshot advisories: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, root string
		var raw, sourceJSON []byte
		if err := rows.Scan(&id, &root, &raw, &sourceJSON); err != nil {
			return nil, fmt.Errorf("read snapshot advisory: %w", err)
		}
		if len(raw) == 0 {
			continue
		}
		var source types.DataSource
		if len(sourceJSON) != 0 {
			if err := json.Unmarshal(sourceJSON, &source); err != nil {
				return nil, fmt.Errorf("decode snapshot data-source %q: %w", root, err)
			}
		}
		// Official BoltDB visits root buckets in byte order and lets the last
		// source win when two sources have the same vulnerability identifier.
		// Compare full names in Go too: MySQL's BLOB sort prefix may be shorter
		// than a future source name, and cannot determine ties in that case.
		if prior, ok := selectedRoots[id]; ok && prior > root {
			continue
		}
		selectedRoots[id] = root
		values[id] = trivydb.Value{Source: source, Content: raw}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read snapshot advisories: %w", err)
	}
	return values, nil
}

func (c *Config) snapshotAdvisories(source, pkgName string) ([]types.Advisory, error) {
	values, err := c.snapshotForEachAdvisory([]string{source}, pkgName)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(values))
	for id := range values {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var advisories []types.Advisory
	for _, id := range ids {
		value := values[id]
		var advisory types.Advisory
		if err := json.Unmarshal(value.Content, &advisory); err != nil {
			return nil, fmt.Errorf("decode snapshot advisory %s: %w", id, err)
		}
		advisory.VulnerabilityID = id
		if value.Source != (types.DataSource{}) {
			source := value.Source
			advisory.DataSource = &source
		}
		advisories = append(advisories, advisory)
	}
	return advisories, nil
}

func (c *Config) snapshotCPEs(bucket, key string) ([]int, error) {
	encoded := encodeBucketPath([]string{"Red Hat CPE", bucket})
	var raw []byte
	err := c.db.QueryRow(`SELECT value FROM bolt_db_auxiliary
        WHERE bucket_hash = ? AND bucket_path = ? AND entry_key = ? AND entry_kind = 0`,
		bucketPathHash(encoded), encoded, []byte(key)).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read Red Hat %s mapping: %w", bucket, err)
	}
	var indices []int
	if err := json.Unmarshal(raw, &indices); err != nil {
		return nil, fmt.Errorf("decode Red Hat %s mapping: %w", bucket, err)
	}
	return indices, nil
}

func (c *Config) snapshotVulnerabilityDetails(cveID string) (map[types.SourceID]types.VulnerabilityDetail, error) {
	encoded := encodeBucketPath([]string{"vulnerability-detail", cveID})
	rows, err := c.db.Query(`SELECT entry_key,value FROM bolt_db_auxiliary
        WHERE bucket_hash = ? AND bucket_path = ? AND entry_kind = 0`, bucketPathHash(encoded), encoded)
	if err != nil {
		return nil, fmt.Errorf("query vulnerability details: %w", err)
	}
	defer rows.Close()
	var values map[types.SourceID]types.VulnerabilityDetail
	for rows.Next() {
		var key string
		var raw []byte
		if err := rows.Scan(&key, &raw); err != nil {
			return nil, fmt.Errorf("read vulnerability detail: %w", err)
		}
		var detail types.VulnerabilityDetail
		if err := json.Unmarshal(raw, &detail); err != nil {
			return nil, fmt.Errorf("decode vulnerability detail: %w", err)
		}
		if values == nil {
			values = make(map[types.SourceID]types.VulnerabilityDetail)
		}
		values[types.SourceID(key)] = detail
	}
	return values, rows.Err()
}
