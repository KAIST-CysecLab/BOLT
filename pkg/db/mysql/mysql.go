// Modified by slyfizz on 2025-12-05: added MySQL backend support

package mysql

import (
	"database/sql"
	"encoding/json"
	"net/url"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"

	trivydb "github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
)

// Config implements trivy-db's Operation interface for MySQL
type Config struct {
	db *sql.DB

	sourceMu             sync.Mutex
	sourceBuckets        map[string][]advisoryBucket
	sourceCacheAt        time.Time
	managedSourceBuckets map[string][]string

	snapshotMu        sync.Mutex
	checkSnapshots    bool
	snapshotCheckedAt time.Time
	snapshotDigest    string
	managedSnapshot   bool
}

type advisoryBucket struct {
	platform string
	segment  string
}

// New creates a new MySQL backend
func New(dsn string) (*Config, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to open mysql")
	}

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, oops.Wrapf(err, "failed to ping mysql")
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	c := &Config{db: db, checkSnapshots: true}
	if _, err := c.usesSnapshot(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return c, nil
}

func (c *Config) Close() error {
	if c.db != nil {
		if err := c.db.Close(); err != nil {
			return oops.Wrapf(err, "failed to close mysql")
		}
	}
	return nil
}

func (c *Config) GetVulnerability(vulnerabilityID string) (types.Vulnerability, error) {
	query := "SELECT value FROM vulnerabilities WHERE vulnerability_id = ?"

	var valueJSON []byte
	err := c.db.QueryRow(query, vulnerabilityID).Scan(&valueJSON)

	if err == sql.ErrNoRows {
		return types.Vulnerability{}, oops.Errorf("vulnerability %s not found", vulnerabilityID)
	}
	if err != nil {
		return types.Vulnerability{}, oops.Wrapf(err, "failed to query vulnerability")
	}

	// Parse the JSON
	var vuln types.Vulnerability
	if err := json.Unmarshal(valueJSON, &vuln); err != nil {
		return types.Vulnerability{}, oops.Wrapf(err, "failed to unmarshal vulnerability JSON")
	}

	return vuln, nil
}

func (c *Config) GetAdvisories(source string, pkgName string) ([]types.Advisory, error) {
	if managed, err := c.usesSnapshot(); err != nil {
		return nil, err
	} else if managed {
		return c.snapshotAdvisories(source, pkgName)
	}
	predicate, args, err := c.advisorySourceCondition(source)
	if err != nil {
		return nil, err
	}
	if predicate == "" {
		return nil, nil
	}
	query := `
        SELECT vulnerability_id, platform, segment, value
        FROM vulnerability_advisories
        WHERE ` + predicate + ` AND package = ?
        ORDER BY vulnerability_id, platform, segment
    `
	args = append(args, pkgName)

	rows, err := c.db.Query(query, args...)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to query advisories")
	}
	defer rows.Close()

	var advisories []types.Advisory
	for rows.Next() {
		var (
			vulnID    string
			platform  string
			segment   string
			valueJSON []byte
		)

		if err := rows.Scan(&vulnID, &platform, &segment, &valueJSON); err != nil {
			return nil, oops.Wrapf(err, "failed to scan advisory row")
		}
		// Indexed equality follows the table's collation. Recheck the literal
		// source prefix so case-insensitive collations cannot add other buckets.
		if strings.Contains(source, "::") && !strings.HasPrefix(advisorySourceName(platform, segment), source) {
			continue
		}

		// Parse the JSON
		var adv types.Advisory
		if err := json.Unmarshal(valueJSON, &adv); err != nil {
			return nil, oops.Wrapf(err, "failed to unmarshal advisory %s", vulnID)
		}

		adv.VulnerabilityID = vulnID

		if adv.DataSource == nil {
			adv.DataSource = advisoryDataSource(platform, segment)
		}

		advisories = append(advisories, adv)
	}

	if err := rows.Err(); err != nil {
		return nil, oops.Wrapf(err, "failed to read advisory rows")
	}
	return advisories, nil
}

// advisorySourceCondition preserves exact OS queries. Ecosystem prefixes first
// resolve to stored buckets, then use the (platform, segment, package) index.
func (c *Config) advisorySourceCondition(source string) (string, []interface{}, error) {
	if !strings.Contains(source, "::") {
		platform, segment := parseSource(source)
		return "platform = ? AND segment = ?", []interface{}{platform, segment}, nil
	}
	buckets, err := c.findAdvisoryBuckets(source)
	if err != nil {
		return "", nil, err
	}
	if len(buckets) == 0 {
		return "", nil, nil
	}
	conditions := make([]string, 0, len(buckets))
	args := make([]interface{}, 0, 2*len(buckets))
	for _, bucket := range buckets {
		conditions = append(conditions, "(platform = ? AND segment = ?)")
		args = append(args, bucket.platform, bucket.segment)
	}
	return "(" + strings.Join(conditions, " OR ") + ")", args, nil
}

// findAdvisoryBuckets discovers a prefix's buckets once per Config. The lock
// also prevents concurrent first lookups from repeating the discovery query.
// Failed discoveries are never cached. A successful empty result is cached.
func (c *Config) findAdvisoryBuckets(source string) ([]advisoryBucket, error) {
	c.sourceMu.Lock()
	defer c.sourceMu.Unlock()
	c.expireSourceCache()
	if buckets, ok := c.sourceBuckets[source]; ok {
		return buckets, nil
	}

	// Both supported exports retain the source's first word in platform: either
	// the whole bucket lives there, or remaining words live in segment. LIKE
	// narrows the indexed scan; Go's prefix check below supplies byte semantics.
	firstWord := strings.Fields(source)[0]
	pattern := strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(firstWord) + "%"
	rows, err := c.db.Query(`
        SELECT DISTINCT BINARY platform AS platform, BINARY segment AS segment
        FROM vulnerability_advisories
        WHERE platform LIKE ? ESCAPE '!'
        ORDER BY platform, segment
    `, pattern)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to discover advisory sources")
	}
	defer rows.Close()
	var buckets []advisoryBucket
	for rows.Next() {
		var bucket advisoryBucket
		if err := rows.Scan(&bucket.platform, &bucket.segment); err != nil {
			return nil, oops.Wrapf(err, "failed to scan advisory source")
		}
		if strings.HasPrefix(advisorySourceName(bucket.platform, bucket.segment), source) {
			buckets = append(buckets, bucket)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, oops.Wrapf(err, "failed to read advisory sources")
	}
	if c.sourceBuckets == nil {
		c.sourceBuckets = make(map[string][]advisoryBucket)
	}
	c.sourceBuckets[source] = buckets
	return buckets, nil
}

func advisorySourceName(platform, segment string) string {
	if segment == "" {
		return platform
	}
	return platform + " " + segment
}

// advisoryDataSource recovers metadata for known language buckets when an export
// omitted DataSource. Unknown sources retain their full identity without guessing.
func advisoryDataSource(platform, segment string) *types.DataSource {
	source := advisorySourceName(platform, segment)
	_, name, languageSource := strings.Cut(source, "::")
	if !languageSource {
		return buildDataSource(platform)
	}
	switch {
	case name == "GitLab Advisory Database Community":
		return &types.DataSource{
			ID: "glad", Name: name,
			URL: "https://gitlab.com/gitlab-org/advisories-community",
		}
	case strings.HasPrefix(name, "GitHub Security Advisory "):
		return &types.DataSource{
			ID: "ghsa", Name: name,
			URL: "https://github.com/advisories?query=type%3Areviewed+ecosystem%3A" + url.QueryEscape(strings.TrimPrefix(name, "GitHub Security Advisory ")),
		}
	default:
		return &types.DataSource{ID: types.SourceID(source), Name: source}
	}
}

// buildDataSource creates DataSource based on platform
// Source: https://github.com/aquasecurity/trivy-db/tree/main/pkg/vulnsrc
func buildDataSource(platform string) *types.DataSource {
	sources := map[string]types.DataSource{
		// OS Packages
		"alpine": {
			ID:   "alpine",
			Name: "Alpine Secdb",
			URL:  "https://secdb.alpinelinux.org/",
		},
		"ubuntu": {
			ID:   "ubuntu",
			Name: "Ubuntu CVE Tracker",
			URL:  "https://git.launchpad.net/ubuntu-cve-tracker",
		},
		"debian": {
			ID:   "debian",
			Name: "Debian Security Tracker",
			URL:  "https://salsa.debian.org/security-tracker-team/security-tracker",
		},
		"redhat": {
			ID:   "redhat-oval",
			Name: "Red Hat OVAL v2",
			URL:  "https://www.redhat.com/security/data/oval/v2/",
		},
		"centos": {
			ID:   "redhat-oval",
			Name: "Red Hat OVAL v2",
			URL:  "https://www.redhat.com/security/data/oval/v2/",
		},
		"oracle": {
			ID:   "oracle-oval",
			Name: "Oracle Linux OVAL definitions",
			URL:  "https://linux.oracle.com/security/oval/",
		},
		"rocky": {
			ID:   "rocky",
			Name: "Rocky Linux updateinfo",
			URL:  "https://download.rockylinux.org/pub/rocky/",
		},
		"alma": {
			ID:   "alma",
			Name: "AlmaLinux Product Errata",
			URL:  "https://errata.almalinux.org/",
		},
		"amazon": {
			ID:   "amazon",
			Name: "Amazon Linux Security Center",
			URL:  "https://alas.aws.amazon.com/",
		},
		"photon": {
			ID:   "photon",
			Name: "Photon OS CVE metadata",
			URL:  "https://packages.vmware.com/photon/photon_cve_metadata/",
		},
		"suse": {
			ID:   "suse-cvrf",
			Name: "SUSE CVRF",
			URL:  "https://ftp.suse.com/pub/projects/security/cvrf/",
		},
		"chainguard": {
			ID:   "chainguard",
			Name: "Chainguard Security Data",
			URL:  "https://packages.cgr.dev/chainguard/security.json",
		},
		"wolfi": {
			ID:   "wolfi",
			Name: "Wolfi Secdb",
			URL:  "https://packages.wolfi.dev/os/security.json",
		},
		"azure": {
			ID:   "azure",
			Name: "Azure Linux Vulnerability Data",
			URL:  "https://github.com/microsoft/AzureLinuxVulnerabilityData",
		},
	}

	if ds, ok := sources[platform]; ok {
		return &ds
	}

	// Default (unknown platform)
	return &types.DataSource{
		ID:   types.SourceID(platform),
		Name: platform,
		URL:  "",
	}
}

// parseSource splits source into platform and segment
// e.g. "alpine 3.18" -> ("alpine", "3.18")
// e.g. "debian 11" -> ("debian", "11")
func parseSource(source string) (platform, segment string) {
	parts := strings.Fields(source) // split on whitespace
	if len(parts) >= 2 {
		platform = parts[0]
		segment = strings.Join(parts[1:], " ")
	} else if len(parts) == 1 {
		platform = parts[0]
		segment = ""
	}
	return
}

func (c *Config) ForEachAdvisory(sources []string, pkgName string) (map[string]trivydb.Value, error) {
	if managed, err := c.usesSnapshot(); err != nil {
		return nil, err
	} else if managed {
		return c.snapshotForEachAdvisory(sources, pkgName)
	}
	values := make(map[string]trivydb.Value)

	query := `
        SELECT DISTINCT
            vulnerability_id,
            platform,
            segment,
            value
        FROM vulnerability_advisories
        WHERE package = ?
    `
	args := []interface{}{pkgName}

	if len(sources) > 0 {
		// Parse sources into platform and segment
		var conditions []string
		for _, source := range sources {
			platform, segment := parseSource(source)
			conditions = append(conditions, "(platform = ? AND segment = ?)")
			args = append(args, platform, segment)
		}
		query += ` AND (` + strings.Join(conditions, " OR ") + `)`
	}

	rows, err := c.db.Query(query, args...)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to query advisories")
	}
	defer rows.Close()

	for rows.Next() {
		var (
			vulnID    string
			platform  string
			segment   string
			valueJSON []byte
		)

		if err := rows.Scan(&vulnID, &platform, &segment, &valueJSON); err != nil {
			continue
		}

		// Add the DataSource
		dataSource := buildDataSource(platform)

		values[vulnID] = trivydb.Value{
			Source:  *dataSource,
			Content: valueJSON,
		}
	}

	return values, rows.Err()
}

func (c *Config) GetVulnerabilityDetail(cveID string) (map[types.SourceID]types.VulnerabilityDetail, error) {
	return c.snapshotVulnerabilityDetails(cveID)
}

// Unimplemented methods (read-only backend)
func (c *Config) BatchUpdate(fn func(*bolt.Tx) error) error {
	return oops.Errorf("BatchUpdate not supported in MySQL read-only backend")
}

func (c *Config) PutVulnerabilityDetail(tx *bolt.Tx, vulnerabilityID string, source types.SourceID, vulnerability types.VulnerabilityDetail) error {
	return oops.Errorf("PutVulnerabilityDetail not supported")
}

func (c *Config) DeleteVulnerabilityDetailBucket() error {
	return oops.Errorf("DeleteVulnerabilityDetailBucket not supported")
}

func (c *Config) PutVulnerabilityID(tx *bolt.Tx, vulnerabilityID string) error {
	return oops.Errorf("PutVulnerabilityID not supported")
}

func (c *Config) ForEachVulnerabilityID(fn func(tx *bolt.Tx, cveID string) error) error {
	return oops.Errorf("ForEachVulnerabilityID not supported")
}

func (c *Config) PutVulnerability(tx *bolt.Tx, vulnerabilityID string, vulnerability types.Vulnerability) error {
	return oops.Errorf("PutVulnerability not supported")
}

func (c *Config) SaveAdvisoryDetails(tx *bolt.Tx, cveID string) error {
	return oops.Errorf("SaveAdvisoryDetails not supported")
}

func (c *Config) PutAdvisoryDetail(tx *bolt.Tx, vulnerabilityID, pkgName string, nestedBktNames []string, advisory any) error {
	return oops.Errorf("PutAdvisoryDetail not supported")
}

func (c *Config) DeleteAdvisoryDetailBucket() error {
	return oops.Errorf("DeleteAdvisoryDetailBucket not supported")
}

func (c *Config) PutDataSource(tx *bolt.Tx, bktName string, source types.DataSource) error {
	return oops.Errorf("PutDataSource not supported")
}

func (c *Config) PutRedHatRepositories(tx *bolt.Tx, repository string, cpeIndices []int) error {
	return oops.Errorf("PutRedHatRepositories not supported")
}

func (c *Config) PutRedHatNVRs(tx *bolt.Tx, nvr string, cpeIndices []int) error {
	return oops.Errorf("PutRedHatNVRs not supported")
}

func (c *Config) PutRedHatCPEs(tx *bolt.Tx, cpeIndex int, cpe string) error {
	return oops.Errorf("PutRedHatCPEs not supported")
}

func (c *Config) RedHatRepoToCPEs(repository string) ([]int, error) {
	return c.snapshotCPEs("repository", repository)
}

func (c *Config) RedHatNVRToCPEs(nvr string) ([]int, error) {
	return c.snapshotCPEs("nvr", nvr)
}

func (c *Config) TestConnection() error {
	return c.db.Ping()
}

func (c *Config) GetStats() (map[string]int, error) {
	stats := make(map[string]int)

	var count int
	err := c.db.QueryRow("SELECT COUNT(*) FROM vulnerabilities").Scan(&count)
	if err != nil {
		return nil, err
	}
	stats["vulnerabilities"] = count

	err = c.db.QueryRow("SELECT COUNT(*) FROM vulnerability_advisories").Scan(&count)
	if err != nil {
		return nil, err
	}
	stats["advisories"] = count

	return stats, nil
}
