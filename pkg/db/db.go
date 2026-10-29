// Modified by slyfizz on 2025-11-14: added MySQL database initialization and fallback
// Modified by slyfizz on 2025-11-27: skipped database updates when MySQL is active
// Modified by slyfizz on 2025-11-28: accepted an explicit MySQL DSN
// Modified by slyfizz on 2026-04-09: avoided BoltDB initialization when MySQL connects
// Modified by slyfizz on 2026-10-06: failed instead of falling back to BoltDB when a configured MySQL backend cannot be initialized

package db

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/metadata"
	"github.com/aquasecurity/trivy/pkg/clock"
	"github.com/aquasecurity/trivy/pkg/db/mysql"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/oci"
)

const (
	SchemaVersion = db.SchemaVersion
	dbMediaType   = "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip"
)

var (
	// GitHub Container Registry
	DefaultGHCRRepository = fmt.Sprintf("%s:%d", "ghcr.io/aquasecurity/trivy-db", db.SchemaVersion)
	defaultGHCRRepository = lo.Must(name.NewTag(DefaultGHCRRepository))

	// GCR mirror
	DefaultGCRRepository = fmt.Sprintf("%s:%d", "mirror.gcr.io/aquasec/trivy-db", db.SchemaVersion)
	defaultGCRRepository = lo.Must(name.NewTag(DefaultGCRRepository))

	// MySQL global state
	mysqlClient     *mysql.Config
	boltInitialized bool

	Init  = initDBs  // initialize both BoltDB and MySQL
	Close = closeDBs // close both
	Path  = db.Path  // keep the BoltDB path
)

// Initialize both BoltDB and MySQL (MySQL takes precedence)
func initDBs(dir string, mysqlDSN string) error {
	// The flag takes precedence; fall back to the environment variable
	dsn := mysqlDSN
	if dsn == "" {
		dsn = os.Getenv("TRIVY_MYSQL_DSN")
	}
	if dsn != "" {
		log.Info("Attempting MySQL initialization...", log.String("dsn", maskPassword(dsn)))
		client, err := mysql.New(dsn)
		if err == nil {
			mysqlClient = client
			log.Info("MySQL backend initialized successfully")
			log.Info("BoltDB not needed when using MySQL")
			return nil
		}
		return xerrors.Errorf("failed to initialize the explicitly configured MySQL backend: %w", err)

	} else {
		log.Debug("TRIVY_MYSQL_DSN not set, using BoltDB")
	}

	log.Info("Initializing BoltDB...")
	if err := db.Init(dir); err != nil {
		return xerrors.Errorf("failed to init BoltDB: %w", err)
	}
	boltInitialized = true
	log.Info("BoltDB initialized successfully")
	return nil
}

// Close both
func closeDBs() error {
	var errs []error

	if boltInitialized {
		if err := db.Close(); err != nil {
			errs = append(errs, fmt.Errorf("BoltDB close error: %w", err))
		}
	}

	if mysqlClient != nil {
		if err := mysqlClient.Close(); err != nil {
			errs = append(errs, fmt.Errorf("MySQL close error: %w", err))
		}
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// Mask the password in a DSN
func maskPassword(dsn string) string {
	for i := 0; i < len(dsn); i++ {
		if dsn[i] == ':' {
			for j := i + 1; j < len(dsn); j++ {
				if dsn[j] == '@' {
					return dsn[:i+1] + "***" + dsn[j:]
				}
			}
		}
	}
	return dsn
}

// GetMySQLClient returns the MySQL client if initialized
func GetMySQLClient() *mysql.Config {
	return mysqlClient
}

// IsMySQLEnabled returns true if MySQL backend is available
func IsMySQLEnabled() bool {
	return mysqlClient != nil
}

type options struct {
	artifact       *oci.Artifact
	dbRepositories []name.Reference
}

// Option is a functional option
type Option func(*options)

// WithOCIArtifact takes an OCI artifact
func WithOCIArtifact(art *oci.Artifact) Option {
	return func(opts *options) {
		opts.artifact = art
	}
}

// WithDBRepository takes a dbRepository
func WithDBRepository(dbRepository []name.Reference) Option {
	return func(opts *options) {
		opts.dbRepositories = dbRepository
	}
}

// Client implements DB operations
type Client struct {
	*options

	dbDir    string
	metadata metadata.Client
	quiet    bool
}

func Dir(cacheDir string) string {
	return filepath.Join(cacheDir, "db")
}

// NewClient is the factory method for DB client
func NewClient(dbDir string, quiet bool, opts ...Option) *Client {
	o := &options{
		dbRepositories: []name.Reference{
			defaultGCRRepository,
			defaultGHCRRepository,
		},
	}

	for _, opt := range opts {
		opt(o)
	}

	return &Client{
		options:  o,
		dbDir:    dbDir,
		metadata: metadata.NewClient(dbDir),
		quiet:    quiet,
	}
}

// NeedsUpdate check is DB needs update
func (c *Client) NeedsUpdate(ctx context.Context, cliVersion string, skip bool) (bool, error) {
	// With the MySQL backend in use, no DB download or update is needed
	if mysqlClient != nil {
		log.DebugContext(ctx, "Using MySQL backend, DB download/update not needed")
		return false, nil
	}

	// BoltDB logic (original code)
	meta, err := c.metadata.Get()
	if err != nil {
		log.DebugContext(ctx, "There is no valid metadata file", log.Err(err))
		if skip {
			log.ErrorContext(ctx, "The first run cannot skip downloading DB")
			return false, xerrors.New("--skip-update cannot be specified on the first run")
		}
		meta = metadata.Metadata{Version: db.SchemaVersion}
	}

	if db.SchemaVersion < meta.Version {
		log.ErrorContext(ctx, "Trivy version is old. Update to the latest version.", log.String("version", cliVersion))
		return false, xerrors.Errorf("the version of DB schema doesn't match. Local DB: %d, Expected: %d",
			meta.Version, db.SchemaVersion)
	}

	if skip {
		log.DebugContext(ctx, "Skipping DB update...")
		if err = c.validate(meta); err != nil {
			return false, xerrors.Errorf("validate error: %w", err)
		}
		return false, nil
	}

	if db.SchemaVersion != meta.Version {
		log.DebugContext(ctx, "The local DB schema version does not match with supported version schema.",
			log.Int("local_version", meta.Version), log.Int("supported_version", db.SchemaVersion))
		return true, nil
	}

	return !c.isNewDB(ctx, meta), nil
}

func (c *Client) validate(meta metadata.Metadata) error {
	if db.SchemaVersion != meta.Version {
		log.Error("The local DB has an old schema version which is not supported by the current version of Trivy CLI. DB needs to be updated.")
		return xerrors.Errorf("--skip-update cannot be specified with the old DB schema. Local DB: %d, Expected: %d",
			meta.Version, db.SchemaVersion)
	}
	return nil
}

func (c *Client) isNewDB(ctx context.Context, meta metadata.Metadata) bool {
	now := clock.Now(ctx)
	if now.Before(meta.NextUpdate) {
		log.Debug("DB update was skipped because the local DB is the latest")
		return true
	}

	if now.Before(meta.DownloadedAt.Add(time.Hour)) {
		log.Debug("DB update was skipped because the local DB was downloaded during the last hour")
		return true
	}
	return false
}

// Download downloads the DB file
func (c *Client) Download(ctx context.Context, dst string, opt types.RegistryOptions) error {
	// Remove the metadata file under the cache directory before downloading DB
	if err := c.metadata.Delete(); err != nil {
		log.DebugContext(ctx, "No metadata file")
	}

	if err := c.downloadDB(ctx, opt, dst); err != nil {
		return xerrors.Errorf("OCI artifact error: %w", err)
	}

	if err := c.updateDownloadedAt(ctx, dst); err != nil {
		return xerrors.Errorf("failed to update downloaded_at: %w", err)
	}
	return nil
}

func (c *Client) Clear(_ context.Context) error {
	if err := os.RemoveAll(c.dbDir); err != nil {
		return xerrors.Errorf("failed to remove vulnerability database: %w", err)
	}
	return nil
}

func (c *Client) updateDownloadedAt(ctx context.Context, dbDir string) error {
	log.Debug("Updating database metadata...")

	// We have to initialize a metadata client here
	// since the destination may be different from the cache directory.
	client := metadata.NewClient(dbDir)
	meta, err := client.Get()
	if err != nil {
		return xerrors.Errorf("unable to get metadata: %w", err)
	}

	meta.DownloadedAt = clock.Now(ctx).UTC()
	if err = client.Update(meta); err != nil {
		return xerrors.Errorf("failed to update metadata: %w", err)
	}

	return nil
}

func (c *Client) initArtifacts(opt types.RegistryOptions) oci.Artifacts {
	if c.artifact != nil {
		return oci.Artifacts{c.artifact}
	}
	return oci.NewArtifacts(c.dbRepositories, opt)
}

func (c *Client) downloadDB(ctx context.Context, opt types.RegistryOptions, dst string) error {
	log.InfoContext(ctx, "Downloading vulnerability DB...")
	downloadOpt := oci.DownloadOption{
		MediaType: dbMediaType,
		Quiet:     c.quiet,
	}
	if err := c.initArtifacts(opt).Download(ctx, dst, downloadOpt); err != nil {
		return xerrors.Errorf("failed to download vulnerability DB: %w", err)
	}
	return nil
}

func (c *Client) ShowInfo() error {
	// Print MySQL information if MySQL is initialized
	if mysqlClient != nil {
		log.Info("Using MySQL backend")
		if err := mysqlClient.TestConnection(); err != nil {
			return xerrors.Errorf("MySQL connection test failed: %w", err)
		}

		stats, err := mysqlClient.GetStats()
		if err != nil {
			return xerrors.Errorf("failed to get MySQL stats: %w", err)
		}
		log.Info("MySQL DB stats",
			log.Int("vulnerabilities", stats["vulnerabilities"]),
			log.Int("advisories", stats["advisories"]))
		return nil
	}

	// Print BoltDB information if BoltDB is initialized
	if boltInitialized {
		meta, err := c.metadata.Get()
		if err != nil {
			return xerrors.Errorf("something wrong with DB: %w", err)
		}
		log.Debug("BoltDB info", log.Int("schema", meta.Version), log.Time("updated_at", meta.UpdatedAt),
			log.Time("next_update", meta.NextUpdate), log.Time("downloaded_at", meta.DownloadedAt))
		return nil
	}

	// Not initialized yet: log it instead of returning an error
	log.Debug("Database not yet initialized (will be initialized later)")
	return nil // not an error
}
