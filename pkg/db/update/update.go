// Package update downloads immutable official DB snapshots and publishes them to
// the MySQL backend. A failed refresh never falls back to an older local DB.
package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	trivydb "github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/metadata"
	"github.com/google/go-containerregistry/pkg/name"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy/pkg/db/mysql"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/oci"
)

const mediaType = "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip"

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type Options struct {
	CacheDir     string
	Repositories []name.Reference
	Registry     types.RegistryOptions
	MySQLDSN     string
	Quiet        bool
}

type artifact interface {
	Digest(context.Context) (string, error)
	Download(context.Context, string, oci.DownloadOption) error
}

type updater struct {
	artifact func(string, types.RegistryOptions) artifact
	sync     func(context.Context, string, mysql.Snapshot) (mysql.SyncResult, error)
}

// Run checks the remote manifest on every invocation. The immutable DB layer and
// MySQL import are reused when the digest has not changed, independently of the
// upstream metadata's (potentially longer) NextUpdate interval.
func Run(ctx context.Context, opts Options) (mysql.SyncResult, error) {
	u := updater{
		artifact: func(repo string, registry types.RegistryOptions) artifact {
			return oci.NewArtifact(repo, registry)
		},
		sync: mysql.Sync,
	}
	return u.run(ctx, opts)
}

func (u updater) run(ctx context.Context, opts Options) (mysql.SyncResult, error) {
	if opts.MySQLDSN == "" {
		return mysql.SyncResult{}, fmt.Errorf("MySQL DSN is required for a MySQL refresh")
	}
	root := filepath.Join(opts.CacheDir, "db-updates")
	if err := os.MkdirAll(root, 0755); err != nil {
		return mysql.SyncResult{}, err
	}
	// bbolt supplies a cross-platform process lock, including release after an
	// interrupted updater. This lock DB contains no vulnerability data.
	lock, err := acquireLock(ctx, filepath.Join(root, "update.lock"))
	if err != nil {
		return mysql.SyncResult{}, err
	}
	defer lock.Close()
	snapshot, err := u.download(ctx, root, opts)
	if err != nil {
		return mysql.SyncResult{}, err
	}
	result, err := u.sync(ctx, opts.MySQLDSN, snapshot)
	if err != nil {
		return mysql.SyncResult{}, fmt.Errorf("refresh MySQL from official Trivy DB: %w", err)
	}
	// This local pointer is informational. The atomic MySQL metadata table is
	// authoritative; failure to write a cache pointer must not imply DB rollback.
	if err := writeJSON(filepath.Join(root, "current.json"), snapshot); err != nil {
		log.WarnContext(ctx, "Could not save DB cache pointer", log.Err(err))
	}
	log.InfoContext(ctx, "Official Trivy DB ready", log.String("digest", snapshot.Digest),
		log.Time("updated_at", snapshot.Metadata.UpdatedAt), log.Bool("changed", result.Changed))
	return result, nil
}

func acquireLock(ctx context.Context, path string) (*bolt.DB, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 100 * time.Millisecond})
		if !errors.Is(err, bolt.ErrTimeout) {
			return db, err
		}
	}
}

func (u updater) download(ctx context.Context, root string, opts Options) (mysql.Snapshot, error) {
	repositories := opts.Repositories
	if len(repositories) == 0 {
		repositories = []name.Reference{name.MustParseReference("ghcr.io/aquasecurity/trivy-db:2")}
	}
	var failures []error
	for _, repo := range repositories {
		if err := ctx.Err(); err != nil {
			return mysql.Snapshot{}, err
		}
		snapshot, err := u.downloadRepository(ctx, root, repo.String(), opts)
		if err == nil {
			return snapshot, nil
		}
		// A fallback is another explicitly configured upstream repository, never
		// an unverified cached snapshot after an upstream error.
		failures = append(failures, fmt.Errorf("%s: %w", repo.String(), err))
		log.WarnContext(ctx, "Official DB repository unavailable", log.String("repository", repo.String()), log.Err(err))
	}
	return mysql.Snapshot{}, fmt.Errorf("cannot refresh official Trivy DB: %w", errors.Join(failures...))
}

func (u updater) downloadRepository(ctx context.Context, root, repo string, opts Options) (mysql.Snapshot, error) {
	art := u.artifact(repo, opts.Registry)
	digest, err := art.Digest(ctx)
	if err != nil {
		return mysql.Snapshot{}, err
	}
	if !digestPattern.MatchString(digest) {
		return mysql.Snapshot{}, fmt.Errorf("unsupported manifest digest %q", digest)
	}
	dir := filepath.Join(root, digest[len("sha256:"):])
	if snapshot, err := readSnapshot(ctx, dir); err == nil && snapshot.Digest == digest {
		snapshot.Repository = repo
		log.InfoContext(ctx, "Reusing downloaded official DB", log.String("digest", digest))
		return snapshot, nil
	}
	stage, err := os.MkdirTemp(root, ".download-")
	if err != nil {
		return mysql.Snapshot{}, err
	}
	defer os.RemoveAll(stage)
	log.InfoContext(ctx, "Downloading official Trivy DB", log.String("repository", repo), log.String("digest", digest))
	// art holds the resolved image from Digest, so a moving tag cannot change
	// the downloaded layer between version checking and the actual download.
	if err := art.Download(ctx, stage, oci.DownloadOption{MediaType: mediaType, Filename: "db.tar.gz", Quiet: opts.Quiet}); err != nil {
		return mysql.Snapshot{}, err
	}
	meta, err := validateSnapshot(stage)
	if err != nil {
		return mysql.Snapshot{}, err
	}
	meta.DownloadedAt = time.Now().UTC()
	if err := metadata.NewClient(stage).Update(meta); err != nil {
		return mysql.Snapshot{}, err
	}
	snapshot := mysql.Snapshot{Repository: repo, Digest: digest, Metadata: meta, DBPath: filepath.Join(dir, "trivy.db")}
	snapshot.DBSHA256, snapshot.DBSize, err = hashDatabase(ctx, filepath.Join(stage, "trivy.db"))
	if err != nil {
		return mysql.Snapshot{}, err
	}
	if err := writeJSON(filepath.Join(stage, "snapshot.json"), snapshot); err != nil {
		return mysql.Snapshot{}, err
	}
	// Only this updater's invalid digest cache is replaced. Live MySQL tables
	// are untouched until the later importer completes all validation.
	if err := os.RemoveAll(dir); err != nil {
		return mysql.Snapshot{}, err
	}
	if err := os.Rename(stage, dir); err != nil {
		return mysql.Snapshot{}, err
	}
	return snapshot, nil
}

func readSnapshot(ctx context.Context, dir string) (mysql.Snapshot, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "snapshot.json"))
	if err != nil {
		return mysql.Snapshot{}, err
	}
	var snapshot mysql.Snapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return mysql.Snapshot{}, err
	}
	meta, err := validateSnapshot(dir)
	if err != nil {
		return mysql.Snapshot{}, err
	}
	if meta.Version != snapshot.Metadata.Version || !meta.UpdatedAt.Equal(snapshot.Metadata.UpdatedAt) {
		return mysql.Snapshot{}, fmt.Errorf("cached snapshot metadata does not match its manifest record")
	}
	snapshot.DBPath = filepath.Join(dir, "trivy.db")
	hash, size, err := hashDatabase(ctx, snapshot.DBPath)
	if err != nil {
		return mysql.Snapshot{}, err
	}
	if hash != snapshot.DBSHA256 || size != snapshot.DBSize {
		return mysql.Snapshot{}, fmt.Errorf("cached database content does not match its verified download")
	}
	return snapshot, nil
}

func hashDatabase(ctx context.Context, path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	hash := sha256.New()
	buffer := make([]byte, 1024*1024)
	var size int64
	for {
		if err := ctx.Err(); err != nil {
			return "", 0, err
		}
		n, err := f.Read(buffer)
		if n > 0 {
			_, _ = hash.Write(buffer[:n])
			size += int64(n)
		}
		if errors.Is(err, io.EOF) {
			return hex.EncodeToString(hash.Sum(nil)), size, nil
		}
		if err != nil {
			return "", 0, err
		}
	}
}

func validateSnapshot(dir string) (metadata.Metadata, error) {
	meta, err := metadata.NewClient(dir).Get()
	if err != nil {
		return meta, err
	}
	if meta.Version != trivydb.SchemaVersion || meta.UpdatedAt.IsZero() {
		return meta, fmt.Errorf("unsupported or invalid Trivy DB metadata (schema %d, expected %d)", meta.Version, trivydb.SchemaVersion)
	}
	db, err := bolt.Open(filepath.Join(dir, "trivy.db"), 0400, &bolt.Options{ReadOnly: true, Timeout: time.Second})
	if err != nil {
		return meta, fmt.Errorf("open downloaded Trivy DB: %w", err)
	}
	defer db.Close()
	err = db.View(func(tx *bolt.Tx) error {
		for _, name := range []string{"vulnerability", "data-source"} {
			bucket := tx.Bucket([]byte(name))
			if bucket == nil {
				return fmt.Errorf("downloaded Trivy DB is missing %s", name)
			}
			key, _ := bucket.Cursor().First()
			if key == nil {
				return fmt.Errorf("downloaded Trivy DB has empty %s", name)
			}
		}
		return nil
	})
	return meta, err
}

func writeJSON(path string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".metadata-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(append(raw, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
