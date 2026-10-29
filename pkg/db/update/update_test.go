package update

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aquasecurity/trivy-db/pkg/metadata"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy/pkg/db/mysql"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/oci"
)

type fakeArtifact struct {
	digest                 string
	digestErr, downloadErr error
	resolutions, downloads int
	schema                 int
}

func (a *fakeArtifact) Digest(context.Context) (string, error) {
	a.resolutions++
	return a.digest, a.digestErr
}

func (a *fakeArtifact) Download(_ context.Context, dir string, opts oci.DownloadOption) error {
	a.downloads++
	if a.downloadErr != nil {
		return a.downloadErr
	}
	db, err := bolt.Open(filepath.Join(dir, "trivy.db"), 0600, nil)
	if err != nil {
		return err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range []string{"vulnerability", "data-source"} {
			bucket, err := tx.CreateBucket([]byte(name))
			if err != nil {
				return err
			}
			if err := bucket.Put([]byte("example"), []byte(`{}`)); err != nil {
				return err
			}
		}
		return nil
	})
	if closeErr := db.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return metadata.NewClient(dir).Update(metadata.Metadata{Version: a.schema, UpdatedAt: time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)})
}

func testUpdater(a *fakeArtifact, syncFn func(context.Context, string, mysql.Snapshot) (mysql.SyncResult, error)) updater {
	return updater{artifact: func(string, types.RegistryOptions) artifact { return a }, sync: syncFn}
}

func TestRemoteDigestCheckedAndUnchangedLayerReused(t *testing.T) {
	a := &fakeArtifact{digest: "sha256:" + strings.Repeat("a", 64), schema: 2}
	var imported []mysql.Snapshot
	u := testUpdater(a, func(_ context.Context, _ string, snapshot mysql.Snapshot) (mysql.SyncResult, error) {
		imported = append(imported, snapshot)
		return mysql.SyncResult{}, nil
	})
	opts := Options{CacheDir: t.TempDir(), MySQLDSN: "test"}
	for i := 0; i < 2; i++ {
		_, err := u.run(context.Background(), opts)
		require.NoError(t, err)
	}
	require.Equal(t, 2, a.resolutions, "check upstream even when NextUpdate would skip the built-in updater")
	require.Equal(t, 1, a.downloads)
	require.Len(t, imported, 2)
	require.Equal(t, imported[0].DBPath, imported[1].DBPath)
	require.FileExists(t, imported[0].DBPath)
	require.Equal(t, a.digest, imported[0].Digest)

	// A cached snapshot must not hide an upstream failure.
	a.digestErr = errors.New("registry unavailable")
	_, err := u.run(context.Background(), opts)
	require.ErrorContains(t, err, "registry unavailable")
	require.Len(t, imported, 2)
}

func TestFailuresDoNotAdvancePublishedSnapshot(t *testing.T) {
	a := &fakeArtifact{digest: "sha256:" + strings.Repeat("a", 64), schema: 2}
	var importErr error
	var imports int
	u := testUpdater(a, func(context.Context, string, mysql.Snapshot) (mysql.SyncResult, error) {
		imports++
		return mysql.SyncResult{}, importErr
	})
	opts := Options{CacheDir: t.TempDir(), MySQLDSN: "test"}
	_, err := u.run(context.Background(), opts)
	require.NoError(t, err)
	pointer := filepath.Join(opts.CacheDir, "db-updates", "current.json")
	before, err := os.ReadFile(pointer)
	require.NoError(t, err)
	for _, stage := range []string{"network", "schema", "import"} {
		t.Run(stage, func(t *testing.T) {
			a.digest = "sha256:" + strings.Repeat("b", 64)
			a.downloadErr, a.schema, importErr = nil, 2, nil
			switch stage {
			case "network":
				a.downloadErr = errors.New("interrupted transfer")
			case "schema":
				a.schema = 3
			case "import":
				importErr = errors.New("insert failed")
			}
			_, err := u.run(context.Background(), opts)
			require.Error(t, err)
			after, err := os.ReadFile(pointer)
			require.NoError(t, err)
			require.Equal(t, before, after)
			leftovers, err := filepath.Glob(filepath.Join(opts.CacheDir, "db-updates", ".download-*"))
			require.NoError(t, err)
			require.Empty(t, leftovers)
		})
	}
	require.Equal(t, 2, imports, "invalid or incomplete downloads must never reach MySQL")
	// Retry the failed import using the completely downloaded, validated DB.
	importErr = nil
	downloads := a.downloads
	_, err = u.run(context.Background(), opts)
	require.NoError(t, err)
	require.Equal(t, downloads, a.downloads)
	raw, err := os.ReadFile(pointer)
	require.NoError(t, err)
	var published mysql.Snapshot
	require.NoError(t, json.Unmarshal(raw, &published))
	require.Equal(t, a.digest, published.Digest)
}

func TestConfiguredRepositoryFallback(t *testing.T) {
	first := &fakeArtifact{digestErr: errors.New("registry rate limited")}
	second := &fakeArtifact{digest: "sha256:" + strings.Repeat("c", 64), schema: 2}
	var got mysql.Snapshot
	u := updater{
		artifact: func(repo string, _ types.RegistryOptions) artifact {
			if strings.HasPrefix(repo, "ghcr.io/") {
				return first
			}
			return second
		},
		sync: func(_ context.Context, _ string, snapshot mysql.Snapshot) (mysql.SyncResult, error) {
			got = snapshot
			return mysql.SyncResult{}, nil
		},
	}
	_, err := u.run(context.Background(), Options{CacheDir: t.TempDir(), MySQLDSN: "test", Repositories: []name.Reference{
		name.MustParseReference("ghcr.io/aquasecurity/trivy-db:2"), name.MustParseReference("mirror.gcr.io/aquasec/trivy-db:2"),
	}})
	require.NoError(t, err)
	require.Equal(t, "mirror.gcr.io/aquasec/trivy-db:2", got.Repository)
	require.Equal(t, second.digest, got.Digest)
}

func TestModifiedCachedDatabaseIsDownloadedAgain(t *testing.T) {
	a := &fakeArtifact{digest: "sha256:" + strings.Repeat("d", 64), schema: 2}
	var snapshot mysql.Snapshot
	u := testUpdater(a, func(_ context.Context, _ string, s mysql.Snapshot) (mysql.SyncResult, error) {
		snapshot = s
		return mysql.SyncResult{}, nil
	})
	opts := Options{CacheDir: t.TempDir(), MySQLDSN: "test"}
	_, err := u.run(context.Background(), opts)
	require.NoError(t, err)
	require.Len(t, snapshot.DBSHA256, 64)
	require.Positive(t, snapshot.DBSize)
	// Keep the file readable and structurally valid while changing its content.
	db, err := bolt.Open(snapshot.DBPath, 0600, nil)
	require.NoError(t, err)
	require.NoError(t, db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("vulnerability")).Put([]byte("example"), []byte(`{"modified":true}`))
	}))
	require.NoError(t, db.Close())
	_, err = u.run(context.Background(), opts)
	require.NoError(t, err)
	require.Equal(t, 2, a.downloads)
}

func TestInvalidDigestAndCancellation(t *testing.T) {
	a := &fakeArtifact{digest: "sha256:../../outside", schema: 2}
	u := testUpdater(a, func(context.Context, string, mysql.Snapshot) (mysql.SyncResult, error) {
		t.Fatal("must not import")
		return mysql.SyncResult{}, nil
	})
	_, err := u.run(context.Background(), Options{CacheDir: t.TempDir(), MySQLDSN: "test"})
	require.ErrorContains(t, err, "unsupported manifest digest")
	require.Zero(t, a.downloads)

	path := filepath.Join(t.TempDir(), "lock")
	lock, err := acquireLock(context.Background(), path)
	require.NoError(t, err)
	defer lock.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = acquireLock(ctx, path)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}
