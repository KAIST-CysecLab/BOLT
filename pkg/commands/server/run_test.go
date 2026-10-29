package server

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/flag"
)

func TestRunMySQLRefreshFailureStopsBeforeInitialization(t *testing.T) {
	originalInit := db.Init
	t.Cleanup(func() { db.Init = originalInit })
	initializations := 0
	db.Init = func(string, string) error {
		initializations++
		return errors.New("unexpected initialization")
	}
	for _, downloadOnly := range []bool{false, true} {
		name := "startup"
		if downloadOnly {
			name = "download-only"
		}
		t.Run(name, func(t *testing.T) {
			// Exercise the environment DSN path used in deployment without ever
			// opening a real connection or contacting a registry.
			t.Setenv("TRIVY_MYSQL_DSN", "test-dsn")
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			err := Run(ctx, flag.Options{
				GlobalOptions: flag.GlobalOptions{CacheDir: t.TempDir()},
				CacheOptions:  flag.CacheOptions{CacheBackend: "memory"},
				DBOptions:     flag.DBOptions{DownloadDBOnly: downloadOnly},
			})
			require.ErrorIs(t, err, context.Canceled)
			require.ErrorContains(t, err, "official vulnerability DB update failed")
			require.Zero(t, initializations)
		})
	}
}

func TestRunMySQLSkipUpdateUsesExistingDatabase(t *testing.T) {
	originalInit := db.Init
	t.Cleanup(func() { db.Init = originalInit })
	t.Setenv("TRIVY_MYSQL_DSN", "environment-dsn")
	stop := errors.New("stop after initialization")
	var initializedDSN string
	db.Init = func(_ string, dsn string) error {
		initializedDSN = dsn
		return stop
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cacheDir := t.TempDir()
	err := Run(ctx, flag.Options{
		GlobalOptions: flag.GlobalOptions{CacheDir: cacheDir},
		CacheOptions:  flag.CacheOptions{CacheBackend: "memory"},
		DBOptions:     flag.DBOptions{SkipDBUpdate: true, MySQLDSN: "explicit-dsn"},
	})
	require.ErrorIs(t, err, stop)
	require.Equal(t, "explicit-dsn", initializedDSN)
	require.NoDirExists(t, cacheDir+"/db-updates", "skip must bypass the updater entirely")
}
