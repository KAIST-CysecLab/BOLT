// Modified by slyfizz on 2025-11-28: passed the MySQL DSN into server database initialization
// Modified by slyfizz on 2026-04-09: skipped BoltDB downloads when MySQL is configured
// Modified by slyfizz on 2026-10-06: updated the MySQL database from the official Trivy DB at server startup

package server

import (
	"context"
	"os"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/commands/operation"
	"github.com/aquasecurity/trivy/pkg/db"
	dbupdate "github.com/aquasecurity/trivy/pkg/db/update"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/module"
	rpcServer "github.com/aquasecurity/trivy/pkg/rpc/server"
)

// Run runs the scan
func Run(ctx context.Context, opts flag.Options) (err error) {
	log.InitLogger(opts.Debug, opts.Quiet)

	// configure cache dir
	cacheClient, cleanup, err := cache.New(opts.CacheOpts())
	if err != nil {
		return xerrors.Errorf("server cache error: %w", err)
	}
	defer cleanup()

	mySQLDSN := opts.MySQLDSN
	if mySQLDSN == "" {
		mySQLDSN = os.Getenv("TRIVY_MYSQL_DSN")
	}

	if mySQLDSN != "" {
		if !opts.SkipDBUpdate {
			updateCtx := ctx
			cancel := func() {}
			if opts.Timeout > 0 {
				updateCtx, cancel = context.WithTimeout(ctx, opts.Timeout)
			}
			_, updateErr := dbupdate.Run(updateCtx, dbupdate.Options{
				CacheDir: opts.CacheDir, Repositories: opts.DBRepositories,
				Registry: opts.RegistryOpts(), MySQLDSN: mySQLDSN, Quiet: opts.Quiet || opts.NoProgress,
			})
			cancel()
			if updateErr != nil {
				return xerrors.Errorf("official vulnerability DB update failed: %w", updateErr)
			}
		}
		if opts.DownloadDBOnly {
			return nil
		}
		if err = db.Init(db.Dir(opts.CacheDir), mySQLDSN); err != nil {
			return xerrors.Errorf("error in vulnerability DB initialize: %w", err)
		}
	} else {
		// download the database file
		if err = operation.DownloadDB(ctx, opts.AppVersion, opts.CacheDir, opts.DBRepositories,
			true, opts.SkipDBUpdate, opts.RegistryOpts()); err != nil {
			return err
		}

		if opts.DownloadDBOnly {
			return nil
		}

		if err = db.Init(db.Dir(opts.CacheDir), mySQLDSN); err != nil {
			return xerrors.Errorf("error in vulnerability DB initialize: %w", err)
		}
	}

	// Initialize WASM modules
	m, err := module.NewManager(ctx, module.Options{
		Dir:            opts.ModuleDir,
		EnabledModules: opts.EnabledModules,
	})
	if err != nil {
		return xerrors.Errorf("WASM module error: %w", err)
	}
	m.Register()

	server := rpcServer.NewServer(opts.AppVersion, opts.Listen, opts.CacheDir, opts.Token, opts.TokenHeader,
		opts.PathPrefix, opts.DBRepositories, opts.RegistryOpts())
	// The background worker replaces a local BoltDB. MySQL refreshes at startup;
	// it must never enter that worker's close-and-reopen BoltDB lifecycle.
	return server.ListenAndServe(ctx, cacheClient, opts.SkipDBUpdate || mySQLDSN != "")
}
