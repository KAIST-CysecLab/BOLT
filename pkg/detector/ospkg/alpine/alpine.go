// Modified by slyfizz on 2025-11-14: added MySQL-backed Alpine advisory detection
// Modified by slyfizz on 2025-11-27: retained local database fallback for Alpine
// Modified by slyfizz on 2025-12-05: added MySQL backend support

package alpine


import (
	"context"
	"strings"
	"time"

	version "github.com/knqyf263/go-apk-version"
	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/alpine"
	"github.com/aquasecurity/trivy/pkg/db"
	osver "github.com/aquasecurity/trivy/pkg/detector/ospkg/version"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	eolDates = map[string]time.Time{
		"2.0":  time.Date(2012, 4, 1, 23, 59, 59, 0, time.UTC),
		"2.1":  time.Date(2012, 11, 1, 23, 59, 59, 0, time.UTC),
		"2.2":  time.Date(2013, 5, 1, 23, 59, 59, 0, time.UTC),
		"2.3":  time.Date(2013, 11, 1, 23, 59, 59, 0, time.UTC),
		"2.4":  time.Date(2014, 5, 1, 23, 59, 59, 0, time.UTC),
		"2.5":  time.Date(2014, 11, 1, 23, 59, 59, 0, time.UTC),
		"2.6":  time.Date(2015, 5, 1, 23, 59, 59, 0, time.UTC),
		"2.7":  time.Date(2015, 11, 1, 23, 59, 59, 0, time.UTC),
		"3.0":  time.Date(2016, 5, 1, 23, 59, 59, 0, time.UTC),
		"3.1":  time.Date(2016, 11, 1, 23, 59, 59, 0, time.UTC),
		"3.2":  time.Date(2017, 5, 1, 23, 59, 59, 0, time.UTC),
		"3.3":  time.Date(2017, 11, 1, 23, 59, 59, 0, time.UTC),
		"3.4":  time.Date(2018, 5, 1, 23, 59, 59, 0, time.UTC),
		"3.5":  time.Date(2018, 11, 1, 23, 59, 59, 0, time.UTC),
		"3.6":  time.Date(2019, 5, 1, 23, 59, 59, 0, time.UTC),
		"3.7":  time.Date(2019, 11, 1, 23, 59, 59, 0, time.UTC),
		"3.8":  time.Date(2020, 5, 1, 23, 59, 59, 0, time.UTC),
		"3.9":  time.Date(2020, 11, 1, 23, 59, 59, 0, time.UTC),
		"3.10": time.Date(2021, 5, 1, 23, 59, 59, 0, time.UTC),
		"3.11": time.Date(2021, 11, 1, 23, 59, 59, 0, time.UTC),
		"3.12": time.Date(2022, 5, 1, 23, 59, 59, 0, time.UTC),
		"3.13": time.Date(2022, 11, 1, 23, 59, 59, 0, time.UTC),
		"3.14": time.Date(2023, 5, 1, 23, 59, 59, 0, time.UTC),
		"3.15": time.Date(2023, 11, 1, 23, 59, 59, 0, time.UTC),
		"3.16": time.Date(2024, 5, 23, 23, 59, 59, 0, time.UTC),
		"3.17": time.Date(2024, 11, 22, 23, 59, 59, 0, time.UTC),
		"3.18": time.Date(2025, 5, 9, 23, 59, 59, 0, time.UTC),
		"3.19": time.Date(2025, 11, 1, 23, 59, 59, 0, time.UTC),
		"3.20": time.Date(2026, 04, 1, 23, 59, 59, 0, time.UTC),
		"3.21": time.Date(2026, 12, 5, 23, 59, 59, 0, time.UTC),
		"edge": time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC),
	}
)

// Scanner implements the Alpine scanner
type Scanner struct {
	vs alpine.VulnSrc
}

// NewScanner is the factory method for Scanner
func NewScanner() *Scanner {
	// The DB may not be initialized yet when the Scanner is created,
	// so whether MySQL is used is checked at scan time (Detect)
	return &Scanner{
		vs: alpine.NewVulnSrc(),
	}
}

// Detect vulnerabilities in package using Alpine scanner
func (s *Scanner) Detect(ctx context.Context, osVer string, repo *ftypes.Repository, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	osVer = osver.Minor(osVer)
	repoRelease := s.repoRelease(repo)

	// Check for the MySQL backend and log it
	if db.GetMySQLClient() != nil {
		log.InfoContext(ctx, "Using MySQL backend for vulnerability detection")
	} else {
		log.DebugContext(ctx, "Using BoltDB backend for vulnerability detection")
	}

	log.InfoContext(ctx, "Detecting vulnerabilities...", log.String("os_version", osVer),
		log.String("repository", repoRelease), log.Int("pkg_num", len(pkgs)))

	stream := osVer
	if repoRelease != "" && osVer != repoRelease {
		// Prefer the repository release. Use OS version only when the repository is not detected.
		stream = repoRelease
		if repoRelease != "edge" { // TODO: we should detect the current edge version.
			log.WarnContext(ctx, "Mixing Alpine versions is unsupported",
				log.String("os", osVer), log.String("repository", repoRelease))
		}
	}

	var vulns []types.DetectedVulnerability
	for _, pkg := range pkgs {
		srcName := pkg.SrcName
		if srcName == "" {
			srcName = pkg.Name
		}
		
		// Try MySQL
		advisories, err := s.getAdvisories(stream, srcName)
		if err != nil {
			return nil, xerrors.Errorf("failed to get alpine advisories: %w", err)
		}

		sourceVersion, err := version.NewVersion(utils.FormatSrcVersion(pkg))
		if err != nil {
			log.DebugContext(ctx, "Failed to parse the installed package version", log.Err(err))
			continue
		}

		for _, adv := range advisories {
			// Continue processing as before...
			vuln := types.DetectedVulnerability{
				VulnerabilityID:  adv.VulnerabilityID,
				PkgID:            pkg.ID,
				PkgName:          pkg.Name,
				InstalledVersion: utils.FormatVersion(pkg),
				PkgIdentifier:    pkg.Identifier,
				Layer:            pkg.Layer,
				Custom:           adv.Custom,
				DataSource:       adv.DataSource,
			}

			if adv.FixedVersion != "" {
				fixedVersion, err := version.NewVersion(adv.FixedVersion)
				if err != nil {
					log.DebugContext(ctx, "Failed to parse the fixed version", log.Err(err))
					continue
				}

				if sourceVersion.LessThan(fixedVersion) {
					vuln.FixedVersion = adv.FixedVersion
					vulns = append(vulns, vuln)
				}
			} else {
				vulns = append(vulns, vuln)
			}
		}
	}

	return vulns, nil
}


func (s *Scanner) repoRelease(repo *ftypes.Repository) string {
	// repo.Release could be "v3.15", "v3.16", or ""
	if repo == nil {
		return ""
	}

	release := repo.Release
	if release == "" {
		return ""
	}

	return strings.TrimPrefix(release, "v")
}

func (s *Scanner) IsSupportedVersion(ctx context.Context, osFamily ftypes.OSType, osVer string) bool {
	return osver.Supported(ctx, eolDates, osFamily, osver.Minor(osVer))
}

// getAdvisories gets advisories from MySQL or BoltDB
func (s *Scanner) getAdvisories(release, pkgName string) ([]dbTypes.Advisory, error) {
	// Try MySQL first
	if mysqlClient := db.GetMySQLClient(); mysqlClient != nil {
		source := "alpine " + release  // "alpine 3.22"
		log.Debug("Querying MySQL for advisories", log.String("source", source), log.String("package", pkgName))
		advisories, err := mysqlClient.GetAdvisories(source, pkgName)
		if err != nil {
			log.Warn("MySQL query failed, falling back to BoltDB", log.Err(err))
		} else {
			log.Debug("MySQL query successful", log.Int("count", len(advisories)))
			return advisories, nil
		}
	}
	
	// Fallback: BoltDB
	log.Debug("Using BoltDB for advisories")
	return s.vs.Get(release, pkgName)
}