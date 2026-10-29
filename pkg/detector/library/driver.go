// Modified by slyfizz on 2025-11-28: added MySQL-backed library vulnerability detection
// Modified by slyfizz on 2026-09-23: separated advisory lookup from version matching and treated comparison failures as unknown

package library

import (
	"fmt"
	"strings"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	trivydb "github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/bitnami"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/maven"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/npm"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/pep440"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/rubygems"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

// NewDriver returns a driver according to the library type
func NewDriver(libType ftypes.LangType) (Driver, bool) {
	var ecosystem dbTypes.Ecosystem
	var comparer compare.Comparer

	switch libType {
	case ftypes.Bundler, ftypes.GemSpec:
		ecosystem = vulnerability.RubyGems
		comparer = rubygems.Comparer{}
	case ftypes.RustBinary, ftypes.Cargo:
		ecosystem = vulnerability.Cargo
		comparer = compare.GenericComparer{}
	case ftypes.Composer, ftypes.ComposerVendor:
		ecosystem = vulnerability.Composer
		comparer = compare.GenericComparer{}
	case ftypes.GoBinary, ftypes.GoModule:
		ecosystem = vulnerability.Go
		comparer = compare.GenericComparer{}
	case ftypes.Jar, ftypes.Pom, ftypes.Gradle, ftypes.Sbt:
		ecosystem = vulnerability.Maven
		comparer = maven.Comparer{}
	case ftypes.Npm, ftypes.Yarn, ftypes.Pnpm, ftypes.NodePkg, ftypes.JavaScript:
		ecosystem = vulnerability.Npm
		comparer = npm.Comparer{}
	case ftypes.NuGet, ftypes.DotNetCore, ftypes.PackagesProps:
		ecosystem = vulnerability.NuGet
		comparer = compare.GenericComparer{}
	case ftypes.Pipenv, ftypes.Poetry, ftypes.Pip, ftypes.PythonPkg, ftypes.Uv:
		ecosystem = vulnerability.Pip
		comparer = pep440.Comparer{}
	case ftypes.Pub:
		ecosystem = vulnerability.Pub
		comparer = compare.GenericComparer{}
	case ftypes.Hex:
		ecosystem = vulnerability.Erlang
		comparer = compare.GenericComparer{}
	case ftypes.Conan:
		ecosystem = vulnerability.Conan
		// Only semver can be used for version ranges
		// https://docs.conan.io/en/latest/versioning/version_ranges.html
		comparer = compare.GenericComparer{}
	case ftypes.Swift:
		// Swift uses semver
		// https://www.swift.org/package-manager/#importing-dependencies
		ecosystem = vulnerability.Swift
		comparer = compare.GenericComparer{}
	case ftypes.Cocoapods:
		// CocoaPods uses RubyGems version specifiers
		// https://guides.cocoapods.org/making/making-a-cocoapod.html#cocoapods-versioning-specifics
		ecosystem = vulnerability.Cocoapods
		comparer = rubygems.Comparer{}
	case ftypes.CondaPkg, ftypes.CondaEnv:
		log.Warn("Conda package is supported for SBOM, not for vulnerability scanning")
		return Driver{}, false
	case ftypes.Bitnami:
		ecosystem = vulnerability.Bitnami
		comparer = bitnami.Comparer{}
	case ftypes.K8sUpstream:
		ecosystem = vulnerability.Kubernetes
		comparer = compare.GenericComparer{}
	case ftypes.Julia:
		log.Warn("Julia is supported for SBOM, not for vulnerability scanning")
		return Driver{}, false
	default:
		log.Warn("The library type is not supported for vulnerability scanning",
			log.String("type", string(libType)))
		return Driver{}, false
	}

	// Use the MySQL backend if available, otherwise BoltDB
	var dbc db.Operation // an interface, so either MySQL or BoltDB can back it
	if mysqlClient := trivydb.GetMySQLClient(); mysqlClient != nil {
		dbc = mysqlClient
		log.Debug("Library detector using MySQL backend", log.String("ecosystem", string(ecosystem)))
	} else {
		dbc = db.Config{}
		log.Debug("Library detector using BoltDB backend", log.String("ecosystem", string(ecosystem)))
	}

	return Driver{
		ecosystem: ecosystem,
		comparer:  comparer,
		dbc:       dbc,
	}, true
}

// Driver represents security advisories for each programming language
type Driver struct {
	ecosystem dbTypes.Ecosystem
	comparer  compare.Comparer
	dbc       db.Operation // an interface, so either MySQL or BoltDB can back it
}

// Type returns the driver ecosystem
func (d *Driver) Type() string {
	return string(d.ecosystem)
}

// GetAdvisories retrieves candidate advisories without making a version decision.
// If "ecosystem" is pip, it looks for buckets with "pip::" and gets security advisories from those buckets.
// It allows us to add a new data source with the ecosystem prefix (e.g. pip::new-data-source)
// and detect vulnerabilities without specifying a specific bucket name.
func (d *Driver) GetAdvisories(pkgName string) ([]dbTypes.Advisory, error) {
	// e.g. "pip::", "npm::"
	prefix := fmt.Sprintf("%s::", d.ecosystem)
	advisories, err := d.dbc.GetAdvisories(prefix, vulnerability.NormalizePkgName(d.ecosystem, pkgName))
	if err != nil {
		return nil, xerrors.Errorf("failed to get %s advisories: %w", d.ecosystem, err)
	}
	return advisories, nil
}

// DetectVulnerabilities checks the package version against its candidate advisories.
func (d *Driver) DetectVulnerabilities(pkgID, pkgName, pkgVer string) ([]types.DetectedVulnerability, error) {
	advisories, err := d.GetAdvisories(pkgName)
	if err != nil {
		return nil, err
	}

	var vulns []types.DetectedVulnerability
	for _, adv := range advisories {
		if !d.comparer.IsVulnerable(pkgVer, adv) {
			continue
		}

		vuln := types.DetectedVulnerability{
			VulnerabilityID:  adv.VulnerabilityID,
			PkgID:            pkgID,
			PkgName:          pkgName,
			InstalledVersion: pkgVer,
			FixedVersion:     createFixedVersions(adv),
			DataSource:       adv.DataSource,
			Custom:           adv.Custom,
		}
		vulns = append(vulns, vuln)
	}

	return vulns, nil
}

// DetectVulnerabilitiesFromAdvisories evaluates previously retrieved advisories
// without another database lookup. Comparison failures invalidate the whole result
// so callers can retain the advisories as candidates instead of reporting clean.
func (d *Driver) DetectVulnerabilitiesFromAdvisories(pkgID, pkgName, pkgVer string, advisories []dbTypes.Advisory) ([]types.DetectedVulnerability, error) {
	checked, ok := d.comparer.(compare.CheckedComparer)
	if !ok {
		return nil, xerrors.Errorf("%s does not support checked version comparison", d.ecosystem)
	}
	if strings.TrimSpace(pkgVer) == "" {
		return nil, xerrors.New("installed version is empty")
	}
	var vulns []types.DetectedVulnerability
	for _, advisory := range advisories {
		matched, err := checked.IsVulnerableChecked(pkgVer, advisory)
		if err != nil {
			return nil, xerrors.Errorf("cannot evaluate %s for %s@%s: %w", advisory.VulnerabilityID, pkgName, pkgVer, err)
		}
		if !matched {
			continue
		}
		vulns = append(vulns, types.DetectedVulnerability{
			VulnerabilityID:  advisory.VulnerabilityID,
			PkgID:            pkgID,
			PkgName:          pkgName,
			InstalledVersion: pkgVer,
			FixedVersion:     createFixedVersions(advisory),
			DataSource:       advisory.DataSource,
			Custom:           advisory.Custom,
		})
	}
	return vulns, nil
}

func createFixedVersions(advisory dbTypes.Advisory) string {
	if len(advisory.PatchedVersions) != 0 {
		return joinFixedVersions(advisory.PatchedVersions)
	}

	var fixedVersions []string
	for _, version := range advisory.VulnerableVersions {
		for _, s := range strings.Split(version, ",") {
			s = strings.TrimSpace(s)
			if !strings.HasPrefix(s, "<=") && strings.HasPrefix(s, "<") {
				s = strings.TrimPrefix(s, "<")
				fixedVersions = append(fixedVersions, strings.TrimSpace(s))
			}
		}
	}
	return joinFixedVersions(fixedVersions)
}

func joinFixedVersions(fixedVersions []string) string {
	return strings.Join(lo.Uniq(fixedVersions), ", ")
}
