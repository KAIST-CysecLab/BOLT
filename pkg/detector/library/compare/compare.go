// Modified by slyfizz on 2026-09-23: added CheckedComparer and IsVulnerableChecked to distinguish comparison failures from negative matches

package compare

import (
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-version/pkg/version"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

// Comparer is an interface for version comparison
type Comparer interface {
	IsVulnerable(currentVersion string, advisory dbTypes.Advisory) bool
}

// CheckedComparer distinguishes a negative match from a version-comparison failure.
// Comparer remains unchanged for existing callers and external implementations.
type CheckedComparer interface {
	Comparer
	IsVulnerableChecked(currentVersion string, advisory dbTypes.Advisory) (bool, error)
}

type matchVersion func(currentVersion, constraint string) (bool, error)

// IsVulnerableChecked evaluates every constraint before making a decision. Unlike
// the legacy API, missing ranges and parser errors are unknown, not clean results.
func IsVulnerableChecked(pkgVer string, advisory dbTypes.Advisory, match matchVersion) (bool, error) {
	if strings.TrimSpace(pkgVer) == "" {
		return false, xerrors.New("installed version is empty")
	}
	groups := [][]string{advisory.VulnerableVersions, advisory.PatchedVersions, advisory.UnaffectedVersions}
	matched := [3]bool{}
	count := 0
	for group, constraints := range groups {
		for _, constraint := range constraints {
			if strings.TrimSpace(constraint) == "" {
				return false, xerrors.New("advisory contains an empty version constraint")
			}
			ok, err := match(pkgVer, constraint)
			if err != nil {
				return false, xerrors.Errorf("cannot compare installed version %q with constraint %q: %w", pkgVer, constraint, err)
			}
			matched[group] = matched[group] || ok
			count++
		}
	}
	if count == 0 {
		return false, xerrors.New("advisory has no version constraints")
	}
	if len(advisory.VulnerableVersions) != 0 && !matched[0] {
		return false, nil
	}
	if len(advisory.PatchedVersions)+len(advisory.UnaffectedVersions) == 0 {
		return matched[0], nil
	}
	return !matched[1] && !matched[2], nil
}

// IsVulnerable checks if the package version is vulnerable to the advisory.
func IsVulnerable(pkgVer string, advisory dbTypes.Advisory, match matchVersion) bool {
	// If one of vulnerable/patched versions is empty, we should detect it anyway.
	for _, v := range append(advisory.VulnerableVersions, advisory.PatchedVersions...) {
		if v == "" {
			return true
		}
	}
	var matched bool
	var err error

	if len(advisory.VulnerableVersions) != 0 {
		matched, err = match(pkgVer, strings.Join(advisory.VulnerableVersions, " || "))
		if err != nil {
			log.Warn("Version matching error", log.Err(err))
			return false
		} else if !matched {
			// the version is not vulnerable
			return false
		}
	}

	secureVersions := append(advisory.PatchedVersions, advisory.UnaffectedVersions...)
	if len(secureVersions) == 0 {
		// the version matches vulnerable versions and patched/unaffected versions are not provided
		// or all values are empty
		return matched
	}

	matched, err = match(pkgVer, strings.Join(secureVersions, " || "))
	if err != nil {
		log.Warn("Version matching error", log.Err(err))
		return false
	}
	return !matched
}

// GenericComparer represents a comparer for semver-like versioning
type GenericComparer struct{}

// IsVulnerable checks if the package version is vulnerable to the advisory.
func (v GenericComparer) IsVulnerable(ver string, advisory dbTypes.Advisory) bool {
	return IsVulnerable(ver, advisory, v.matchVersion)
}

func (v GenericComparer) IsVulnerableChecked(ver string, advisory dbTypes.Advisory) (bool, error) {
	return IsVulnerableChecked(ver, advisory, v.matchVersion)
}

// matchVersion checks if the package version satisfies the given constraint.
func (v GenericComparer) matchVersion(currentVersion, constraint string) (bool, error) {
	ver, err := version.Parse(currentVersion)
	if err != nil {
		return false, xerrors.Errorf("version error (%s): %s", currentVersion, err)
	}

	c, err := version.NewConstraints(constraint)
	if err != nil {
		return false, xerrors.Errorf("constraint error (%s): %s", currentVersion, err)
	}

	return c.Check(ver), nil
}
