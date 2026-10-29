package library

import (
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbtypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type forbiddenAdvisoryLookup struct{ db.Operation }

func (forbiddenAdvisoryLookup) GetAdvisories(string, string) ([]dbtypes.Advisory, error) {
	panic("checked detection must reuse the supplied advisories")
}

func TestDetectVulnerabilitiesFromAdvisories(t *testing.T) {
	driver := Driver{ecosystem: vulnerability.Go, comparer: compare.GenericComparer{}, dbc: forbiddenAdvisoryLookup{}}
	advisory := dbtypes.Advisory{
		VulnerabilityID: "CVE-TEST-1", VulnerableVersions: []string{"<1.3.0"},
		DataSource: &dbtypes.DataSource{ID: vulnerability.OSV}, Custom: map[string]string{"origin": "test"},
	}
	vulns, err := driver.DetectVulnerabilitiesFromAdvisories("pkg-id", "example", "1.2.3", []dbtypes.Advisory{advisory})
	require.NoError(t, err)
	require.Len(t, vulns, 1)
	assert.Equal(t, "CVE-TEST-1", vulns[0].VulnerabilityID)
	assert.Equal(t, "pkg-id", vulns[0].PkgID)
	assert.Equal(t, "example", vulns[0].PkgName)
	assert.Equal(t, "1.2.3", vulns[0].InstalledVersion)
	assert.Equal(t, "1.3.0", vulns[0].FixedVersion)
	assert.Equal(t, advisory.DataSource, vulns[0].DataSource)
	assert.Equal(t, advisory.Custom, vulns[0].Custom)

	vulns, err = driver.DetectVulnerabilitiesFromAdvisories("pkg-id", "example", "1.3.0", []dbtypes.Advisory{advisory})
	require.NoError(t, err)
	assert.Empty(t, vulns)

	vulns, err = driver.DetectVulnerabilitiesFromAdvisories("pkg-id", "example", "1.2..4", []dbtypes.Advisory{advisory})
	require.Error(t, err)
	assert.Nil(t, vulns)

	for _, bad := range []dbtypes.Advisory{
		{VulnerabilityID: "CVE-TEST-BAD"},
		{VulnerabilityID: "CVE-TEST-BAD", VulnerableVersions: []string{"<1.0.0"}, PatchedVersions: []string{`<1.0\.0`}},
	} {
		vulns, err = driver.DetectVulnerabilitiesFromAdvisories("pkg-id", "example", "1.2.3", []dbtypes.Advisory{advisory, bad})
		require.ErrorContains(t, err, "CVE-TEST-BAD")
		assert.Nil(t, vulns, "a later comparison failure must discard partial findings")
	}
}
