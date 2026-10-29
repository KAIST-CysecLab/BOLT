package result_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/result"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestFilterResultPreservesDistinctBinaryComponentFindings(t *testing.T) {
	for _, tc := range []struct {
		name     string
		kind     ftypes.TargetType
		wantRefs []string
	}{
		{name: "binary component identities survive", kind: "binary", wantRefs: []string{"urn:bolt:binary:first", "urn:bolt:binary:second"}},
		{name: "ordinary package deduplication remains unchanged", kind: ftypes.Npm, wantRefs: []string{"urn:bolt:binary:first"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first := types.DetectedVulnerability{
				VulnerabilityID: "CVE-2099-0001",
				PkgName:         "zlib",
				PkgPath:         "/usr/bin/demo",
				Status:          dbTypes.StatusUnderInvestigation,
				PkgIdentifier:   ftypes.PkgIdentifier{BOMRef: "urn:bolt:binary:first"},
				Vulnerability:   dbTypes.Vulnerability{Severity: dbTypes.SeverityHigh.String()},
			}
			second := first
			second.PkgIdentifier.BOMRef = "urn:bolt:binary:second"
			scan := types.Result{
				Target: first.PkgPath, Class: types.ClassLangPkg, Type: tc.kind,
				Vulnerabilities: []types.DetectedVulnerability{first, second, first},
			}
			err := result.FilterResult(context.Background(), &scan, result.IgnoreConfig{}, result.FilterOptions{
				Severities: []dbTypes.Severity{dbTypes.SeverityHigh},
			})
			require.NoError(t, err)
			var refs []string
			for _, finding := range scan.Vulnerabilities {
				refs = append(refs, finding.PkgIdentifier.BOMRef)
				assert.Equal(t, first.VulnerabilityID, finding.VulnerabilityID)
				assert.Equal(t, dbTypes.StatusUnderInvestigation, finding.Status)
				assert.Empty(t, finding.InstalledVersion)
			}
			assert.ElementsMatch(t, tc.wantRefs, refs, "same-ref duplicates must collapse without merging different binary components")
		})
	}
}
