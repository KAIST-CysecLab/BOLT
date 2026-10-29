package compare_test

import (
	"testing"

	dbtypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/bitnami"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/maven"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/npm"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/pep440"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/rubygems"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckedComparers(t *testing.T) {
	comparers := map[string]compare.CheckedComparer{
		"generic": compare.GenericComparer{}, "bitnami": bitnami.Comparer{},
		"maven": maven.Comparer{}, "npm": npm.Comparer{},
		"pep440": pep440.Comparer{}, "rubygems": rubygems.Comparer{},
	}
	tests := []struct {
		name     string
		version  string
		advisory dbtypes.Advisory
		want     bool
		wantErr  bool
	}{
		{
			name: "affected", version: "1.2.3",
			advisory: dbtypes.Advisory{VulnerableVersions: []string{"<1.3.0"}, PatchedVersions: []string{">=1.3.0"}}, want: true,
		},
		{
			name: "outside affected range", version: "1.3.0",
			advisory: dbtypes.Advisory{VulnerableVersions: []string{"<1.3.0"}},
		},
		{
			name: "patched exclusion", version: "1.2.3",
			advisory: dbtypes.Advisory{VulnerableVersions: []string{"<2.0.0"}, PatchedVersions: []string{">=1.2.0"}},
		},
		{
			name: "unaffected exclusion", version: "1.2.3",
			advisory: dbtypes.Advisory{VulnerableVersions: []string{"<2.0.0"}, UnaffectedVersions: []string{">=1.2.0"}},
		},
		{
			name: "empty installed version", version: "",
			advisory: dbtypes.Advisory{VulnerableVersions: []string{"<1.3.0"}}, wantErr: true,
		},
		{name: "missing ranges", version: "1.2.3", wantErr: true},
		{
			name: "empty patched constraint", version: "1.2.3",
			advisory: dbtypes.Advisory{VulnerableVersions: []string{"<2.0.0"}, PatchedVersions: []string{""}}, wantErr: true,
		},
		{
			name: "invalid vulnerable constraint", version: "1.2.3",
			advisory: dbtypes.Advisory{VulnerableVersions: []string{`<1.0\.0`}}, wantErr: true,
		},
		{
			name: "invalid constraint after matching alternative", version: "1.2.3",
			advisory: dbtypes.Advisory{VulnerableVersions: []string{"<2.0.0", `<1.0\.0`}}, wantErr: true,
		},
		{
			name: "invalid patched constraint after negative vulnerable match", version: "1.2.3",
			advisory: dbtypes.Advisory{VulnerableVersions: []string{"<1.0.0"}, PatchedVersions: []string{`<1.0\.0`}}, wantErr: true,
		},
		{
			name: "invalid unaffected constraint after patched match", version: "1.2.3",
			advisory: dbtypes.Advisory{PatchedVersions: []string{">=1.0.0"}, UnaffectedVersions: []string{`<1.0\.0`}}, wantErr: true,
		},
	}
	for name, comparer := range comparers {
		t.Run(name, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					got, err := comparer.IsVulnerableChecked(tt.version, tt.advisory)
					if tt.wantErr {
						require.Error(t, err)
						assert.False(t, got)
					} else {
						require.NoError(t, err)
						assert.Equal(t, tt.want, got)
						assert.Equal(t, comparer.IsVulnerable(tt.version, tt.advisory), got)
					}
				})
			}
			// Maven intentionally accepts arbitrary version qualifiers. Preserve its
			// ecosystem ordering instead of imposing semver validation on it.
			if name != "maven" {
				_, err := comparer.IsVulnerableChecked("1.2..4", dbtypes.Advisory{VulnerableVersions: []string{"<2.0.0"}})
				require.Error(t, err)
			}
		})
	}
}
