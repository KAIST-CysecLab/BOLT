package binary

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeDetector struct {
	lookups, comparisons  int
	lookupName            string
	advisories            []dbTypes.Advisory
	lookupErr, compareErr error
}

func (d *fakeDetector) GetAdvisories(name string) ([]dbTypes.Advisory, error) {
	d.lookups++
	d.lookupName = name
	return d.advisories, d.lookupErr
}

func (d *fakeDetector) DetectVulnerabilitiesFromAdvisories(_, _, version string, _ []dbTypes.Advisory) ([]types.DetectedVulnerability, error) {
	d.comparisons++
	if d.compareErr != nil {
		return nil, d.compareErr
	}
	if version == "2.0.0" {
		return nil, nil
	}
	return []types.DetectedVulnerability{{VulnerabilityID: "CVE-test", InstalledVersion: version, FixedVersion: "2.0.0"}}, nil
}

func scannerFor(d *fakeDetector) *Scanner {
	return &Scanner{newDriver: func(ftypes.LangType) (detector, bool) { return d, true }}
}

func scanOptions() types.ScanOptions {
	return types.ScanOptions{Scanners: types.Scanners{types.VulnerabilityScanner}, PkgTypes: []string{types.PkgTypeLibrary}, PkgRelationships: ftypes.Relationships}
}

func testResource(t *testing.T, generator, path string, components ...cdx.Component) ftypes.CustomResource {
	t.Helper()
	var children []string
	for i := range components {
		if components[i].BOMRef == "" {
			components[i].BOMRef = components[i].Name
		}
		children = append(children, components[i].BOMRef)
	}
	bom := cdx.BOM{BOMFormat: "CycloneDX", SpecVersion: cdx.SpecVersion1_5, Version: 1,
		Metadata:   &cdx.Metadata{Component: &cdx.Component{BOMRef: "app", Name: "test-app", Type: cdx.ComponentTypeApplication}},
		Components: &components, Dependencies: &[]cdx.Dependency{{Ref: "app", Dependencies: &children}}}
	raw, err := json.Marshal(bom)
	require.NoError(t, err)
	return ftypes.CustomResource{Type: generator, FilePath: path, Data: raw}
}

func component(name, version, pkgURL string) cdx.Component {
	return cdx.Component{Name: name, Version: version, PackageURL: pkgURL, Type: cdx.ComponentTypeLibrary}
}

func TestScanAssessments(t *testing.T) {
	tests := []struct {
		name, generator, ver, pkgURL, project, wantStatus, wantReason string
		compareError                                                  error
		wantFindings, wantComparisons                                 int
	}{
		{name: "supported explicit PURL", ver: "1.0.0", pkgURL: "pkg:conan/zlib@1.0.0", wantStatus: "scanned", wantReason: "version-range-evaluated", wantFindings: 1, wantComparisons: 1},
		{name: "fixed version", ver: "2.0.0", pkgURL: "pkg:conan/zlib@2.0.0", wantStatus: "scanned", wantReason: "version-range-evaluated", wantComparisons: 1},
		{name: "reference metadata ignores newer reference", generator: ftypes.CustomResourceCycloneDXBinSBOM, ver: "2.0.0", pkgURL: "pkg:generic/zlib@2.0.0", project: "madler@@zlib", wantStatus: "candidate", wantReason: "reference-version-only", wantFindings: 1},
		{name: "legacy generator is also uncertain", generator: ftypes.CustomResourceCycloneDXBinSBOM, ver: "2.0.0", pkgURL: "pkg:conan/zlib@2.0.0", wantStatus: "candidate", wantReason: "reference-version-only", wantFindings: 1},
		{name: "unknown version remains candidate", pkgURL: "pkg:conan/zlib", wantStatus: "candidate", wantReason: "missing-version", wantFindings: 1},
		{name: "version conflict", ver: "1.0.0", pkgURL: "pkg:conan/zlib@2.0.0", wantStatus: "candidate", wantReason: "conflicting-versions", wantFindings: 1},
		{name: "invalid raw tag", ver: "release-2.0.0", pkgURL: "pkg:conan/zlib@release-2.0.0", wantStatus: "candidate", wantReason: "unparseable-version", wantFindings: 1},
		{name: "typed npm invalid version", ver: "master", pkgURL: "pkg:npm/zlib@master", compareError: errors.New("invalid npm version"), wantStatus: "candidate", wantReason: "version-comparison-failed", wantFindings: 1, wantComparisons: 1},
		{name: "invalid advisory constraint", ver: "1.0.0", pkgURL: "pkg:conan/zlib@1.0.0", compareError: errors.New("invalid constraint"), wantStatus: "candidate", wantReason: "version-comparison-failed", wantFindings: 1, wantComparisons: 1},
		{name: "source mapping is a candidate not a conan install", ver: "1.0.0", pkgURL: "pkg:generic/zlib@1.0.0", project: "madler@@zlib", wantStatus: "candidate", wantReason: "upstream-advisory-mapping", wantFindings: 1, wantComparisons: 1},
		{name: "bare name never guesses a project", ver: "1.0.0", pkgURL: "pkg:generic/zlib@1.0.0", wantStatus: "not-scanned", wantReason: "unmapped-project-identity"},
		{name: "commit SHA is not a release version", ver: "100f4ff91b5a5b31a84b3999365c3058df6251ea", pkgURL: "pkg:github/madler/zlib@100f4ff91b5a5b31a84b3999365c3058df6251ea", wantStatus: "candidate", wantReason: "commit-version-not-resolved", wantFindings: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			generator := tt.generator
			if generator == "" {
				generator = ftypes.CustomResourceCycloneDXBomBlint
			}
			c := component("zlib", tt.ver, tt.pkgURL)
			if tt.project != "" {
				setProperty(&c, PropertyComponentID, tt.project)
			}
			d := &fakeDetector{advisories: []dbTypes.Advisory{{VulnerabilityID: "CVE-test"}}, compareErr: tt.compareError}
			resource := testResource(t, generator, "/app/server", c)
			before := string(resource.Data.([]byte))
			results, updated, err := scannerFor(d).Scan(context.Background(), []ftypes.CustomResource{resource}, scanOptions())
			require.NoError(t, err)
			require.Len(t, results, 1)
			require.Len(t, results[0].Packages, 1)
			assert.Len(t, results[0].Vulnerabilities, tt.wantFindings)
			assert.Equal(t, tt.wantComparisons, d.comparisons)
			assert.Equal(t, tt.pkgURL, results[0].Packages[0].Identifier.PURL.String())
			assert.Equal(t, before, string(resource.Data.([]byte)), "cached analyzer input must remain immutable")
			bom, err := decodeFragment(updated[0].Data)
			require.NoError(t, err)
			require.Len(t, *bom.Components, 1)
			assert.Equal(t, []string{tt.wantStatus}, propertyValues((*bom.Components)[0], PropertyScanStatus))
			assert.Equal(t, []string{tt.wantReason}, propertyValues((*bom.Components)[0], PropertyScanReason))
			if tt.wantStatus == "candidate" {
				finding := results[0].Vulnerabilities[0]
				assert.Empty(t, finding.InstalledVersion)
				assert.Empty(t, finding.FixedVersion)
				assert.Equal(t, dbTypes.StatusUnderInvestigation, finding.Status)
				assert.Equal(t, "candidate", finding.Custom.(map[string]any)[PropertyAssessment])
			}
		})
	}
}

func TestScanPreservesUnsupportedAndDisabledInventory(t *testing.T) {
	d := &fakeDetector{}
	resource := testResource(t, ftypes.CustomResourceCycloneDXBomBlint, "/app/server", component("libc.so.6", "", "pkg:file/libc.so.6"))
	results, updated, err := scannerFor(d).Scan(context.Background(), []ftypes.CustomResource{resource}, scanOptions())
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Len(t, results[0].Packages, 1)
	assert.Empty(t, results[0].Vulnerabilities)
	assert.Zero(t, d.lookups)
	bom, err := decodeFragment(updated[0].Data)
	require.NoError(t, err)
	assert.Equal(t, []string{"unsupported-package-type"}, propertyValues((*bom.Components)[0], PropertyScanReason))
	for _, opts := range []types.ScanOptions{
		{Scanners: types.Scanners{types.SBOMScanner}, PkgTypes: []string{types.PkgTypeLibrary}},
		{Scanners: types.Scanners{types.VulnerabilityScanner}, PkgTypes: []string{types.PkgTypeOS}},
	} {
		resource = testResource(t, ftypes.CustomResourceCycloneDXBomBlint, "/app/server", component("zlib", "1.0.0", "pkg:conan/zlib@1.0.0"))
		results, updated, err = scannerFor(d).Scan(context.Background(), []ftypes.CustomResource{resource}, opts)
		require.NoError(t, err)
		assert.Empty(t, results)
		assert.Zero(t, d.lookups)
		bom, err = decodeFragment(updated[0].Data)
		require.NoError(t, err)
		assert.Equal(t, []string{"not-requested"}, propertyValues((*bom.Components)[0], PropertyScanReason))
	}
}

func TestScanRespectsPackageRelationships(t *testing.T) {
	for _, relationships := range [][]ftypes.Relationship{nil, {ftypes.RelationshipIndirect}} {
		d := &fakeDetector{advisories: []dbTypes.Advisory{{VulnerabilityID: "CVE-test"}}}
		resource := testResource(t, ftypes.CustomResourceCycloneDXBomBlint, "/app/server", component("zlib", "1.0.0", "pkg:conan/zlib@1.0.0"))
		opts := scanOptions()
		opts.PkgRelationships = relationships
		results, updated, err := scannerFor(d).Scan(context.Background(), []ftypes.CustomResource{resource}, opts)
		require.NoError(t, err)
		assert.Empty(t, results)
		assert.Zero(t, d.lookups)
		bom, err := decodeFragment(updated[0].Data)
		require.NoError(t, err)
		require.Len(t, *bom.Components, 1, "original inventory must remain available")
		assert.Equal(t, []string{"not-scanned"}, propertyValues((*bom.Components)[0], PropertyScanStatus))
		assert.Equal(t, []string{"relationship-excluded"}, propertyValues((*bom.Components)[0], PropertyScanReason))
	}
}

func TestScanScopesReferencesAndCachesAcrossBinaries(t *testing.T) {
	c := component("zlib", "1.0.0", "pkg:conan/zlib@1.0.0")
	d := &fakeDetector{advisories: []dbTypes.Advisory{{VulnerabilityID: "CVE-test"}}}
	resources := []ftypes.CustomResource{
		testResource(t, ftypes.CustomResourceCycloneDXBomBlint, "/app/a", c),
		testResource(t, ftypes.CustomResourceCycloneDXBinSBOM, "/app/b", c),
		testResource(t, ftypes.CustomResourceCycloneDXBomBlint, "/app/c", c),
	}
	results, updated, err := scannerFor(d).Scan(context.Background(), resources, scanOptions())
	require.NoError(t, err)
	require.Len(t, results, 3)
	assert.Equal(t, 2, d.lookups, "one lookup per distinct version-evidence assessment")
	assert.Equal(t, 1, d.comparisons)
	refs := map[string]bool{}
	for _, result := range results {
		ref := result.Packages[0].Identifier.BOMRef
		assert.False(t, refs[ref], "same PURL in different binaries needs distinct occurrence refs")
		refs[ref] = true
		assert.Equal(t, ref, result.Vulnerabilities[0].PkgIdentifier.BOMRef)
	}
	_, twice, err := scannerFor(d).Scan(context.Background(), updated, scanOptions())
	require.NoError(t, err)
	for i := range updated {
		onceBOM, err := decodeFragment(updated[i].Data)
		require.NoError(t, err)
		twiceBOM, err := decodeFragment(twice[i].Data)
		require.NoError(t, err)
		assert.Equal(t, onceBOM.Metadata.Component.BOMRef, twiceBOM.Metadata.Component.BOMRef)
		assert.Equal(t, (*onceBOM.Components)[0].BOMRef, (*twiceBOM.Components)[0].BOMRef)
		assert.Equal(t, onceBOM.Dependencies, twiceBOM.Dependencies)
	}
}

func TestScanParseErrorDoesNotLeakToNextComponent(t *testing.T) {
	mapped := component("zlib", "1.0.0", "")
	setProperty(&mapped, PropertyComponentID, "madler@@zlib")
	d := &fakeDetector{advisories: []dbTypes.Advisory{{VulnerabilityID: "CVE-test"}}}
	resource := testResource(t, ftypes.CustomResourceCycloneDXBomBlint, "/app/test", component("bad", "1", "invalid"), mapped)
	results, updated, err := scannerFor(d).Scan(context.Background(), []ftypes.CustomResource{resource}, scanOptions())
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Len(t, results[0].Vulnerabilities, 1)
	bom, err := decodeFragment(updated[0].Data)
	require.NoError(t, err)
	assert.Equal(t, []string{"invalid-package-url"}, propertyValues((*bom.Components)[0], PropertyScanReason))
	assert.Equal(t, []string{"candidate"}, propertyValues((*bom.Components)[1], PropertyScanStatus))
}

func TestScanNestedComponentsAndDistinctRepositories(t *testing.T) {
	a := component("zlib", "1.0.0", "pkg:generic/zlib@1.0.0")
	a.ExternalReferences = &[]cdx.ExternalReference{{Type: cdx.ERTypeVCS, URL: "https://github.com/madler/zlib.git"}}
	b := a
	b.ExternalReferences = &[]cdx.ExternalReference{{Type: cdx.ERTypeVCS, URL: "https://github.com/unrelated/zlib"}}
	a.Components = &[]cdx.Component{b}
	d := &fakeDetector{advisories: []dbTypes.Advisory{{VulnerabilityID: "CVE-test"}}}
	resource := testResource(t, ftypes.CustomResourceCycloneDXBomBlint, "/app/test", a)
	results, updated, err := scannerFor(d).Scan(context.Background(), []ftypes.CustomResource{resource}, scanOptions())
	require.NoError(t, err)
	require.Len(t, results[0].Packages, 2)
	assert.NotEqual(t, results[0].Packages[0].ID, results[0].Packages[1].ID)
	bom, err := decodeFragment(updated[0].Data)
	require.NoError(t, err)
	require.Len(t, *bom.Components, 2)
	assert.Nil(t, (*bom.Components)[0].Components)
	assert.Len(t, *bom.Dependencies, 2)
	assert.Len(t, results[0].Vulnerabilities, 1)
}

func TestScanErrorsAndMissingCoverage(t *testing.T) {
	resource := testResource(t, ftypes.CustomResourceCycloneDXBomBlint, "/app/test", component("zlib", "1.0.0", "pkg:conan/zlib@1.0.0"))
	d := &fakeDetector{lookupErr: errors.New("database unavailable")}
	_, _, err := scannerFor(d).Scan(context.Background(), []ftypes.CustomResource{resource}, scanOptions())
	require.ErrorContains(t, err, "database unavailable")
	d.lookupErr = nil
	results, updated, err := scannerFor(d).Scan(context.Background(), []ftypes.CustomResource{resource}, scanOptions())
	require.NoError(t, err)
	assert.Empty(t, results[0].Vulnerabilities)
	bom, err := decodeFragment(updated[0].Data)
	require.NoError(t, err)
	assert.Equal(t, []string{"no-advisories"}, propertyValues((*bom.Components)[0], PropertyScanStatus))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err = scannerFor(d).Scan(ctx, []ftypes.CustomResource{resource}, scanOptions())
	require.ErrorIs(t, err, context.Canceled)
}

func TestDecodeFragmentPreservesCommentTextAndBase64(t *testing.T) {
	raw := []byte(`/* progress */ {"components":[{"type":"library","name":"literal /* keep */ text"}]}`)
	for _, data := range []any{raw, base64.StdEncoding.EncodeToString(raw)} {
		bom, err := decodeFragment(data)
		require.NoError(t, err)
		assert.Equal(t, "literal /* keep */ text", (*bom.Components)[0].Name)
	}
}

func TestLookupIdentityRequiresProjectEvidence(t *testing.T) {
	p, err := purl.FromString("pkg:generic/zlib@1.2.11")
	require.NoError(t, err)
	c := component("zlib", "1.2.11", p.String())
	_, reason := lookupIdentity(c, p)
	assert.Equal(t, "unmapped-project-identity", reason)
	c.ExternalReferences = &[]cdx.ExternalReference{{Type: cdx.ERTypeVCS, URL: "https://github.com.evil/madler/zlib"}}
	_, reason = lookupIdentity(c, p)
	assert.Equal(t, "unmapped-project-identity", reason)
	setProperty(&c, PropertyComponentID, "madler@@zlib")
	id, reason := lookupIdentity(c, p)
	assert.Empty(t, reason)
	assert.Equal(t, "zlib", id.name)
	*c.Properties = append(*c.Properties, cdx.Property{Name: PropertyComponentID, Value: "fork@@zlib"})
	_, reason = lookupIdentity(c, p)
	assert.Equal(t, "ambiguous-project-identity", reason)
}
