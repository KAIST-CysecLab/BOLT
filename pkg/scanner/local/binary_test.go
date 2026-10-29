package local

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/internal/dbtest"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	cdxreport "github.com/aquasecurity/trivy/pkg/report/cyclonedx"
	"github.com/aquasecurity/trivy/pkg/result"
	binaryscanner "github.com/aquasecurity/trivy/pkg/scanner/binary"
	"github.com/aquasecurity/trivy/pkg/scanner/langpkg"
	"github.com/aquasecurity/trivy/pkg/scanner/ospkg"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
)

func initBinaryIntegrationDB(t *testing.T) {
	t.Helper()
	dbtest.InitDB(t, []string{"testdata/fixtures/binary.yaml"})
	t.Cleanup(func() { require.NoError(t, dbtest.Close()) })
}

func binaryIntegrationResource(t *testing.T, source, path string, components ...cdx.Component) ftypes.CustomResource {
	t.Helper()
	refs := make([]string, 0, len(components))
	for _, component := range components {
		refs = append(refs, component.BOMRef)
	}
	raw, err := json.Marshal(map[string]any{
		"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
		"metadata":     cdx.Metadata{Component: &cdx.Component{Type: cdx.ComponentTypeApplication, Name: "demo", BOMRef: "app:demo"}},
		"components":   components,
		"dependencies": []cdx.Dependency{{Ref: "app:demo", Dependencies: &refs}},
		// A fragment's own findings must never bypass the normal scan/filter path.
		"vulnerabilities": []cdx.Vulnerability{{ID: "CVE-RAW-SENTINEL"}},
	})
	require.NoError(t, err)
	return ftypes.CustomResource{Type: source, FilePath: path, Data: raw}
}

func binaryIntegrationZlib(version, purlType string, reference bool) cdx.Component {
	component := cdx.Component{Type: cdx.ComponentTypeLibrary, Name: "zlib", Version: version,
		BOMRef: "lib:zlib", PackageURL: "pkg:" + purlType + "/zlib@" + version}
	if reference {
		component.Properties = &[]cdx.Property{
			{Name: binaryscanner.PropertyComponentID, Value: "madler@@zlib"},
			{Name: binaryscanner.PropertyVersionSource, Value: "reference-metadata"},
		}
	}
	return component
}

func scanBinaryIntegration(t *testing.T, resources []ftypes.CustomResource, scanners types.Scanners) types.Results {
	t.Helper()
	// Snapshot the actual input bytes, rather than sharing the original byte slice
	// with an expected value, so in-place annotation would fail this assertion.
	originals := make([][]byte, len(resources))
	for i, resource := range resources {
		originals[i] = bytes.Clone(resource.Data.([]byte))
	}
	scanner := NewScanner(nil, ospkg.NewScanner(), langpkg.NewScanner(), vulnerability.NewClient(db.Config{}))
	results, _, err := scanner.ScanTarget(context.Background(), types.ScanTarget{
		Name: "binary-fixture", CustomResources: resources,
	}, types.ScanOptions{
		PkgTypes: []string{types.PkgTypeLibrary}, PkgRelationships: ftypes.Relationships, Scanners: scanners,
	})
	require.NoError(t, err)
	for i, resource := range resources {
		assert.Equal(t, originals[i], resource.Data, "input resource %d was mutated", i)
	}
	return results
}

func binaryIntegrationFindings(results types.Results) []types.DetectedVulnerability {
	var findings []types.DetectedVulnerability
	for _, scan := range results {
		findings = append(findings, scan.Vulnerabilities...)
	}
	return findings
}

func writeBinaryIntegration(t *testing.T, results types.Results) cdx.BOM {
	t.Helper()
	var out bytes.Buffer
	err := cdxreport.NewWriter(&out, "test", false).Write(context.Background(), types.Report{
		ArtifactName: "binary-fixture", ArtifactType: artifact.TypeContainerImage, Results: results,
	})
	require.NoError(t, err)
	var bom cdx.BOM
	require.NoError(t, json.Unmarshal(out.Bytes(), &bom))
	assertBinaryIntegrationReferences(t, bom)
	return bom
}

func assertBinaryIntegrationReferences(t *testing.T, bom cdx.BOM) {
	t.Helper()
	refs := map[string]bool{}
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		refs[bom.Metadata.Component.BOMRef] = true
	}
	for _, component := range lo.FromPtr(bom.Components) {
		require.NotEmpty(t, component.BOMRef)
		require.False(t, refs[component.BOMRef], "duplicate component ref %s", component.BOMRef)
		refs[component.BOMRef] = true
	}
	deps := map[string]bool{}
	for _, dependency := range lo.FromPtr(bom.Dependencies) {
		require.True(t, refs[dependency.Ref], "dangling dependency root %s", dependency.Ref)
		require.False(t, deps[dependency.Ref], "duplicate dependency root %s", dependency.Ref)
		deps[dependency.Ref] = true
		children := map[string]bool{}
		for _, ref := range lo.FromPtr(dependency.Dependencies) {
			require.True(t, refs[ref], "dangling dependency child %s", ref)
			require.NotEqual(t, dependency.Ref, ref, "self dependency")
			require.False(t, children[ref], "duplicate child %s", ref)
			children[ref] = true
		}
	}
	for _, vuln := range lo.FromPtr(bom.Vulnerabilities) {
		require.NotEqual(t, "CVE-RAW-SENTINEL", vuln.ID)
		require.NotEmpty(t, lo.FromPtr(vuln.Affects))
		for _, affects := range *vuln.Affects {
			require.True(t, refs[affects.Ref], "dangling vulnerability affects %s", affects.Ref)
		}
	}
}

func TestScanTargetBinaryAssessmentEndToEnd(t *testing.T) {
	initBinaryIntegrationDB(t)
	for _, tc := range []struct {
		name       string
		source     string
		component  cdx.Component
		wantIDs    []string
		candidate  bool
		wantStatus string
	}{
		{name: "affected exact Conan package", source: ftypes.CustomResourceCycloneDXBomBlint,
			component: binaryIntegrationZlib("1.2.11", "conan", false), wantIDs: []string{"CVE-2099-0001"}, wantStatus: "scanned"},
		{name: "fixed exact Conan package keeps inventory", source: ftypes.CustomResourceCycloneDXBomBlint,
			component: binaryIntegrationZlib("1.3.1", "conan", false), wantStatus: "scanned"},
		{name: "reference release remains a candidate despite being newer than fixes", source: ftypes.CustomResourceCycloneDXBinSBOM,
			component: binaryIntegrationZlib("1.3.1", "generic", true), wantIDs: []string{"CVE-2099-0001", "CVE-2099-0002"}, candidate: true, wantStatus: "candidate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resource := binaryIntegrationResource(t, tc.source, "/usr/bin/demo", tc.component)
			results := scanBinaryIntegration(t, []ftypes.CustomResource{resource}, types.Scanners{types.VulnerabilityScanner})
			findings := binaryIntegrationFindings(results)
			var ids []string
			for _, finding := range findings {
				ids = append(ids, finding.VulnerabilityID)
				assert.NotEmpty(t, finding.Title, "FillInfo should load real DB details")
				assert.NotEmpty(t, finding.Severity)
				assert.NotEmpty(t, finding.PrimaryURL)
				require.NotNil(t, finding.DataSource)
				assert.Equal(t, dbTypes.SourceID("glad"), finding.DataSource.ID)
				assert.Equal(t, "/usr/bin/demo", finding.PkgPath)
				assert.Contains(t, finding.PkgIdentifier.BOMRef, "urn:bolt:binary:")
				if tc.candidate {
					assert.Equal(t, dbTypes.StatusUnderInvestigation, finding.Status, "FillInfo must not upgrade a candidate")
					assert.Empty(t, finding.InstalledVersion)
					assert.Empty(t, finding.FixedVersion)
				} else {
					assert.Equal(t, dbTypes.StatusFixed, finding.Status)
					assert.Equal(t, "1.2.11", finding.InstalledVersion)
					assert.Equal(t, "1.2.13", finding.FixedVersion)
				}
			}
			assert.ElementsMatch(t, tc.wantIDs, ids)
			bom := writeBinaryIntegration(t, results)
			var library *cdx.Component
			roots := 0
			for _, component := range lo.FromPtr(bom.Components) {
				if component.Type == cdx.ComponentTypeApplication {
					roots++
				}
				if component.Name == "zlib" {
					require.Nil(t, library, "same package was emitted twice")
					library = lo.ToPtr(component)
				}
			}
			require.NotNil(t, library)
			assert.Equal(t, 1, roots, "scanner aggregate root should merge with the binary root")
			assert.Equal(t, tc.component.PackageURL, library.PackageURL, "advisory lookup must not relabel inventory")
			assert.Equal(t, tc.component.Version, library.Version)
			assert.Contains(t, lo.FromPtr(library.Properties), cdx.Property{Name: binaryscanner.PropertyScanStatus, Value: tc.wantStatus})
			assert.Len(t, lo.FromPtr(bom.Vulnerabilities), len(tc.wantIDs))
			for _, vuln := range lo.FromPtr(bom.Vulnerabilities) {
				require.Len(t, lo.FromPtr(vuln.Affects), 1)
				assert.Equal(t, library.BOMRef, (*vuln.Affects)[0].Ref)
				if tc.candidate {
					require.NotNil(t, vuln.Analysis)
					assert.Equal(t, cdx.IASInTriage, vuln.Analysis.State)
					for _, version := range lo.FromPtr((*vuln.Affects)[0].Range) {
						assert.Empty(t, version.Version)
						assert.Equal(t, cdx.VulnerabilityStatusUnknown, version.Status)
					}
				}
			}
		})
	}
}

func TestScanTargetBinarySupportedLanguagePURLs(t *testing.T) {
	initBinaryIntegrationDB(t)
	var resources []ftypes.CustomResource
	for _, ecosystem := range []string{"npm", "pypi"} {
		resources = append(resources, binaryIntegrationResource(t, ftypes.CustomResourceCycloneDXBomBlint, "/usr/bin/"+ecosystem,
			cdx.Component{Type: cdx.ComponentTypeLibrary, BOMRef: "lib:widget", Name: "fixture-widget", Version: "1.0.0",
				PackageURL: "pkg:" + ecosystem + "/fixture-widget@1.0.0"}))
	}
	results := scanBinaryIntegration(t, resources, types.Scanners{types.VulnerabilityScanner})
	findings := binaryIntegrationFindings(results)
	require.Len(t, findings, 2)
	assert.ElementsMatch(t, []string{"CVE-2099-0003", "CVE-2099-0004"}, []string{findings[0].VulnerabilityID, findings[1].VulnerabilityID})
	for _, finding := range findings {
		assert.Equal(t, "1.0.0", finding.InstalledVersion)
		assert.Equal(t, "1.1.0", finding.FixedVersion)
		assert.Equal(t, dbTypes.StatusFixed, finding.Status)
	}
	assert.NotEqual(t, findings[0].PkgIdentifier.BOMRef, findings[1].PkgIdentifier.BOMRef)
	writeBinaryIntegration(t, results)
}

func TestScanTargetBinaryTwoGeneratorsKeepAssessmentAndOneRoot(t *testing.T) {
	initBinaryIntegrationDB(t)
	resources := []ftypes.CustomResource{
		binaryIntegrationResource(t, ftypes.CustomResourceCycloneDXBomBlint, "/usr/bin/demo", binaryIntegrationZlib("1.2.11", "conan", false)),
		binaryIntegrationResource(t, ftypes.CustomResourceCycloneDXBinSBOM, "/usr/bin/demo", binaryIntegrationZlib("1.3.1", "generic", true)),
	}
	results := scanBinaryIntegration(t, resources, types.Scanners{types.VulnerabilityScanner})
	require.Len(t, binaryIntegrationFindings(results), 3)
	bom := writeBinaryIntegration(t, results)
	require.Len(t, lo.FromPtr(bom.Components), 3, "two inventory representations share one binary root")
	refs := map[string]string{}
	for _, component := range *bom.Components {
		refs[component.BOMRef] = component.PackageURL
	}
	require.Len(t, lo.FromPtr(bom.Vulnerabilities), 3, "the shared CVE needs separate confirmed and candidate assessments")
	confirmed, candidates := 0, 0
	for _, vuln := range *bom.Vulnerabilities {
		require.Len(t, lo.FromPtr(vuln.Affects), 1)
		purl := refs[(*vuln.Affects)[0].Ref]
		if vuln.Analysis != nil && vuln.Analysis.State == cdx.IASInTriage {
			candidates++
			assert.Equal(t, "pkg:generic/zlib@1.3.1", purl)
		} else {
			confirmed++
			assert.Equal(t, "CVE-2099-0001", vuln.ID)
			assert.Equal(t, "pkg:conan/zlib@1.2.11", purl)
		}
	}
	assert.Equal(t, 1, confirmed)
	assert.Equal(t, 2, candidates)
}

func TestScanTargetBinaryCandidatesRespectFilters(t *testing.T) {
	initBinaryIntegrationDB(t)
	for _, tc := range []struct {
		name    string
		options result.FilterOptions
		ignore  result.IgnoreConfig
	}{
		{name: "severity", options: result.FilterOptions{Severities: []dbTypes.Severity{dbTypes.SeverityCritical}}},
		{name: "ignore IDs", options: result.FilterOptions{Severities: []dbTypes.Severity{dbTypes.SeverityHigh, dbTypes.SeverityMedium}},
			ignore: result.IgnoreConfig{Vulnerabilities: result.IgnoreFindings{{ID: "CVE-2099-0001"}, {ID: "CVE-2099-0002"}}}},
		{name: "ignore candidate status", options: result.FilterOptions{Severities: []dbTypes.Severity{dbTypes.SeverityHigh, dbTypes.SeverityMedium},
			IgnoreStatuses: []dbTypes.Status{dbTypes.StatusUnderInvestigation}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resource := binaryIntegrationResource(t, ftypes.CustomResourceCycloneDXBinSBOM, "/usr/bin/demo", binaryIntegrationZlib("1.3.1", "generic", true))
			results := scanBinaryIntegration(t, []ftypes.CustomResource{resource}, types.Scanners{types.VulnerabilityScanner})
			require.Len(t, binaryIntegrationFindings(results), 2)
			for i := range results {
				require.NoError(t, result.FilterResult(context.Background(), &results[i], tc.ignore, tc.options))
			}
			require.Empty(t, binaryIntegrationFindings(results))
			bom := writeBinaryIntegration(t, results)
			assert.Empty(t, lo.FromPtr(bom.Vulnerabilities), "writer must not resurrect filtered findings")
			components := lo.FromPtr(bom.Components)
			require.Len(t, components, 2, "filtered inventory should retain its root and library")
			assert.True(t, lo.ContainsBy(components, func(c cdx.Component) bool { return c.PackageURL == "pkg:generic/zlib@1.3.1" }))
		})
	}
}

func TestScanTargetBinaryInventoryWithoutVulnerabilityScanner(t *testing.T) {
	// Deliberately do not initialize a DB: an accidental advisory lookup would
	// fail, rather than merely returning no findings from an empty test database.
	resource := binaryIntegrationResource(t, ftypes.CustomResourceCycloneDXBinSBOM, "/usr/bin/demo", binaryIntegrationZlib("1.3.1", "generic", true))
	results := scanBinaryIntegration(t, []ftypes.CustomResource{resource}, types.Scanners{types.SBOMScanner})
	require.Empty(t, binaryIntegrationFindings(results))
	for _, scan := range results {
		assert.NotEqual(t, binaryscanner.ResultType, scan.Type)
	}
	bom := writeBinaryIntegration(t, results)
	assert.Empty(t, lo.FromPtr(bom.Vulnerabilities))
	require.Len(t, lo.FromPtr(bom.Components), 2)
	for _, component := range *bom.Components {
		if component.Name == "zlib" {
			assert.Contains(t, lo.FromPtr(component.Properties), cdx.Property{Name: binaryscanner.PropertyScanStatus, Value: "not-scanned"})
		}
	}
}

func TestScanTargetBinarySamePackageAcrossFilesHasDistinctReferences(t *testing.T) {
	initBinaryIntegrationDB(t)
	var resources []ftypes.CustomResource
	for _, path := range []string{"/opt/first/demo", "/opt/second/demo"} {
		resources = append(resources, binaryIntegrationResource(t, ftypes.CustomResourceCycloneDXBomBlint, path, binaryIntegrationZlib("1.2.11", "conan", false)))
	}
	// The same fragment arriving twice must not create a duplicate component or
	// duplicate finding for a single file.
	resources = append(resources, resources[0])
	results := scanBinaryIntegration(t, resources, types.Scanners{types.VulnerabilityScanner})
	findings := binaryIntegrationFindings(results)
	require.Len(t, findings, 2)
	assert.NotEqual(t, findings[0].PkgIdentifier.BOMRef, findings[1].PkgIdentifier.BOMRef)
	bom := writeBinaryIntegration(t, results)
	require.Len(t, lo.FromPtr(bom.Components), 4, "two binary roots and two library instances")
	require.Len(t, lo.FromPtr(bom.Vulnerabilities), 1, "one CVE affects two separate instances")
	assert.Len(t, lo.FromPtr((*bom.Vulnerabilities)[0].Affects), 2)
}
