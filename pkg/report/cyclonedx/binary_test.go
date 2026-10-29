package cyclonedx

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	dbtypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/result"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/package-url/packageurl-go"
)

func binaryReportFixture(t *testing.T, binary, assessment string) (types.Result, ftypes.CustomResource) {
	t.Helper()
	ref := "urn:bolt:binary:" + binary + ":zlib"
	purl, err := packageurl.FromString("pkg:generic/zlib@1.2.11")
	if err != nil {
		t.Fatal(err)
	}
	identifier := ftypes.PkgIdentifier{UID: "uid:" + ref, BOMRef: ref, PURL: &purl}
	scan := types.Result{
		Target: "usr/bin/" + binary,
		Class:  types.ClassLangPkg,
		Type:   "binary",
		Packages: []ftypes.Package{{
			ID: ref, Name: "zlib", Version: "1.2.11", Identifier: identifier,
		}},
	}
	if assessment != "" {
		installed := "1.2.11"
		if assessment == "candidate" {
			installed = ""
		}
		scan.Vulnerabilities = []types.DetectedVulnerability{{
			VulnerabilityID: "CVE-TEST-0001", PkgName: "zlib", PkgPath: scan.Target,
			PkgIdentifier: identifier, InstalledVersion: installed, FixedVersion: "1.2.12",
			Vulnerability: dbtypes.Vulnerability{Severity: "HIGH", Description: "Test advisory"},
			Custom:        map[string]any{binaryAssessmentProperty: assessment},
		}}
	}
	fragment := fmt.Sprintf(`{
		"metadata":{"component":{"type":"application","name":%q,"bom-ref":%q}},
		"components":[{
			"type":"library","name":"zlib","version":"1.2.11","purl":"pkg:generic/zlib@1.2.11","bom-ref":%q,
			"description":"Original generator component",
			"properties":[{"name":"bolt:binary:version-source","value":"reference"}],
			"evidence":{"identity":{"field":"name","confidence":0.8}},
			"externalReferences":[{"type":"vcs","url":"https://example.org/zlib"}]
		}],
		"dependencies":[{"ref":%q,"dependsOn":[%q]}],
		"vulnerabilities":[{"id":"CVE-RAW-MUST-NOT-BYPASS-FILTER","affects":[{"ref":%q}]}]
	}`, binary, "urn:bolt:binary:"+binary, ref, "urn:bolt:binary:"+binary, ref, ref)
	return scan, ftypes.CustomResource{Type: ftypes.CustomResourceCycloneDXBinSBOM, FilePath: scan.Target, Data: []byte(fragment)}
}

func renderBinaryReport(t *testing.T, results types.Results, resources ...ftypes.CustomResource) cdx.BOM {
	t.Helper()
	results = append(results, types.Result{Class: types.ClassCustom, CustomResources: resources})
	report := types.Report{ArtifactName: "test-image", ArtifactType: artifact.TypeContainerImage, Results: results}
	var out bytes.Buffer
	if err := NewWriter(&out, "test", false).Write(context.Background(), report); err != nil {
		t.Fatal(err)
	}
	var bom cdx.BOM
	if err := json.Unmarshal(out.Bytes(), &bom); err != nil {
		t.Fatal(err)
	}
	assertBinaryReferences(t, bom)
	return bom
}

func assertBinaryReferences(t *testing.T, bom cdx.BOM) {
	t.Helper()
	refs := map[string]bool{}
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		refs[bom.Metadata.Component.BOMRef] = true
	}
	if bom.Components != nil {
		for _, component := range *bom.Components {
			if component.BOMRef == "" || refs[component.BOMRef] {
				t.Fatalf("empty or duplicated component ref %q", component.BOMRef)
			}
			refs[component.BOMRef] = true
		}
	}
	if bom.Dependencies != nil {
		deps := map[string]bool{}
		for _, dep := range *bom.Dependencies {
			if !refs[dep.Ref] || deps[dep.Ref] {
				t.Fatalf("dangling or duplicate dependency ref %q", dep.Ref)
			}
			deps[dep.Ref] = true
			if dep.Dependencies != nil {
				for _, ref := range *dep.Dependencies {
					if !refs[ref] || ref == dep.Ref {
						t.Fatalf("invalid dependency %q -> %q", dep.Ref, ref)
					}
				}
			}
		}
	}
	if bom.Vulnerabilities != nil {
		for _, vuln := range *bom.Vulnerabilities {
			if vuln.Affects == nil {
				t.Fatalf("vulnerability %s has no affects", vuln.ID)
			}
			for _, affects := range *vuln.Affects {
				if !refs[affects.Ref] {
					t.Fatalf("vulnerability %s has dangling ref %q", vuln.ID, affects.Ref)
				}
			}
		}
	}
}

func TestWriterEnrichesBinaryPackagesWithoutDuplicateComponents(t *testing.T) {
	scan, fragment := binaryReportFixture(t, "appA", "affected")
	// Both generators supplied the same scoped component and scanner package.
	second := fragment
	second.Type = ftypes.CustomResourceCycloneDXBomBlint
	bom := renderBinaryReport(t, types.Results{scan, scan}, fragment, second)
	if len(*bom.Components) != 2 {
		t.Fatalf("components = %d, want binary root and library only", len(*bom.Components))
	}
	for _, component := range *bom.Components {
		if component.BOMRef != scan.Packages[0].Identifier.BOMRef {
			continue
		}
		if component.Version != "1.2.11" || component.PackageURL != "pkg:generic/zlib@1.2.11" || component.Description != "Original generator component" || component.Evidence == nil || component.ExternalReferences == nil {
			t.Fatalf("original component metadata lost: %#v", component)
		}
		sources := map[string]bool{}
		for _, prop := range *component.Properties {
			if prop.Name == propertyMetadata {
				sources[prop.Value] = true
			}
		}
		if !sources[sourceTagBinSBOM] || !sources[sourceTagBomBlint] {
			t.Fatalf("missing generator provenance: %v", sources)
		}
	}
	if bom.Vulnerabilities == nil || len(*bom.Vulnerabilities) != 1 || len(*(*bom.Vulnerabilities)[0].Affects) != 1 {
		t.Fatalf("expected one CVE affecting one component: %#v", bom.Vulnerabilities)
	}
}

func TestWriterKeepsBinaryAssessmentsLocalToEachComponent(t *testing.T) {
	scan, fragment := binaryReportFixture(t, "appA", "affected")
	var source cdx.BOM
	if err := json.Unmarshal(fragment.Data.([]byte), &source); err != nil {
		t.Fatal(err)
	}
	rootProperties := []cdx.Property{
		{Name: "bolt:binary:source-ref", Value: "pkg:generic/appA"},
		{Name: "bolt:binary:vulnerability-status", Value: "not-scanned"},
		{Name: "bolt:binary:vulnerability-reason", Value: "unmapped-project-identity"},
		{Name: "bolt:binary:root-only", Value: "must-not-inherit"},
		{Name: "binary:file:path", Value: "usr/bin/appA"},
	}
	childProperties := []cdx.Property{
		{Name: "bolt:binary:source-ref", Value: "pkg:generic/zlib@1.2.11"},
		{Name: "bolt:binary:vulnerability-status", Value: "scanned"},
		{Name: "bolt:binary:vulnerability-reason", Value: "version-range-evaluated"},
	}
	source.Metadata.Component.Properties = &rootProperties
	(*source.Components)[0].Properties = &childProperties
	data, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	fragment.Data = data
	bom := renderBinaryReport(t, types.Results{scan}, fragment)
	for _, component := range *bom.Components {
		properties := map[string][]string{}
		if component.Properties != nil {
			for _, property := range *component.Properties {
				properties[property.Name] = append(properties[property.Name], property.Value)
			}
		}
		want := rootProperties
		if component.BOMRef == scan.Packages[0].Identifier.BOMRef {
			want = childProperties
			if len(properties["bolt:binary:root-only"]) != 0 {
				t.Fatalf("root-only component property inherited: %v", properties)
			}
			if values := properties["binary:file:path"]; len(values) != 1 || values[0] != "usr/bin/appA" {
				t.Fatalf("shared file metadata lost: %v", properties)
			}
		}
		for _, property := range want {
			if values := properties[property.Name]; len(values) != 1 || values[0] != property.Value {
				t.Fatalf("component %q property %q = %v, want only %q", component.BOMRef, property.Name, values, property.Value)
			}
		}
	}
}

func TestWriterSeparatesCandidateAndConfirmedBinaryFindings(t *testing.T) {
	candidate, fragmentA := binaryReportFixture(t, "appA", "candidate")
	confirmed, fragmentB := binaryReportFixture(t, "appB", "affected")
	// An ordinary package with the same CVE must not inherit binary uncertainty.
	purl, _ := packageurl.FromString("pkg:npm/example@1.0.0")
	id := ftypes.PkgIdentifier{UID: "ordinary", BOMRef: "pkg:npm/example@1.0.0", PURL: &purl}
	ordinary := types.Result{
		Target: "package-lock.json", Class: types.ClassLangPkg, Type: "npm",
		Packages: []ftypes.Package{{Name: "example", Version: "1.0.0", Identifier: id}},
		Vulnerabilities: []types.DetectedVulnerability{{
			VulnerabilityID: "CVE-TEST-0001", PkgName: "example", InstalledVersion: "1.0.0", PkgIdentifier: id,
		}},
	}
	bom := renderBinaryReport(t, types.Results{candidate, confirmed, ordinary}, fragmentA, fragmentB)
	if bom.Vulnerabilities == nil || len(*bom.Vulnerabilities) != 2 {
		t.Fatalf("expected separate candidate and confirmed entries: %#v", bom.Vulnerabilities)
	}
	var candidateRef string
	for _, vuln := range *bom.Vulnerabilities {
		if vuln.Analysis != nil && vuln.Analysis.State == cdx.IASInTriage {
			candidateRef = vuln.BOMRef
			if candidateRef == "" || len(*vuln.Affects) != 1 || (*vuln.Affects)[0].Ref != candidate.Packages[0].Identifier.BOMRef {
				t.Fatalf("incorrect candidate affects: %#v", vuln)
			}
			versions := *(*vuln.Affects)[0].Range
			if len(versions) != 1 || versions[0].Status != cdx.VulnerabilityStatusUnknown || versions[0].Version != "" || versions[0].Range != "vers:generic/*" {
				t.Fatalf("candidate must not assert an affected installed version: %#v", versions)
			}
		} else {
			if len(*vuln.Affects) != 2 {
				t.Fatalf("confirmed refs lost: %#v", vuln.Affects)
			}
			for _, affects := range *vuln.Affects {
				if affects.Ref == candidate.Packages[0].Identifier.BOMRef || affects.Range == nil || (*affects.Range)[0].Status != cdx.VulnerabilityStatusAffected {
					t.Fatalf("candidate and confirmed refs mixed: %#v", affects)
				}
			}
		}
	}
	if candidateRef == "" {
		t.Fatal("missing in_triage entry")
	}
}

func TestWriterBinaryFindingsRespectFiltersAndKeepInventory(t *testing.T) {
	for _, assessment := range []string{"candidate", "affected", ""} {
		t.Run(assessment, func(t *testing.T) {
			scan, fragment := binaryReportFixture(t, "appA", assessment)
			if err := result.FilterResult(context.Background(), &scan, result.IgnoreConfig{}, result.FilterOptions{Severities: []dbtypes.Severity{dbtypes.SeverityCritical}}); err != nil {
				t.Fatal(err)
			}
			bom := renderBinaryReport(t, types.Results{scan}, fragment)
			if bom.Vulnerabilities != nil && len(*bom.Vulnerabilities) != 0 {
				t.Fatalf("filtered or raw fragment vulnerability bypassed filtering: %#v", bom.Vulnerabilities)
			}
			if len(*bom.Components) != 2 {
				t.Fatalf("no-CVE inventory not retained: %#v", bom.Components)
			}
		})
	}
}
