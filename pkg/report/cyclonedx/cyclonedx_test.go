package cyclonedx

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestWriterMergesLibtreeAndBomBlintDependencies(t *testing.T) {
	libtree := []byte(`[
		{"name":"binA","dependsOn":["libfoo.so.1","libbar.so.1"]},
		{"name":"libfoo.so.1","dependsOn":[]},
		{"name":"libbar.so.1","dependsOn":["libqux.so.1"]},
		{"name":"libqux.so.1","dependsOn":[]}
	]`)
	blint := []byte(`{
		"metadata": {
			"component": {
				"bom-ref": "pkg:generic/binA",
				"type": "application",
				"name": "binA",
				"purl": "pkg:generic/binA"
			}
		},
		"components": [
			{
				"bom-ref": "pkg:file/libfoo.so.1",
				"type": "library",
				"name": "libfoo.so.1",
				"purl": "pkg:file/libfoo.so.1"
			},
			{
				"bom-ref": "pkg:file/libbaz.so.1",
				"type": "library",
				"name": "libbaz.so.1",
				"purl": "pkg:file/libbaz.so.1"
			}
		],
		"dependencies": [
			{
				"ref": "pkg:generic/binA",
				"dependsOn": ["pkg:file/libfoo.so.1"]
			}
		]
	}`)

	report := types.Report{
		ArtifactName: "test-image",
		ArtifactType: artifact.TypeContainerImage,
		Results: types.Results{
			{
				Target: "target_binaries/binA",
				Class:  types.ClassCustom,
				CustomResources: []ftypes.CustomResource{
					{
						Type:     "libtree",
						FilePath: "target_binaries/binA",
						Data:     libtree,
					},
					{
						Type:     "cyclonedx",
						FilePath: "target_binaries/binA",
						Data:     blint,
					},
				},
			},
		},
	}

	var out bytes.Buffer
	if err := NewWriter(&out, "test", true).Write(context.Background(), report); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	var doc struct {
		Components []struct {
			BOMRef string `json:"bom-ref"`
			Name   string `json:"name"`
		} `json:"components"`
		Dependencies []struct {
			Ref       string   `json:"ref"`
			DependsOn []string `json:"dependsOn"`
		} `json:"dependencies"`
		Libtree json.RawMessage `json:"libtree"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal output: %v\n%s", err, out.String())
	}

	var got []string
	for _, dep := range doc.Dependencies {
		if dep.Ref == "pkg:generic/binA" {
			got = dep.DependsOn
			break
		}
	}
	want := []string{
		"pkg:file/libfoo.so.1",
		"pkg:file/libbar.so.1",
		"pkg:file/libbaz.so.1",
	}
	if !sameStrings(got, want) {
		t.Fatalf("binA dependsOn = %#v, want %#v", got, want)
	}

	count := map[string]int{}
	for _, ref := range got {
		count[ref]++
	}
	if count["pkg:file/libfoo.so.1"] != 1 {
		t.Fatalf("expected libfoo to be deduplicated once, got %d in %#v", count["pkg:file/libfoo.so.1"], got)
	}

	componentRefs := map[string]struct{}{}
	for _, component := range doc.Components {
		componentRefs[component.BOMRef] = struct{}{}
	}
	for _, ref := range []string{"pkg:file/libbar.so.1", "pkg:file/libqux.so.1"} {
		if _, ok := componentRefs[ref]; !ok {
			t.Fatalf("missing synthetic libtree component %s in %#v", ref, doc.Components)
		}
	}

	var libbarDeps []string
	for _, dep := range doc.Dependencies {
		if dep.Ref == "pkg:file/libbar.so.1" {
			libbarDeps = dep.DependsOn
			break
		}
	}
	if !sameStrings(libbarDeps, []string{"pkg:file/libqux.so.1"}) {
		t.Fatalf("libbar dependsOn = %#v, want libqux", libbarDeps)
	}

	if doc.Libtree != nil {
		t.Fatalf("nonstandard top-level libtree field was emitted: %s", doc.Libtree)
	}
}

func TestWriterSkipsLibtreeDependenciesByDefault(t *testing.T) {
	libtree := []byte(`[
		{"name":"binA","dependsOn":["libfoo.so.1","libbar.so.1"]},
		{"name":"libfoo.so.1","dependsOn":[]},
		{"name":"libbar.so.1","dependsOn":["libqux.so.1"]},
		{"name":"libqux.so.1","dependsOn":[]}
	]`)
	blint := []byte(`{
		"metadata": {
			"component": {
				"bom-ref": "pkg:generic/binA",
				"type": "application",
				"name": "binA",
				"purl": "pkg:generic/binA"
			}
		},
		"components": [
			{
				"bom-ref": "pkg:file/libfoo.so.1",
				"type": "library",
				"name": "libfoo.so.1",
				"purl": "pkg:file/libfoo.so.1"
			}
		],
		"dependencies": [
			{
				"ref": "pkg:generic/binA",
				"dependsOn": ["pkg:file/libfoo.so.1"]
			}
		]
	}`)

	report := types.Report{
		ArtifactName: "test-image",
		ArtifactType: artifact.TypeContainerImage,
		Results: types.Results{
			{
				Target: "target_binaries/binA",
				Class:  types.ClassCustom,
				CustomResources: []ftypes.CustomResource{
					{
						Type:     "libtree",
						FilePath: "target_binaries/binA",
						Data:     libtree,
					},
					{
						Type:     "cyclonedx",
						FilePath: "target_binaries/binA",
						Data:     blint,
					},
				},
			},
		},
	}

	var out bytes.Buffer
	if err := NewWriter(&out, "test", false).Write(context.Background(), report); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	var doc struct {
		Components []struct {
			BOMRef string `json:"bom-ref"`
		} `json:"components"`
		Dependencies []struct {
			Ref       string   `json:"ref"`
			DependsOn []string `json:"dependsOn"`
		} `json:"dependencies"`
		Libtree json.RawMessage `json:"libtree"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal output: %v\n%s", err, out.String())
	}

	if len(doc.Libtree) != 0 {
		t.Fatalf("libtree graph should not be emitted when disabled: %#v", doc.Libtree)
	}

	for _, component := range doc.Components {
		if component.BOMRef == "pkg:file/libbar.so.1" || component.BOMRef == "pkg:file/libqux.so.1" {
			t.Fatalf("unexpected synthetic libtree component when disabled: %#v", doc.Components)
		}
	}

	for _, dep := range doc.Dependencies {
		if dep.Ref == "pkg:file/libbar.so.1" {
			t.Fatalf("unexpected libtree transitive dependency when disabled: %#v", doc.Dependencies)
		}
		if dep.Ref == "pkg:generic/binA" && !sameStrings(dep.DependsOn, []string{"pkg:file/libfoo.so.1"}) {
			t.Fatalf("binA dependsOn = %#v, want only bom-blint dependency", dep.DependsOn)
		}
	}
}

// binSBOMFragment is shaped like the document bin-sbom emits: an "app:" root and
// "lib:" components, which do not collide with bom-blint's purl-style refs.
const binSBOMFragment = `{
	"metadata": {
		"component": {
			"bom-ref": "app:binA",
			"type": "application",
			"name": "binA"
		}
	},
	"components": [
		{
			"bom-ref": "lib:zlib@1.3.2",
			"type": "library",
			"name": "zlib",
			"version": "1.3.2",
			"purl": "pkg:generic/zlib@1.3.2"
		}
	],
	"dependencies": [
		{"ref": "app:binA", "dependsOn": ["lib:zlib@1.3.2"]}
	]
}`

type mergedDoc struct {
	Components []struct {
		BOMRef     string `json:"bom-ref"`
		Type       string `json:"type"`
		Name       string `json:"name"`
		Properties []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"properties"`
	} `json:"components"`
	Dependencies []struct {
		Ref       string   `json:"ref"`
		DependsOn []string `json:"dependsOn"`
	} `json:"dependencies"`
}

func writeAndParse(t *testing.T, resources []ftypes.CustomResource) mergedDoc {
	t.Helper()

	report := types.Report{
		ArtifactName: "test-image",
		ArtifactType: artifact.TypeContainerImage,
		Results: types.Results{
			{
				Target:          "target_binaries/binA",
				Class:           types.ClassCustom,
				CustomResources: resources,
			},
		},
	}

	var out bytes.Buffer
	if err := NewWriter(&out, "test", false).Write(context.Background(), report); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	var doc mergedDoc
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal output: %v\n%s", err, out.String())
	}
	return doc
}

func sourceTags(doc mergedDoc, bomRef string) []string {
	var tags []string
	for _, component := range doc.Components {
		if component.BOMRef != bomRef {
			continue
		}
		for _, p := range component.Properties {
			if p.Name == "metadata" {
				tags = append(tags, p.Value)
			}
		}
	}
	return tags
}

func TestWriterTagsBinSBOMComponents(t *testing.T) {
	doc := writeAndParse(t, []ftypes.CustomResource{
		{
			Type:     ftypes.CustomResourceCycloneDXBinSBOM,
			FilePath: "target_binaries/binA",
			Data:     []byte(binSBOMFragment),
		},
	})

	if got := sourceTags(doc, "lib:zlib@1.3.2"); !sameStrings(got, []string{"bin_sbom", "bin_sbom"}) {
		// The component carries its own tag plus the root's, matching bom-blint's shape.
		t.Fatalf("zlib metadata tags = %#v, want bin_sbom", got)
	}
	if got := sourceTags(doc, "app:binA"); !sameStrings(got, []string{"bin_sbom"}) {
		t.Fatalf("root metadata tags = %#v, want [bin_sbom]", got)
	}

	for _, dep := range doc.Dependencies {
		if dep.Ref == "app:binA" && !sameStrings(dep.DependsOn, []string{"lib:zlib@1.3.2"}) {
			t.Fatalf("binA dependsOn = %#v, want [lib:zlib@1.3.2]", dep.DependsOn)
		}
	}
}

func TestWriterMergesBothGeneratorsIntoOneRoot(t *testing.T) {
	blint := []byte(`{
		"metadata": {
			"component": {
				"bom-ref": "pkg:generic/binA",
				"type": "application",
				"name": "binA",
				"purl": "pkg:generic/binA"
			}
		},
		"components": [
			{
				"bom-ref": "pkg:file/libfoo.so.1",
				"type": "library",
				"name": "libfoo.so.1",
				"purl": "pkg:file/libfoo.so.1"
			}
		],
		"dependencies": [
			{"ref": "pkg:generic/binA", "dependsOn": ["pkg:file/libfoo.so.1"]}
		]
	}`)

	doc := writeAndParse(t, []ftypes.CustomResource{
		{
			Type:     ftypes.CustomResourceCycloneDXBomBlint,
			FilePath: "target_binaries/binA",
			Data:     blint,
		},
		{
			Type:     ftypes.CustomResourceCycloneDXBinSBOM,
			FilePath: "target_binaries/binA",
			Data:     []byte(binSBOMFragment),
		},
	})

	// One binary must yield one root, not one per generator.
	var roots []string
	for _, component := range doc.Components {
		if component.Type == "application" && component.Name == "binA" {
			roots = append(roots, component.BOMRef)
		}
	}
	if !sameStrings(roots, []string{"pkg:generic/binA"}) {
		t.Fatalf("roots for binA = %#v, want only the first generator's ref", roots)
	}

	// The shared root records both generators.
	if got := sourceTags(doc, "pkg:generic/binA"); !sameStrings(got, []string{"bom_blint", "bin_sbom"}) {
		t.Fatalf("root metadata tags = %#v, want both generators", got)
	}

	// Each generator's components survive, tagged by their own source.
	if got := sourceTags(doc, "pkg:file/libfoo.so.1"); len(got) == 0 || got[0] != "bom_blint" {
		t.Fatalf("libfoo metadata tags = %#v, want bom_blint", got)
	}
	if got := sourceTags(doc, "lib:zlib@1.3.2"); len(got) == 0 || got[0] != "bin_sbom" {
		t.Fatalf("zlib metadata tags = %#v, want bin_sbom", got)
	}

	// One dependency entry for the root, holding both generators' children.
	var edges [][]string
	for _, dep := range doc.Dependencies {
		if dep.Ref == "pkg:generic/binA" {
			edges = append(edges, dep.DependsOn)
		}
	}
	if len(edges) != 1 {
		t.Fatalf("got %d dependency entries for binA, want 1: %#v", len(edges), edges)
	}
	if !sameStrings(edges[0], []string{"pkg:file/libfoo.so.1", "lib:zlib@1.3.2"}) {
		t.Fatalf("binA dependsOn = %#v, want both generators' children", edges[0])
	}

	// The second generator's own root ref must not linger as a dangling edge.
	for _, dep := range doc.Dependencies {
		if dep.Ref == "app:binA" {
			t.Fatalf("unexpected rival root dependency entry: %#v", dep)
		}
	}
}

func sameStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func TestWriterMergeIsIndependentOfResourceOrder(t *testing.T) {
	blint := []byte(`{
		"metadata": {"component": {"bom-ref": "pkg:generic/binA", "type": "application", "name": "binA", "purl": "pkg:generic/binA"}},
		"components": [{"bom-ref": "pkg:file/libfoo.so.1", "type": "library", "name": "libfoo.so.1", "purl": "pkg:file/libfoo.so.1"}],
		"dependencies": [{"ref": "pkg:generic/binA", "dependsOn": ["pkg:file/libfoo.so.1"]}]
	}`)

	blintRes := ftypes.CustomResource{
		Type:     ftypes.CustomResourceCycloneDXBomBlint,
		FilePath: "target_binaries/binA",
		Data:     blint,
	}
	binSBOMRes := ftypes.CustomResource{
		Type:     ftypes.CustomResourceCycloneDXBinSBOM,
		FilePath: "target_binaries/binA",
		Data:     []byte(binSBOMFragment),
	}

	// The applier rebuilds custom resources by walking a map, so the order fragments
	// reach the writer varies between runs. Both orders must produce the same BOM.
	forward := writeAndParse(t, []ftypes.CustomResource{blintRes, binSBOMRes})
	reversed := writeAndParse(t, []ftypes.CustomResource{binSBOMRes, blintRes})

	if !reflect.DeepEqual(forward.Components, reversed.Components) {
		t.Fatalf("components depend on custom resource order:\nforward  = %#v\nreversed = %#v",
			forward.Components, reversed.Components)
	}

	// The artifact's own dependency entry is keyed by a freshly generated serial number,
	// so compare the edges this merge produces instead of the whole list.
	deps := func(doc mergedDoc, ref string) []string {
		for _, dep := range doc.Dependencies {
			if dep.Ref == ref {
				return dep.DependsOn
			}
		}
		return nil
	}
	if !sameStrings(deps(forward, "pkg:generic/binA"), deps(reversed, "pkg:generic/binA")) {
		t.Fatalf("binA dependsOn depends on custom resource order: %#v vs %#v",
			deps(forward, "pkg:generic/binA"), deps(reversed, "pkg:generic/binA"))
	}

	// bom-blint owns the root either way.
	var roots []string
	for _, component := range reversed.Components {
		if component.Type == "application" && component.Name == "binA" {
			roots = append(roots, component.BOMRef)
		}
	}
	if !sameStrings(roots, []string{"pkg:generic/binA"}) {
		t.Fatalf("roots for binA = %#v, want only pkg:generic/binA", roots)
	}
}
