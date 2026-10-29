package cyclonedx

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

type recursiveLibtreeDocument struct {
	cdx.BOM
}

func recursiveGraphResource(t *testing.T, filePath string, graph []libtreeGraphNode) ftypes.CustomResource {
	t.Helper()
	raw, err := json.Marshal(graph)
	if err != nil {
		t.Fatal(err)
	}
	return ftypes.CustomResource{Type: "libtree", FilePath: filePath, Data: raw}
}

func renderRecursiveLibtree(t *testing.T, resources []ftypes.CustomResource, enabled bool) recursiveLibtreeDocument {
	t.Helper()
	report := types.Report{
		ArtifactName: "recursive-test-image", ArtifactType: artifact.TypeContainerImage,
		Results: types.Results{{Class: types.ClassCustom, CustomResources: resources}},
	}
	var out bytes.Buffer
	if err := NewWriter(&out, "test", enabled).Write(context.Background(), report); err != nil {
		t.Fatal(err)
	}
	var doc recursiveLibtreeDocument
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("decode writer output: %v\n%s", err, out.String())
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(out.Bytes(), &fields); err != nil {
		t.Fatal(err)
	}
	if _, ok := fields["libtree"]; ok {
		t.Fatal("recursive graph leaked into a nonstandard top-level field")
	}
	assertBinaryReferences(t, doc.BOM)
	return doc
}

func graphProperties(component cdx.Component) map[string]string {
	values := map[string]string{}
	if component.Properties != nil {
		for _, property := range *component.Properties {
			values[property.Name] = property.Value
		}
	}
	return values
}

func graphComponents(doc recursiveLibtreeDocument) map[string]cdx.Component {
	components := map[string]cdx.Component{}
	if doc.Components != nil {
		for _, component := range *doc.Components {
			if id := graphProperties(component)["bolt:libtree:node-id"]; id != "" {
				components[id] = component
			}
		}
	}
	return components
}

func graphDependencies(doc recursiveLibtreeDocument) map[string][]string {
	dependencies := map[string][]string{}
	if doc.Dependencies != nil {
		for _, dependency := range *doc.Dependencies {
			if dependency.Dependencies != nil {
				dependencies[dependency.Ref] = *dependency.Dependencies
			}
		}
	}
	return dependencies
}

func recursiveGraphFixture() ([]libtreeGraphNode, []libtreeGraphNode) {
	const rootA, rootB = "/opt/a/tool", "/opt/b/tool"
	const first = rootA + "::/opt/a/lib/libsame.so"
	const transitive = rootA + "::/usr/lib/libsame.so"
	const missing = rootA + "::missing:/usr/lib/libsame.so::libmissing.so"
	return []libtreeGraphNode{
			{ID: rootA, Name: "tool", Path: rootA, DependsOn: []string{first}, Status: "resolved", Kind: "application"},
			{ID: first, Name: "libsame.so", Path: "/opt/a/lib/libsame.so", DependsOn: []string{transitive}, Status: "resolved"},
			{ID: transitive, Name: "libsame.so", Path: "/usr/lib/libsame.so", DependsOn: []string{first, missing}, Status: "resolved"},
			{ID: missing, Name: "libmissing.so", DependsOn: []string{}, Status: "missing", Reason: "dependency not found in target filesystem"},
		}, []libtreeGraphNode{
			{ID: rootB, Name: "tool", Path: rootB, DependsOn: []string{rootB + "::/usr/lib/libsame.so"}, Status: "resolved", Kind: "application"},
			{ID: rootB + "::/usr/lib/libsame.so", Name: "libsame.so", Path: "/usr/lib/libsame.so", DependsOn: []string{}, Status: "resolved"},
		}
}

func TestWriterRecursiveLibtreeWithoutBinaryGenerators(t *testing.T) {
	first, second := recursiveGraphFixture()
	resources := []ftypes.CustomResource{
		recursiveGraphResource(t, "opt/a/tool", first),
		recursiveGraphResource(t, "opt/b/tool", second),
	}
	doc := renderRecursiveLibtree(t, resources, true)
	components, dependencies := graphComponents(doc), graphDependencies(doc)
	wantGraph := append(append([]libtreeGraphNode{}, first...), second...)
	if len(components) != len(wantGraph) {
		t.Fatalf("same-name paths or root contexts were merged: %d components, want %d", len(components), len(wantGraph))
	}
	for _, node := range wantGraph {
		component := components[node.ID]
		if component.BOMRef == "" || component.Name != node.Name {
			t.Fatalf("missing component for node %q: %#v", node.ID, component)
		}
		var want []string
		for _, child := range node.DependsOn {
			want = append(want, components[child].BOMRef)
		}
		if !sameStrings(dependencies[component.BOMRef], want) {
			t.Fatalf("recursive edge for %q = %v, want %v", node.ID, dependencies[component.BOMRef], want)
		}
		if _, exists := dependencies[component.BOMRef]; node.Status == "resolved" && !exists {
			t.Fatalf("resolved node %q lacks an explicit dependency record", node.ID)
		}
		if props := graphProperties(component); props["bolt:libtree:status"] != node.Status || props["bolt:libtree:path"] != node.Path ||
			props["bolt:libtree:name"] != node.Name || props["bolt:libtree:reason"] != node.Reason || props["bolt:libtree:kind"] != node.Kind {
			t.Fatalf("node metadata lost: %q, %v", node.ID, props)
		}
	}
	missing := components[first[3].ID]
	if _, exists := dependencies[missing.BOMRef]; exists {
		t.Fatal("unresolved dependency was claimed to have no dependencies")
	}
	if missing.PackageURL != "" || graphProperties(missing)["bolt:libtree:reason"] != first[3].Reason {
		t.Fatalf("missing dependency was presented as a resolved file: %#v", missing)
	}
	if graphProperties(missing)[PropertyComponentGroup] != GroupUnknown {
		t.Fatal("unresolved dependency was classified as an installed system library")
	}
	for _, node := range []libtreeGraphNode{first[1], first[2], second[1]} {
		if graphProperties(components[node.ID])[PropertyComponentGroup] != GroupSys {
			t.Fatalf("resolved runtime library %q lost its system classification", node.ID)
		}
	}
	for _, root := range []string{first[0].ID, second[0].ID} {
		if components[root].Type != cdx.ComponentTypeApplication {
			t.Fatalf("graph root %q is not an application", root)
		}
		if graphProperties(components[root])[PropertyComponentGroup] != GroupApp {
			t.Fatalf("resolved executable root %q lost its application classification", root)
		}
	}
	if doc.Metadata == nil || doc.Metadata.Component == nil || !sameStrings(dependencies[doc.Metadata.Component.BOMRef], []string{
		components[first[0].ID].BOMRef, components[second[0].ID].BOMRef,
	}) {
		t.Fatalf("artifact root does not link to both executable roots: %#v", doc.Dependencies)
	}
	// Applier map iteration can change CustomResource order; node identity must
	// remain stable even when the same pathname occurs under separate roots.
	reversed := renderRecursiveLibtree(t, []ftypes.CustomResource{resources[1], resources[0]}, true)
	for id, component := range graphComponents(reversed) {
		if component.BOMRef != components[id].BOMRef {
			t.Fatalf("unstable BOM reference for %q", id)
		}
	}
}

func TestWriterRecursiveLibtreeMapsRootsByFullPath(t *testing.T) {
	first, second := recursiveGraphFixture()
	fragment := func(ref string) []byte {
		raw, err := json.Marshal(cdx.BOM{Metadata: &cdx.Metadata{Component: &cdx.Component{
			Type: cdx.ComponentTypeApplication, Name: "generator-subject", BOMRef: ref,
		}}})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	resources := []ftypes.CustomResource{
		recursiveGraphResource(t, "opt/a/tool", first),
		recursiveGraphResource(t, "opt/b/tool", second),
		{Type: ftypes.CustomResourceCycloneDXBomBlint, FilePath: "./opt/a/../a/tool", Data: fragment("app:first")},
		{Type: ftypes.CustomResourceCycloneDXBomBlint, FilePath: "/opt/b/tool", Data: fragment("app:second")},
	}
	doc := renderRecursiveLibtree(t, resources, true)
	components, dependencies := graphComponents(doc), graphDependencies(doc)
	if components[first[0].ID].BOMRef != "app:first" || components[second[0].ID].BOMRef != "app:second" {
		t.Fatalf("same basename mapped to the wrong binary resource: %v", components)
	}
	for _, root := range []string{first[0].ID, second[0].ID} {
		if components[root].Name != "generator-subject" || graphProperties(components[root])["bolt:libtree:name"] != "tool" {
			t.Fatalf("generator subject or ELF name was lost for %s", root)
		}
	}
	if !sameStrings(dependencies["app:first"], []string{components[first[1].ID].BOMRef}) ||
		!sameStrings(dependencies["app:second"], []string{components[second[1].ID].BOMRef}) {
		t.Fatalf("binary roots crossed dependency graphs: %v", dependencies)
	}
	if len(*doc.Components) != len(first)+len(second) {
		t.Fatalf("duplicate synthetic roots remain: %#v", doc.Components)
	}
}

func TestWriterRecursiveLibtreeDisabled(t *testing.T) {
	first, _ := recursiveGraphFixture()
	doc := renderRecursiveLibtree(t, []ftypes.CustomResource{recursiveGraphResource(t, "opt/a/tool", first)}, false)
	if len(graphComponents(doc)) != 0 {
		t.Fatalf("disabled graph was emitted: %#v", doc)
	}
}

func TestWriterRecursiveLibtreeSharedLibraryRoot(t *testing.T) {
	root := libtreeGraphNode{
		ID: "/usr/lib/libstandalone.so", Name: "libstandalone.so", Path: "/usr/lib/libstandalone.so",
		DependsOn: []string{}, Status: "resolved", Kind: "library",
	}
	doc := renderRecursiveLibtree(t, []ftypes.CustomResource{recursiveGraphResource(t, "usr/lib/libstandalone.so", []libtreeGraphNode{root})}, true)
	component := graphComponents(doc)[root.ID]
	if component.Type != cdx.ComponentTypeLibrary || graphProperties(component)[PropertyComponentGroup] != GroupSys || component.PackageURL != "pkg:file/usr/lib/libstandalone.so" {
		t.Fatalf("a shared-library scan root was claimed to be an executable application: %#v", component)
	}
	if !sameStrings(graphDependencies(doc)[doc.Metadata.Component.BOMRef], []string{component.BOMRef}) {
		t.Fatal("standalone library root is not linked to the artifact")
	}
}
