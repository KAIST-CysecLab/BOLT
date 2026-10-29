package cyclonedx

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/xeipuuv/gojsonschema"
)

// Schema references must be satisfied by the vendored fixtures. An unexpected
// reference fails locally instead of making the test depend on network access.
type offlineSchemaReference struct{ gojsonschema.JSONLoader }

func (r offlineSchemaReference) LoadJSON() (interface{}, error) {
	return nil, fmt.Errorf("unregistered offline schema reference: %v", r.JsonSource())
}

func (offlineSchemaReference) LoaderFactory() gojsonschema.JSONLoaderFactory {
	return offlineSchemaFactory{}
}

type offlineSchemaFactory struct{}

func (offlineSchemaFactory) New(source string) gojsonschema.JSONLoader {
	return offlineSchemaReference{gojsonschema.NewReferenceLoader(source)}
}

func officialCycloneDX16Schema(t *testing.T) *gojsonschema.Schema {
	t.Helper()
	manifestBytes, err := os.ReadFile("testdata/schema/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest []struct {
		File   string `json:"file"`
		ID     string `json:"id"`
		SHA256 string `json:"sha256"`
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	loader := gojsonschema.NewSchemaLoader()
	for _, entry := range manifest {
		data, err := os.ReadFile(filepath.Join("testdata/schema", entry.File))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != entry.SHA256 {
			t.Fatalf("official schema fixture %s changed: SHA256 = %s, want %s", entry.File, got, entry.SHA256)
		}
		if err := loader.AddSchema(entry.ID, gojsonschema.NewBytesLoader(data)); err != nil {
			t.Fatalf("register %s: %v", entry.File, err)
		}
	}
	schema, err := loader.Compile(offlineSchemaFactory{}.New("http://cyclonedx.org/schema/bom-1.6.schema.json"))
	if err != nil {
		t.Fatalf("compile official CycloneDX 1.6 schema: %v", err)
	}
	return schema
}

func schemaGraphFixture(t *testing.T) (ftypes.CustomResource, []libtreeGraphNode) {
	t.Helper()
	const root = "/usr/bin/appA"
	graph := []libtreeGraphNode{
		{ID: root, Name: "appA", Path: root, Kind: "application", Status: "resolved", DependsOn: []string{"leaf", "missing"}},
		{ID: "leaf", Name: "libresolved.so", Path: "/usr/lib/libresolved.so", Kind: "library", Status: "resolved", DependsOn: []string{}},
		{ID: "missing", Name: "libmissing.so", Kind: "library", Status: "missing", Reason: "dependency not found in target filesystem", DependsOn: []string{}},
	}
	return recursiveGraphResource(t, "usr/bin/appA", graph), graph
}

func TestWriterOfficialCycloneDX16Schema(t *testing.T) {
	schema := officialCycloneDX16Schema(t)
	graphResource, graph := schemaGraphFixture(t)
	confirmed, confirmedFragment := binaryReportFixture(t, "appA", "affected")
	candidate, candidateFragment := binaryReportFixture(t, "appB", "candidate")
	blintFragment := confirmedFragment
	blintFragment.Type = ftypes.CustomResourceCycloneDXBomBlint
	tests := []struct {
		name         string
		results      types.Results
		resources    []ftypes.CustomResource
		includeGraph bool
		wantGraph    bool
		wantFindings int
	}{
		{name: "empty report"},
		{name: "empty report with libtree enabled", includeGraph: true},
		{name: "recursive graph", resources: []ftypes.CustomResource{graphResource}, includeGraph: true, wantGraph: true},
		{name: "recursive graph disabled", resources: []ftypes.CustomResource{graphResource}},
		{name: "confirmed binary finding", results: types.Results{confirmed}, resources: []ftypes.CustomResource{confirmedFragment}, wantFindings: 1},
		{name: "candidate binary finding", results: types.Results{candidate}, resources: []ftypes.CustomResource{candidateFragment}, wantFindings: 1},
		{name: "both generators and recursive graph", results: types.Results{confirmed, candidate}, resources: []ftypes.CustomResource{confirmedFragment, blintFragment, candidateFragment, graphResource}, includeGraph: true, wantGraph: true, wantFindings: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := append(types.Results{}, tt.results...)
			results = append(results, types.Result{Class: types.ClassCustom, CustomResources: tt.resources})
			report := types.Report{ArtifactName: "schema-test-image", ArtifactType: artifact.TypeContainerImage, Results: results}
			var out bytes.Buffer
			if err := NewWriter(&out, "test", tt.includeGraph).Write(context.Background(), report); err != nil {
				t.Fatal(err)
			}
			// Validate the original output, since decoding into cdx.BOM would hide
			// unknown top-level properties such as the former "libtree" extension.
			validation, err := schema.Validate(gojsonschema.NewBytesLoader(out.Bytes()))
			if err != nil {
				t.Fatal(err)
			}
			for _, problem := range validation.Errors() {
				t.Errorf("official CycloneDX 1.6 schema: %s", problem)
			}
			var raw map[string]json.RawMessage
			if err := json.Unmarshal(out.Bytes(), &raw); err != nil {
				t.Fatal(err)
			}
			if _, exists := raw["libtree"]; exists {
				t.Error("nonstandard top-level libtree field was emitted")
			}
			if bytes.Equal(bytes.TrimSpace(raw["vulnerabilities"]), []byte("null")) {
				t.Error("vulnerabilities must be an array or omitted, never null")
			}
			var bom cdx.BOM
			if err := json.Unmarshal(out.Bytes(), &bom); err != nil {
				t.Fatal(err)
			}
			assertBinaryReferences(t, bom)
			findings := 0
			if bom.Vulnerabilities != nil {
				findings = len(*bom.Vulnerabilities)
			}
			if findings != tt.wantFindings {
				t.Fatalf("vulnerability count = %d, want %d", findings, tt.wantFindings)
			}
			components := map[string]cdx.Component{}
			if bom.Components != nil {
				for _, component := range *bom.Components {
					if id := graphProperties(component)["bolt:libtree:node-id"]; id != "" {
						components[id] = component
					}
				}
			}
			if !tt.wantGraph {
				if len(components) != 0 {
					t.Fatal("disabled or absent recursive graph introduced components")
				}
				return
			}
			if len(components) != len(graph) {
				t.Fatalf("graph component count = %d, want %d", len(components), len(graph))
			}
			for _, node := range graph {
				props := graphProperties(components[node.ID])
				if props["bolt:libtree:status"] != node.Status || props["bolt:libtree:path"] != node.Path || props["bolt:libtree:reason"] != node.Reason {
					t.Errorf("node %q lost resolver evidence: %v", node.ID, props)
				}
			}
			dependencies := map[string]cdx.Dependency{}
			if bom.Dependencies != nil {
				for _, dependency := range *bom.Dependencies {
					dependencies[dependency.Ref] = dependency
				}
			}
			leaf, exists := dependencies[components["leaf"].BOMRef]
			if !exists || leaf.Dependencies == nil || len(*leaf.Dependencies) != 0 {
				t.Error("resolved leaf must explicitly declare dependsOn: []")
			}
			if _, exists := dependencies[components["missing"].BOMRef]; exists {
				t.Error("an unresolved library must not assert that it has no dependencies")
			}
			root := dependencies[components[graph[0].ID].BOMRef]
			if root.Dependencies == nil {
				t.Fatal("recursive root has no standard dependencies")
			}
			for _, child := range []string{"leaf", "missing"} {
				if !contains(*root.Dependencies, components[child].BOMRef) {
					t.Errorf("missing standard dependency edge to %s", child)
				}
			}
		})
	}
}

func TestOfficialCycloneDX16SchemaRejectsInvalidOutput(t *testing.T) {
	schema := officialCycloneDX16Schema(t)
	for name, body := range map[string]string{
		"top-level extension":     `{"bomFormat":"CycloneDX","specVersion":"1.6","libtree":[]}`,
		"null vulnerabilities":    `{"bomFormat":"CycloneDX","specVersion":"1.6","vulnerabilities":null}`,
		"invalid component":       `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library"}]}`,
		"invalid dependency":      `{"bomFormat":"CycloneDX","specVersion":"1.6","dependencies":[{"ref":"app","dependsOn":null}]}`,
		"invalid SPDX identifier": `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"test","licenses":[{"license":{"id":"NOT-A-LICENSE"}}]}]}`,
		"invalid timestamp":       `{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"timestamp":"not-a-timestamp"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			result, err := schema.Validate(gojsonschema.NewStringLoader(body))
			if err != nil {
				t.Fatal(err)
			}
			if result.Valid() {
				t.Fatal("official schema accepted invalid output")
			}
		})
	}
}
