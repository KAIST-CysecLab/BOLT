package cyclonedx

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

// Reduced from a real bom_blint result for an ET_DYN shared library. Metadata
// called the subject an application and supplied a generic PURL. Resolving its
// ELF must refine that root without relabeling the OSS packages it contains.
func TestWriterResolvedSharedLibraryRefinesBinaryGeneratorRoot(t *testing.T) {
	root := libtreeGraphNode{
		ID: "/apps/a/lib/libsame.so", Path: "/apps/a/lib/libsame.so", Name: "libsame.so",
		Status: "resolved", Kind: "library", DependsOn: []string{},
	}
	for _, combined := range []bool{false, true} {
		name := "bom-blint"
		if combined {
			name = "both generators"
		}
		t.Run(name, func(t *testing.T) {
			resources := []ftypes.CustomResource{
				recursiveGraphResource(t, "apps/a/lib/libsame.so", []libtreeGraphNode{root}),
				{Type: ftypes.CustomResourceCycloneDXBomBlint, FilePath: "apps/a/lib/libsame.so", Data: []byte(`{
                    "metadata":{"component":{"type":"application","name":"libsame.so","bom-ref":"root:blint","purl":"pkg:generic/libsame.so"}},
                    "components":[{"type":"library","name":"libsame.so","bom-ref":"package:bundled","purl":"pkg:generic/libsame.so@1.0"}],
                    "dependencies":[{"ref":"root:blint","dependsOn":["package:bundled"]}]
                }`)},
			}
			if combined {
				resources = append(resources, ftypes.CustomResource{
					Type: ftypes.CustomResourceCycloneDXBinSBOM, FilePath: "apps/a/lib/libsame.so", Data: []byte(`{
                        "metadata":{"component":{"type":"application","name":"libsame.so","bom-ref":"root:bin-sbom"}},
                        "components":[{"type":"library","name":"hiredis","bom-ref":"package:hiredis","purl":"pkg:generic/hiredis@1.0"}],
                        "dependencies":[{"ref":"root:bin-sbom","dependsOn":["package:hiredis"]}]
                    }`),
				})
			}
			doc := renderRecursiveLibtree(t, resources, true)
			component := graphComponents(doc)[root.ID]
			if component.BOMRef != "root:blint" || component.PackageURL != "pkg:generic/libsame.so" || component.Type != cdx.ComponentTypeLibrary ||
				graphProperties(component)[PropertyComponentGroup] != GroupSys {
				t.Fatalf("ELF kind must refine the root while preserving its identity: %#v", component)
			}
			var bundled int
			for _, component := range *doc.Components {
				if component.BOMRef == "package:bundled" || component.BOMRef == "package:hiredis" {
					bundled++
					if graphProperties(component)[PropertyComponentGroup] != GroupApp || graphProperties(component)["bolt:libtree:root"] != "" {
						t.Fatalf("bundled package was mistaken for the subject ELF: %#v", component)
					}
				}
			}
			wantBundled := 1
			if combined {
				wantBundled = 2
			}
			if bundled != wantBundled || len(graphDependencies(doc)[component.BOMRef]) != wantBundled {
				t.Fatalf("combined inventory or root dependencies were lost: %#v", doc)
			}
		})
	}
}
