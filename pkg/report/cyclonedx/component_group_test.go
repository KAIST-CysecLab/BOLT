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

func property(name, value string) cdx.Property {
	return cdx.Property{Name: name, Value: value}
}

func TestClassifyComponent(t *testing.T) {
	tests := []struct {
		name      string
		component cdx.Component
		want      string
	}{
		{
			// Rule 1 must win over rule 4: libc is supplied by the loader, not bundled by
			// the application, even though BLint is what reported it.
			name: "soname purl beats generator tag",
			component: cdx.Component{
				Type:       cdx.ComponentTypeLibrary,
				Name:       "libc.so.6",
				PackageURL: "pkg:file/libc.so.6",
				Properties: &[]cdx.Property{property(propertyMetadata, sourceTagBomBlint)},
			},
			want: GroupSys,
		},
		{
			// Rule 2 must win over rule 4, so the purl is the recorded reason.
			name: "ecosystem purl beats generator tag",
			component: cdx.Component{
				Type:       cdx.ComponentTypeLibrary,
				Name:       "github.com/foo/bar",
				PackageURL: "pkg:golang/github.com/foo/bar@v1.0.0",
				Properties: &[]cdx.Property{property(propertyMetadata, sourceTagBomBlint)},
			},
			want: GroupApp,
		},
		{
			name: "language package",
			component: cdx.Component{
				Type:       cdx.ComponentTypeLibrary,
				Name:       "lodash",
				PackageURL: "pkg:npm/lodash@4.17.21",
			},
			want: GroupApp,
		},
		{
			name: "purl type is matched case-insensitively",
			component: cdx.Component{
				Type:       cdx.ComponentTypeLibrary,
				Name:       "lodash",
				PackageURL: "PKG:NPM/lodash@4.17.21",
			},
			want: GroupApp,
		},
		{
			// Trivy emits pkg:conda for conda packages, so the ecosystem has to be listed
			// or every conda package is classified as a system component.
			name: "conda package",
			component: cdx.Component{
				Type:       cdx.ComponentTypeLibrary,
				Name:       "openssl",
				PackageURL: "pkg:conda/openssl@1.1.1q",
			},
			want: GroupApp,
		},
		{
			name: "julia package",
			component: cdx.Component{
				Type:       cdx.ComponentTypeLibrary,
				Name:       "Example",
				PackageURL: "pkg:julia/Example@1.0.0",
			},
			want: GroupApp,
		},
		{
			name: "apk package",
			component: cdx.Component{
				Type:       cdx.ComponentTypeLibrary,
				Name:       "zlib",
				PackageURL: "pkg:apk/alpine/zlib@1.3.1-r0",
			},
			want: GroupSys,
		},
		{
			name: "deb package",
			component: cdx.Component{
				Type:       cdx.ComponentTypeLibrary,
				Name:       "libssl3",
				PackageURL: "pkg:deb/debian/libssl3@3.0.11-1",
			},
			want: GroupSys,
		},
		{
			// Rule 4. bin-sbom emits pkg:generic for everything it detects, so the tag is
			// the only thing that distinguishes bundled OSS from the system default.
			name: "bundled OSS found by bin-sbom",
			component: cdx.Component{
				Type:       cdx.ComponentTypeLibrary,
				Name:       "hiredis",
				PackageURL: "pkg:generic/hiredis@1.2.0",
				Properties: &[]cdx.Property{property(propertyMetadata, sourceTagBinSBOM)},
			},
			want: GroupApp,
		},
		{
			name: "scanned binary root",
			component: cdx.Component{
				Type:       cdx.ComponentTypeApplication,
				Name:       "redis-server",
				Properties: &[]cdx.Property{property(propertyMetadata, sourceTagBinSBOM)},
			},
			want: GroupApp,
		},
		{
			// A libtree node carries its own tag but resolves to a soname, so rule 1 holds.
			name: "libtree node",
			component: cdx.Component{
				Type:       cdx.ComponentTypeLibrary,
				Name:       "libfoo.so.1",
				PackageURL: "pkg:file/libfoo.so.1",
				Properties: &[]cdx.Property{property(propertyMetadata, sourceTagLibtree)},
			},
			want: GroupSys,
		},
		{
			name: "resolved libtree root without binary generator",
			component: cdx.Component{
				Type: cdx.ComponentTypeApplication, Name: "app",
				Properties: &[]cdx.Property{
					property(propertyMetadata, sourceTagLibtree), property("bolt:libtree:status", "resolved"),
				},
			},
			want: GroupApp,
		},
		{
			name: "unresolved libtree root is unknown",
			component: cdx.Component{
				Type: cdx.ComponentTypeApplication, Name: "app",
				Properties: &[]cdx.Property{
					property(propertyMetadata, sourceTagLibtree), property("bolt:libtree:status", "missing"),
				},
			},
			want: GroupUnknown,
		},
		{
			name: "lang-pkgs aggregate node",
			component: cdx.Component{
				Type:       cdx.ComponentTypeApplication,
				Name:       "Node.js",
				Properties: &[]cdx.Property{property(propertyTrivyClass, string(types.ClassLangPkg))},
			},
			want: GroupApp,
		},
		{
			name: "os-pkgs aggregate node",
			component: cdx.Component{
				Type:       cdx.ComponentTypeOS,
				Name:       "alpine",
				Properties: &[]cdx.Property{property(propertyTrivyClass, string(types.ClassOSPkg))},
			},
			want: GroupSys,
		},
		{
			// Rule 7. The image root is not a package at all, so neither side was
			// established and the label has to say so rather than claim "system".
			name: "neither purl nor properties is unknown",
			component: cdx.Component{
				Type: cdx.ComponentTypeContainer,
				Name: "test-image",
			},
			want: GroupUnknown,
		},
		{
			// pkg:generic means "ecosystem unknown". Without a generator tag to place it
			// (rule 4), nothing distinguishes it from a type this file has never seen.
			name: "unmatched purl type is unknown",
			component: cdx.Component{
				Type:       cdx.ComponentTypeLibrary,
				Name:       "mystery",
				PackageURL: "pkg:generic/mystery@1.0",
			},
			want: GroupUnknown,
		},
		{
			// A result node of some other class carries the Class property but matches
			// neither rule 5 nor rule 6, so it falls through.
			name: "result node of an unhandled class is unknown",
			component: cdx.Component{
				Type:       cdx.ComponentTypeApplication,
				Name:       "target_binaries/binA",
				Properties: &[]cdx.Property{property(propertyTrivyClass, string(types.ClassCustom))},
			},
			want: GroupUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyComponent(tt.component); got != tt.want {
				t.Fatalf("classifyComponent() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSetComponentGroupKeepsExistingLabel(t *testing.T) {
	component := cdx.Component{
		Type:       cdx.ComponentTypeLibrary,
		Name:       "zlib",
		PackageURL: "pkg:apk/alpine/zlib@1.3.1-r0",
		Properties: &[]cdx.Property{property(PropertyComponentGroup, GroupApp)},
	}

	setComponentGroup(&component)

	if got := groupLabels(*component.Properties); !sameStrings(got, []string{GroupApp}) {
		t.Fatalf("labels = %#v, want exactly one pre-existing %q", got, GroupApp)
	}
}

func TestSetComponentGroupLabelsNestedComponents(t *testing.T) {
	component := cdx.Component{
		Type: cdx.ComponentTypeApplication,
		Name: "parent",
		Components: &[]cdx.Component{
			{
				Type:       cdx.ComponentTypeLibrary,
				Name:       "lodash",
				PackageURL: "pkg:npm/lodash@4.17.21",
			},
		},
	}

	setComponentGroup(&component)

	nested := (*component.Components)[0]
	if got := groupLabels(*nested.Properties); !sameStrings(got, []string{GroupApp}) {
		t.Fatalf("nested labels = %#v, want [%s]", got, GroupApp)
	}
}

func groupLabels(props []cdx.Property) []string {
	var labels []string
	for _, p := range props {
		if p.Name == PropertyComponentGroup {
			labels = append(labels, p.Value)
		}
	}
	return labels
}

// groupComponent mirrors just enough of a CycloneDX component to read the label back out
// of an emitted document.
type groupComponent struct {
	BOMRef     string `json:"bom-ref"`
	Name       string `json:"name"`
	Properties []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"properties"`
}

type groupDoc struct {
	Metadata struct {
		Component groupComponent `json:"component"`
	} `json:"metadata"`
	Components []groupComponent `json:"components"`
}

func (c groupComponent) group(t *testing.T) string {
	t.Helper()

	var found []string
	for _, p := range c.Properties {
		if p.Name == PropertyComponentGroup {
			found = append(found, p.Value)
		}
	}
	if len(found) != 1 {
		t.Fatalf("component %q has %d %s properties, want exactly 1", c.BOMRef, len(found), PropertyComponentGroup)
	}
	return found[0]
}

func (d groupDoc) component(t *testing.T, bomRef string) groupComponent {
	t.Helper()

	for _, c := range d.Components {
		if c.BOMRef == bomRef {
			return c
		}
	}
	t.Fatalf("component %q not found in emitted document", bomRef)
	return groupComponent{}
}

// TestWriterLabelsEveryComponent checks the label end to end, including the metadata
// component, which lives outside the components array.
func TestWriterLabelsEveryComponent(t *testing.T) {
	libtree := []byte(`[
		{"name":"binA","dependsOn":["libfoo.so.1"]},
		{"name":"libfoo.so.1","dependsOn":[]}
	]`)

	report := types.Report{
		ArtifactName: "test-image",
		ArtifactType: artifact.TypeContainerImage,
		Results: types.Results{
			{
				Target: "target_binaries/binA",
				Class:  types.ClassCustom,
				CustomResources: []ftypes.CustomResource{
					{
						Type:     ftypes.CustomResourceCycloneDXBinSBOM,
						FilePath: "target_binaries/binA",
						Data:     []byte(binSBOMFragment),
					},
					{
						Type:     "libtree",
						FilePath: "target_binaries/binA",
						Data:     libtree,
					},
				},
			},
		},
	}

	var out bytes.Buffer
	if err := NewWriter(&out, "test", true).Write(context.Background(), report); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	var doc groupDoc
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal output: %v\n%s", err, out.String())
	}

	// The container image root is not a package, so no rule places it on either side.
	if got := doc.Metadata.Component.group(t); got != GroupUnknown {
		t.Errorf("image root group = %q, want %q", got, GroupUnknown)
	}

	want := map[string]string{
		"app:binA":             GroupApp, // scanned binary: the application itself
		"lib:zlib@1.3.2":       GroupApp, // bundled OSS, pkg:generic + bin_sbom tag
		"pkg:file/libfoo.so.1": GroupSys, // libtree node resolved by soname
	}
	for bomRef, wantGroup := range want {
		if got := doc.component(t, bomRef).group(t); got != wantGroup {
			t.Errorf("%s group = %q, want %q", bomRef, got, wantGroup)
		}
	}

	// Nothing may be left unlabelled.
	for _, c := range doc.Components {
		c.group(t)
	}
}
