// Modified by slyfizz on 2025-05-29: merged BLint components and dependencies into CycloneDX output
// Modified by slyfizz on 2025-06-26: fixed BLint CycloneDX parsing and dependency handling
// Modified by slyfizz on 2026-04-09: integrated libtree dependency data into CycloneDX output
// Modified by slyfizz on 2026-04-28: emitted libtree data as an ordered top-level graph
// Modified by slyfizz on 2026-07-23: made libtree output optional and merged dependency references
// Modified by KimSeoYe on 2026-08-06: merged bin-sbom fragments and tagged each component with the generator that produced it
// Modified by KimSeoYe on 2026-08-07: merged binary SBOM fragments in a stable generator order
// Modified by KimSeoYe on 2026-08-07: classified components into application and system groups
// Modified by slyfizz on 2026-09-23: retained binary component inventory and its vulnerability annotations
// Modified by slyfizz on 2026-10-13: emitted recursive ELF dependency components and graphs
// Modified by slyfizz on 2026-10-20: conformed the output to the official CycloneDX 1.6 schema

package cyclonedx

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/sbom/cyclonedx"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/package-url/packageurl-go"
	"golang.org/x/xerrors"
)

func contains(slice []string, target string) bool {
	for _, s := range slice {
		if s == target {
			return true
		}
	}
	return false
}

// Values of the "metadata" property, naming the generator a component came from.
const (
	sourceTagBinSBOM  = "bin_sbom"
	sourceTagBomBlint = "bom_blint"
	sourceTagLibtree  = "libtree"
)

// customResourceSource names the generator that produced a CycloneDX fragment. The
// value is attached to every component it contributed as a "metadata" property.
func customResourceSource(resourceType string) string {
	switch resourceType {
	case ftypes.CustomResourceCycloneDXBinSBOM:
		return sourceTagBinSBOM
	default:
		return sourceTagBomBlint
	}
}

// isBinarySBOMResource reports whether a CustomResource carries a CycloneDX fragment
// from one of the binary SBOM generators.
func isBinarySBOMResource(resourceType string) bool {
	return resourceType == ftypes.CustomResourceCycloneDXBomBlint ||
		resourceType == ftypes.CustomResourceCycloneDXBinSBOM
}

// binarySBOMResourceRank orders the generators so that, when several describe the same
// binary, the same one always wins its root component.
func binarySBOMResourceRank(resourceType string) int {
	if resourceType == ftypes.CustomResourceCycloneDXBinSBOM {
		return 1
	}
	return 0
}

// binarySBOMResources flattens the CycloneDX fragments out of the report in a stable
// order.
//
// The applier keys custom resources by file path and type in a map and rebuilds the
// slice by walking it, so the order fragments arrive in varies between runs. Merging in
// arrival order would let a different generator win the root component each time and
// make the emitted bom-refs unreproducible.
func binarySBOMResources(results types.Results) []ftypes.CustomResource {
	var resources []ftypes.CustomResource
	for _, res := range results {
		for _, cr := range res.CustomResources {
			if isBinarySBOMResource(cr.Type) {
				resources = append(resources, cr)
			}
		}
	}

	sort.SliceStable(resources, func(i, j int) bool {
		if resources[i].FilePath != resources[j].FilePath {
			return resources[i].FilePath < resources[j].FilePath
		}
		return binarySBOMResourceRank(resources[i].Type) < binarySBOMResourceRank(resources[j].Type)
	})
	return resources
}

type libtreeGraphNode struct {
	ID        string   `json:"id,omitempty"`
	Name      string   `json:"name"`
	Path      string   `json:"path,omitempty"`
	DependsOn []string `json:"dependsOn"`
	Status    string   `json:"status,omitempty"`
	Reason    string   `json:"reason,omitempty"`
	Kind      string   `json:"kind,omitempty"`
}

func (n libtreeGraphNode) key() string {
	if n.ID != "" {
		return "id:" + n.ID
	}
	return "name:" + n.Name
}

// CustomResource paths are relative to the scanned artifact, whereas resolver
// paths are absolute within it. Never resolve these paths against the host CWD.
func libtreeArtifactPath(path string) string {
	if path == "" {
		return ""
	}
	return filepath.ToSlash(filepath.Clean("/" + filepath.ToSlash(path)))
}

type orderedStringSet struct {
	values []string
	seen   map[string]struct{}
}

func newOrderedStringSet() *orderedStringSet {
	return &orderedStringSet{
		seen: map[string]struct{}{},
	}
}

func (s *orderedStringSet) Add(value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	if _, ok := s.seen[value]; ok {
		return
	}
	s.values = append(s.values, value)
	s.seen[value] = struct{}{}
}

func (s *orderedStringSet) AddAll(values []string) {
	for _, value := range values {
		s.Add(value)
	}
}

func (s *orderedStringSet) Values() []string {
	return append([]string{}, s.values...)
}

func componentRef(component cdx.Component) string {
	if strings.TrimSpace(component.BOMRef) != "" {
		return strings.TrimSpace(component.BOMRef)
	}
	// BLint normally uses the purl as the bom-ref. If bom-ref is absent, purl is
	// the only stable CycloneDX-ish reference available for dependency edges.
	return strings.TrimSpace(component.PackageURL)
}

func fileBOMRef(name string) string {
	return "pkg:file/" + name
}

func baseName(path string) string {
	if path == "" {
		return ""
	}
	return filepath.Base(path)
}

func mergeDependency(deps []cdx.Dependency, ref string, dependsOn []string) []cdx.Dependency {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return deps
	}

	merged := newOrderedStringSet()
	for i := range deps {
		if deps[i].Ref != ref {
			continue
		}
		if deps[i].Dependencies != nil {
			merged.AddAll(*deps[i].Dependencies)
		}
		merged.AddAll(dependsOn)
		values := merged.Values()
		deps[i].Dependencies = &values
		return deps
	}

	merged.AddAll(dependsOn)
	if len(merged.values) == 0 {
		return deps
	}
	values := merged.Values()
	return append(deps, cdx.Dependency{
		Ref:          ref,
		Dependencies: &values,
	})
}

// mergeDependencyEntry folds dep into deps, unioning dependsOn when an entry for the
// same ref already exists.
func mergeDependencyEntry(deps []cdx.Dependency, dep cdx.Dependency) []cdx.Dependency {
	for i := range deps {
		if deps[i].Ref != dep.Ref {
			continue
		}
		merged := newOrderedStringSet()
		if deps[i].Dependencies != nil {
			merged.AddAll(*deps[i].Dependencies)
		}
		if dep.Dependencies != nil {
			merged.AddAll(*dep.Dependencies)
		}
		values := merged.Values()
		deps[i].Dependencies = &values
		return deps
	}
	return append(deps, dep)
}

// renameDependencyRef rewrites references to from into to, both in the entry's own
// ref and in its dependsOn list.
func renameDependencyRef(dep cdx.Dependency, from, to string) cdx.Dependency {
	if from == "" || to == "" || from == to {
		return dep
	}
	if dep.Ref == from {
		dep.Ref = to
	}
	if dep.Dependencies != nil {
		renamed := make([]string, 0, len(*dep.Dependencies))
		for _, d := range *dep.Dependencies {
			if d == from {
				d = to
			}
			renamed = append(renamed, d)
		}
		dep.Dependencies = &renamed
	}
	return dep
}

// addProperties appends the properties a component does not already carry.
func addProperties(component *cdx.Component, props []cdx.Property) {
	if component.Properties == nil {
		component.Properties = &[]cdx.Property{}
	}
	existing := map[cdx.Property]struct{}{}
	for _, p := range *component.Properties {
		existing[p] = struct{}{}
	}
	for _, p := range props {
		if _, ok := existing[p]; ok {
			continue
		}
		*component.Properties = append(*component.Properties, p)
		existing[p] = struct{}{}
	}
}

func mergeLibtreeDirect(libtreeDirect map[string][]string, root string, dependsOn []string) {
	root = strings.TrimSpace(root)
	if root == "" {
		return
	}
	merged := newOrderedStringSet()
	merged.AddAll(libtreeDirect[root])
	merged.AddAll(dependsOn)
	libtreeDirect[root] = merged.Values()
}

func libtreeDirectRefs(libtreeDirect map[string][]string, candidates ...string) []string {
	refs := newOrderedStringSet()
	seenCandidates := newOrderedStringSet()
	for _, candidate := range candidates {
		seenCandidates.Add(candidate)
	}
	for _, candidate := range seenCandidates.Values() {
		for _, dep := range libtreeDirect[candidate] {
			refs.Add(fileBOMRef(dep))
		}
	}
	return refs.Values()
}

func libtreeNodeRef(name string, rootRefs map[string]string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	if ref := strings.TrimSpace(rootRefs[name]); ref != "" {
		return ref
	}
	return fileBOMRef(name)
}

func libtreeGraphNodeRef(node libtreeGraphNode, rootRefs map[string]string) string {
	if node.ID == "" {
		return libtreeNodeRef(node.Name, rootRefs)
	}
	if ref := rootRefs[node.key()]; ref != "" {
		return ref
	}
	// A file may be resolved differently under different executable roots. The
	// resolver ID includes this context, and remains distinct from any PURL.
	digest := sha256.Sum256([]byte(node.ID))
	return "urn:bolt:libtree:" + hex.EncodeToString(digest[:])
}

func libtreeNodeProperties(node libtreeGraphNode) []cdx.Property {
	props := []cdx.Property{{Name: propertyMetadata, Value: sourceTagLibtree}}
	for _, value := range []struct{ name, value string }{
		{"node-id", node.ID}, {"name", node.Name}, {"path", node.Path}, {"status", node.Status}, {"reason", node.Reason}, {"kind", node.Kind},
	} {
		if value.value != "" {
			props = append(props, cdx.Property{Name: "bolt:libtree:" + value.name, Value: value.value})
		}
	}
	return props
}

func componentRefs(components *[]cdx.Component) map[string]struct{} {
	refs := map[string]struct{}{}
	if components == nil {
		return refs
	}
	for _, component := range *components {
		if ref := componentRef(component); ref != "" {
			refs[ref] = struct{}{}
		}
	}
	return refs
}

func appendLibtreeComponents(components *[]cdx.Component, graph []libtreeGraphNode, rootRefs map[string]string, roots map[string]bool) []cdx.Component {
	existing := componentRefs(components)
	indices := make(map[string]int, len(existing))
	for i, component := range *components {
		indices[componentRef(component)] = i
	}
	added := []cdx.Component{}
	for _, node := range graph {
		ref := libtreeGraphNodeRef(node, rootRefs)
		if ref == "" {
			continue
		}
		props := libtreeNodeProperties(node)
		if roots[node.key()] {
			props = append(props, cdx.Property{Name: "bolt:libtree:root", Value: "true"})
		}
		if _, ok := existing[ref]; ok {
			component := &(*components)[indices[ref]]
			addProperties(component, props)
			if node.ID != "" {
				// Generators can label every scanned file an application. The
				// resolved ELF kind refines only that file's metadata root; its
				// identity and any third-party package components are retained.
				if roots[node.key()] && node.Status == "resolved" && node.Kind == "library" {
					component.Type = cdx.ComponentTypeLibrary
				}
			}
			continue
		}
		component := cdx.Component{
			BOMRef: ref,
			Type:   cdx.ComponentTypeLibrary,
			Name:   node.Name,
		}
		if roots[node.key()] && node.Kind != "library" {
			component.Type = cdx.ComponentTypeApplication
		}
		if node.ID == "" {
			component.PackageURL = ref // Legacy graphs identify libraries by soname.
		} else if component.Type == cdx.ComponentTypeLibrary && node.Status == "resolved" && node.Path != "" {
			component.PackageURL = packageurl.NewPackageURL("file", strings.Trim(filepath.ToSlash(filepath.Dir(node.Path)), "/"),
				filepath.Base(node.Path), "", nil, "").ToString()
		}
		addProperties(&component, props)
		indices[ref] = len(*components)
		*components = append(*components, component)
		added = append(added, component)
		existing[ref] = struct{}{}
	}
	return added
}

func mergeLibtreeGraphDependencies(deps []cdx.Dependency, graph []libtreeGraphNode, rootRefs map[string]string) []cdx.Dependency {
	for _, node := range graph {
		ref := libtreeGraphNodeRef(node, rootRefs)
		if ref == "" {
			continue
		}
		childRefs := newOrderedStringSet()
		for _, child := range node.DependsOn {
			if node.ID != "" {
				childRefs.Add(libtreeGraphNodeRef(libtreeGraphNode{ID: child}, rootRefs))
			} else {
				childRefs.Add(libtreeNodeRef(child, rootRefs))
			}
		}
		if node.Status == "resolved" {
			// An inspected ELF with no DT_NEEDED entries is a known leaf in
			// this graph. An absent dependency record means unknown, not empty.
			children := childRefs.Values()
			deps = mergeDependencyEntry(deps, cdx.Dependency{Ref: ref, Dependencies: &children})
		} else {
			// Missing/uninspected nodes must not claim to be dependency-free.
			deps = mergeDependency(deps, ref, childRefs.Values())
		}
	}
	return deps
}

// Writer implements types.Writer
type Writer struct {
	output         io.Writer
	format         cdx.BOMFileFormat
	includeLibtree bool
	marshaler      cyclonedx.Marshaler
}

func NewWriter(output io.Writer, appVersion string, includeLibtree bool) Writer {
	return Writer{
		output:         output,
		format:         cdx.BOMFileFormatJSON,
		includeLibtree: includeLibtree,
		marshaler:      cyclonedx.NewMarshaler(appVersion),
	}
}

func (w Writer) Write(ctx context.Context, report types.Report) error {
	// 1) Produce the base CycloneDX BOM
	bom, err := w.marshaler.MarshalReport(ctx, report)
	if err != nil {
		log.Debugf("err=%s", err)
		return xerrors.Errorf("CycloneDX marshal error: %w", err)
	}
	// 2) Prepare to strip any C-style comments from blint JSON
	reComments := regexp.MustCompile(`(?s)/\*.*?\*/`)
	// 3) Iterate all CustomResources and merge blint SBOM parts
	var libtreeGraph []libtreeGraphNode
	libtreeIndex := map[string]int{}
	libtreeDirect := map[string][]string{}
	libtreeRootRefs := map[string]string{}
	libtreeRoots := map[string]bool{}
	libtreeRootsByPath := map[string][]string{}

	if w.includeLibtree {
		for _, res := range report.Results {
			for _, cr := range res.CustomResources {
				if cr.Type != "libtree" {
					continue
				}

				var raw []byte
				switch v := cr.Data.(type) {
				case []byte:
					raw = v
				case string:
					decoded, err := base64.StdEncoding.DecodeString(v)
					if err == nil {
						raw = decoded
					} else {
						raw = []byte(v)
					}
				default:
					log.Warnf("Unknown libtree cr.Data type: %T", cr.Data)
					continue
				}

				var graph []libtreeGraphNode
				if err := json.Unmarshal(raw, &graph); err != nil {
					log.Warnf("Skipping malformed libtree graph: %v", err)
					continue
				}
				if len(graph) > 0 {
					root := graph[0]
					libtreeRoots[root.key()] = true
					if root.ID != "" {
						for _, path := range []string{root.ID, root.Path, cr.FilePath} {
							if path = libtreeArtifactPath(path); path != "" {
								libtreeRootsByPath[path] = append(libtreeRootsByPath[path], root.key())
							}
						}
					} else {
						mergeLibtreeDirect(libtreeDirect, root.Name, root.DependsOn)
						mergeLibtreeDirect(libtreeDirect, baseName(cr.FilePath), root.DependsOn)
					}
				}
				for _, node := range graph {
					idx, ok := libtreeIndex[node.key()]
					if !ok {
						libtreeIndex[node.key()] = len(libtreeGraph)
						node.DependsOn = append([]string{}, node.DependsOn...)
						libtreeGraph = append(libtreeGraph, node)
						continue
					}
					existing := map[string]struct{}{}
					for _, child := range libtreeGraph[idx].DependsOn {
						existing[child] = struct{}{}
					}
					for _, child := range node.DependsOn {
						if _, ok := existing[child]; ok {
							continue
						}
						libtreeGraph[idx].DependsOn = append(libtreeGraph[idx].DependsOn, child)
						existing[child] = struct{}{}
					}
					if libtreeGraph[idx].DependsOn == nil {
						libtreeGraph[idx].DependsOn = []string{}
					}
				}
			}
		}
	}

	if bom.Components == nil {
		bom.Components = &[]cdx.Component{}
	}
	if bom.Dependencies == nil {
		bom.Dependencies = &[]cdx.Dependency{}
	}
	// Several generators can contribute scanner packages for the same scoped
	// component. Keep one inventory entry before enriching it from the fragments.
	components := *bom.Components
	bom.Components = &[]cdx.Component{}
	componentIndices := map[string]int{}
	for _, component := range components {
		upsertBinaryComponent(bom.Components, componentIndices, component)
	}

	// Root component of each binary, keyed by the file it describes, as an index into
	// *bom.Components. Lets a second generator reporting the same file merge into the
	// root the first one published.
	binaryRoots := map[string]int{}
	binaryRootRefs := map[string]string{}

	for _, cr := range binarySBOMResources(report.Results) {
		sourceTag := customResourceSource(cr.Type)

		var raw []byte
		switch v := cr.Data.(type) {
		case []byte:
			raw = v
		case string:
			decoded, err := base64.StdEncoding.DecodeString(v)
			if err != nil {
				return xerrors.Errorf("base64 decode error: %w", err)
			}
			raw = decoded
		default:
			log.Warnf("Unknown cr.Data type: %T", cr.Data)
			continue
		}

		clean := reComments.ReplaceAll(raw, nil)

		var m map[string]json.RawMessage
		if err := json.Unmarshal(clean, &m); err != nil {
			log.Warnf("Skipping malformed custom CycloneDX fragment (%s): %v", sourceTag, err)
			continue
		}

		// Extract metadata.component as a base component
		var baseComponent *cdx.Component
		if metaJSON, found := m["metadata"]; found {
			var meta struct {
				Component *cdx.Component `json:"component"`
			}
			if err := json.Unmarshal(metaJSON, &meta); err != nil {
				return xerrors.Errorf("failed to parse metadata.component: %w", err)
			}
			if meta.Component != nil {
				baseComponent = meta.Component
				if baseComponent.Properties == nil {
					tmp := []cdx.Property{}
					baseComponent.Properties = &tmp
				}
				*baseComponent.Properties = append(*baseComponent.Properties, cdx.Property{
					Name:  propertyMetadata,
					Value: sourceTag,
				})
			}
		}

		// Initialize per-binary component and dependency storage
		binaryComponents := []cdx.Component{}
		binaryDependencies := []cdx.Dependency{}
		componentRefs := []string{}
		childRefs := []string{}

		// Extract and attach components
		if compsJSON, found := m["components"]; found {
			var comps []cdx.Component
			if err := json.Unmarshal(compsJSON, &comps); err != nil {
				return xerrors.Errorf("failed to parse %s components JSON: %w", sourceTag, err)
			}
			for i := range comps {
				if comps[i].Properties == nil {
					tmp := []cdx.Property{}
					comps[i].Properties = &tmp
				}
				*comps[i].Properties = append(*comps[i].Properties, cdx.Property{
					Name:  propertyMetadata,
					Value: sourceTag,
				})
				inheritBinaryProperties(&comps[i], baseComponent)
				if ref := componentRef(comps[i]); ref != "" {
					componentRefs = append(componentRefs, ref)
					childRefs = append(childRefs, ref)
				}
				binaryComponents = append(binaryComponents, comps[i])
			}
		}

		// The first generator to describe a binary owns its root component. A second
		// generator adds its source tag and children to that node instead of emitting
		// a rival application component for the same file.
		rootRef := ""
		ownRootRef := ""
		var pendingRoot *cdx.Component
		if baseComponent != nil {
			ownRootRef = componentRef(*baseComponent)
			if idx, ok := binaryRoots[cr.FilePath]; ok {
				rootRef = componentRef((*bom.Components)[idx])
				if baseComponent.Properties != nil {
					addProperties(&(*bom.Components)[idx], *baseComponent.Properties)
				}
			} else {
				rootRef = componentRef(*baseComponent)
				pendingRoot = baseComponent
			}
			if rootRef != "" {
				componentRefs = append(componentRefs, rootRef)
			}
		}

		// Extract and attach dependencies, scoped to the current binary
		if depsJSON, found := m["dependencies"]; found {
			var deps []cdx.Dependency
			if err := json.Unmarshal(depsJSON, &deps); err != nil {
				return xerrors.Errorf("failed to parse %s dependencies JSON: %w", sourceTag, err)
			}
			for _, dep := range deps {
				// This fragment's root may have been merged into one an earlier
				// generator published; point its edges at the surviving ref so they
				// do not resurface as a rival root.
				dep = renameDependencyRef(dep, ownRootRef, rootRef)
				if contains(componentRefs, dep.Ref) {
					binaryDependencies = append(binaryDependencies, dep)
					continue
				}

				// Try to extract DependsOn if exists
				var raw map[string]interface{}
				depJSON, _ := json.Marshal(dep)
				_ = json.Unmarshal(depJSON, &raw)

				if depsOn, ok := raw["dependsOn"].([]interface{}); ok {
					for _, d := range depsOn {
						if s, ok := d.(string); ok && contains(componentRefs, s) {
							binaryDependencies = append(binaryDependencies, dep)
							break
						}
					}
				}
			}
		}

		if rootRef != "" {
			binaryName := baseComponent.Name
			libtreeRootRefs[binaryName] = rootRef
			libtreeRootRefs[baseName(cr.FilePath)] = rootRef
			for _, key := range libtreeRootsByPath[libtreeArtifactPath(cr.FilePath)] {
				libtreeRootRefs[key] = rootRef
			}
			// Enrich the binary dependency edge without trying to align libtree
			// and generator components semantically. Dedup is by emitted
			// dependency ref: bom-ref first, falling back to purl when bom-ref
			// is absent. This preserves existing libtree/generator refs and avoids
			// duplicate pkg:file/<name> entries when both sources see the same
			// library.
			mergedRefs := newOrderedStringSet()
			mergedRefs.AddAll(libtreeDirectRefs(libtreeDirect, binaryName, baseName(cr.FilePath)))
			mergedRefs.AddAll(childRefs)
			binaryDependencies = mergeDependency(binaryDependencies, rootRef, mergedRefs.Values())
		}

		// Append per-binary metadata, components, and dependencies to the main BOM
		for _, component := range binaryComponents {
			upsertBinaryComponent(bom.Components, componentIndices, component)
		}
		if pendingRoot != nil {
			binaryRoots[cr.FilePath] = upsertBinaryComponent(bom.Components, componentIndices, *pendingRoot)
		}
		if rootRef != "" {
			binaryRootRefs[cr.FilePath] = rootRef
		}

		// Merge rather than append: when two generators report the same binary they
		// both emit an edge for its root ref, and CycloneDX allows only one.
		for _, dep := range binaryDependencies {
			*bom.Dependencies = mergeDependencyEntry(*bom.Dependencies, dep)
		}
	}
	mergeBinaryApplicationRoots(bom, binaryRootRefs)
	applyBinaryAssessments(bom, report.Results)

	if w.includeLibtree && len(libtreeGraph) != 0 {
		appendLibtreeComponents(bom.Components, libtreeGraph, libtreeRootRefs, libtreeRoots)
		*bom.Dependencies = mergeLibtreeGraphDependencies(*bom.Dependencies, libtreeGraph, libtreeRootRefs)
		if bom.Metadata != nil && bom.Metadata.Component != nil {
			artifactRef := componentRef(*bom.Metadata.Component)
			rootRefs := newOrderedStringSet()
			for _, node := range libtreeGraph {
				if ref := libtreeGraphNodeRef(node, libtreeRootRefs); libtreeRoots[node.key()] && ref != artifactRef {
					rootRefs.Add(ref)
				}
			}
			*bom.Dependencies = mergeDependency(*bom.Dependencies, artifactRef, rootRefs.Values())
		}
	}

	// Classify once the BOM is whole: every generator has merged in by this point, so a
	// single pass labels each component exactly once.
	applyComponentGroups(bom)

	// Recursive ELF metadata is preserved in component properties, and its
	// edges in dependencies. Keep the final document within the official schema.
	encoder := cdx.NewBOMEncoder(w.output, w.format)
	encoder.SetPretty(true)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(bom); err != nil {
		return xerrors.Errorf("failed to encode bom: %w", err)
	}

	return nil
}
