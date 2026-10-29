package cyclonedx

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	sbomcdx "github.com/aquasecurity/trivy/pkg/sbom/cyclonedx"
	"github.com/aquasecurity/trivy/pkg/types"
)

const binaryAssessmentProperty = "bolt:binary:assessment"

// inheritBinaryProperties propagates file metadata without copying the parent's
// component identity or vulnerability assessment onto a different component.
func inheritBinaryProperties(component *cdx.Component, parent *cdx.Component) {
	if parent == nil || parent.Properties == nil {
		return
	}
	var properties []cdx.Property
	for _, property := range *parent.Properties {
		if !strings.HasPrefix(property.Name, "bolt:binary:") {
			properties = append(properties, property)
		}
	}
	if len(properties) == 0 {
		return
	}
	if component.Properties == nil {
		component.Properties = &properties
		return
	}
	*component.Properties = append(*component.Properties, properties...)
}

// upsertBinaryComponent enriches scanner packages with the generator's original
// component. Identity is the scoped bom-ref, never name/version or an unscoped purl.
func upsertBinaryComponent(components *[]cdx.Component, indices map[string]int, incoming cdx.Component) int {
	ref := componentRef(incoming)
	if ref != "" {
		incoming.BOMRef = ref
		if i, ok := indices[ref]; ok {
			existing := &(*components)[i]
			// Generated package components contain useful source and scanner fields;
			// retain those when the fragment does not provide a replacement.
			if incoming.Group == "" {
				incoming.Group = existing.Group
			}
			if incoming.Version == "" {
				incoming.Version = existing.Version
			}
			if incoming.PackageURL == "" {
				incoming.PackageURL = existing.PackageURL
			}
			if incoming.Supplier == nil {
				incoming.Supplier = existing.Supplier
			}
			if incoming.Hashes == nil {
				incoming.Hashes = existing.Hashes
			}
			if incoming.Licenses == nil {
				incoming.Licenses = existing.Licenses
			}
			if incoming.Evidence == nil {
				incoming.Evidence = existing.Evidence
			}
			if incoming.ExternalReferences == nil {
				incoming.ExternalReferences = existing.ExternalReferences
			}
			if existing.Properties != nil {
				addProperties(&incoming, *existing.Properties)
			}
			*existing = incoming
			return i
		}
	}
	*components = append(*components, incoming)
	index := len(*components) - 1
	if ref != "" {
		indices[ref] = index
	}
	return index
}

// mergeBinaryApplicationRoots replaces the encoder's aggregate application node
// with the original binary root, retaining links from the scanned artifact.
func mergeBinaryApplicationRoots(bom *cdx.BOM, roots map[string]string) {
	if bom.Components == nil || len(roots) == 0 {
		return
	}
	renames := map[string]string{}
	rootIndices := map[string]int{}
	for i, component := range *bom.Components {
		rootIndices[componentRef(component)] = i
	}
	for _, component := range *bom.Components {
		to := roots[component.Name]
		from := componentRef(component)
		if to == "" || from == to || component.Type != cdx.ComponentTypeApplication || component.Properties == nil {
			continue
		}
		binary, lang := false, false
		for _, p := range *component.Properties {
			binary = binary || (p.Name == sbomcdx.Namespace+core.PropertyType && p.Value == "binary")
			lang = lang || (p.Name == propertyTrivyClass && p.Value == string(types.ClassLangPkg))
		}
		if i, ok := rootIndices[to]; ok && binary && lang {
			renames[from] = to
			addProperties(&(*bom.Components)[i], *component.Properties)
		}
	}
	if len(renames) == 0 {
		return
	}
	components := make([]cdx.Component, 0, len(*bom.Components))
	for _, component := range *bom.Components {
		if _, remove := renames[componentRef(component)]; !remove {
			components = append(components, component)
		}
	}
	bom.Components = &components
	if bom.Dependencies != nil {
		var dependencies []cdx.Dependency
		for _, dep := range *bom.Dependencies {
			if to := renames[dep.Ref]; to != "" {
				dep.Ref = to
			}
			if dep.Dependencies != nil {
				refs := newOrderedStringSet()
				for _, ref := range *dep.Dependencies {
					if to := renames[ref]; to != "" {
						ref = to
					}
					if ref != dep.Ref {
						refs.Add(ref)
					}
				}
				values := refs.Values()
				dep.Dependencies = &values
			}
			dependencies = mergeDependencyEntry(dependencies, dep)
		}
		bom.Dependencies = &dependencies
	}
	if bom.Vulnerabilities != nil {
		for i := range *bom.Vulnerabilities {
			if (*bom.Vulnerabilities)[i].Affects == nil {
				continue
			}
			for j := range *(*bom.Vulnerabilities)[i].Affects {
				affects := &(*(*bom.Vulnerabilities)[i].Affects)[j]
				if to := renames[affects.Ref]; to != "" {
					affects.Ref = to
				}
			}
		}
	}
}

// applyBinaryAssessments uses the already filtered scanner findings. Fragment
// vulnerabilities are deliberately not imported, as that would bypass filtering.
func applyBinaryAssessments(bom *cdx.BOM, results types.Results) {
	if bom.Vulnerabilities == nil {
		return
	}
	type findingKey struct{ id, ref string }
	candidates := map[findingKey]bool{}
	recommendations := map[string]*orderedStringSet{}
	for _, result := range results {
		for _, finding := range result.Vulnerabilities {
			var assessment string
			if result.Type == "binary" {
				switch custom := finding.Custom.(type) {
				case map[string]any:
					assessment, _ = custom[binaryAssessmentProperty].(string)
				case map[string]string:
					assessment = custom[binaryAssessmentProperty]
				}
			}
			key := findingKey{finding.VulnerabilityID, finding.PkgIdentifier.BOMRef}
			if assessment == "candidate" {
				candidates[key] = true
			} else if finding.FixedVersion != "" {
				if recommendations[finding.VulnerabilityID] == nil {
					recommendations[finding.VulnerabilityID] = newOrderedStringSet()
				}
				recommendations[finding.VulnerabilityID].Add(fmt.Sprintf("Upgrade %s to version %s", finding.PkgName, finding.FixedVersion))
			}
		}
	}
	// A pointer to a nil slice serializes as null, which is not a CycloneDX
	// vulnerabilities array. Preserve an empty array when there are no findings.
	vulnerabilities := make([]cdx.Vulnerability, 0, len(*bom.Vulnerabilities))
	for _, vulnerability := range *bom.Vulnerabilities {
		if vulnerability.Affects == nil {
			vulnerabilities = append(vulnerabilities, vulnerability)
			continue
		}
		var confirmed, uncertain []cdx.Affects
		seen := map[string]bool{}
		for _, affects := range *vulnerability.Affects {
			if candidates[findingKey{vulnerability.ID, affects.Ref}] {
				if !seen[affects.Ref] {
					// No installed version has been established. Do not copy a
					// reference-release version into an affected-version assertion.
					affects.Range = &[]cdx.AffectedVersions{{Range: "vers:generic/*", Status: cdx.VulnerabilityStatusUnknown}}
					uncertain = append(uncertain, affects)
					seen[affects.Ref] = true
				}
			} else if !seen[affects.Ref] {
				confirmed = append(confirmed, affects)
				seen[affects.Ref] = true
			}
		}
		if len(confirmed) != 0 {
			v := vulnerability
			v.Affects = &confirmed
			if len(uncertain) != 0 {
				v.BOMRef = fmt.Sprintf("urn:bolt:vulnerability:affected:%x", sha256.Sum256([]byte(v.ID)))
				// The base marshaler aggregates upgrade advice across every
				// reference. Do not retain advice derived only from candidates.
				var values []string
				if recs := recommendations[v.ID]; recs != nil {
					values = recs.Values()
				}
				sort.Strings(values)
				v.Recommendation = strings.Join(values, "; ")
			}
			vulnerabilities = append(vulnerabilities, v)
		}
		if len(uncertain) != 0 {
			v := vulnerability
			v.BOMRef = fmt.Sprintf("urn:bolt:vulnerability:candidate:%x", sha256.Sum256([]byte(v.ID)))
			v.Affects = &uncertain
			v.Analysis = &cdx.VulnerabilityAnalysis{
				State:  cdx.IASInTriage,
				Detail: "The component was detected in a binary, but its installed version or applicability is unconfirmed. This is a vulnerability candidate requiring investigation.",
			}
			v.Recommendation = "Confirm the installed version and vulnerability applicability before choosing remediation."
			props := []cdx.Property{{Name: binaryAssessmentProperty, Value: "candidate"}}
			if v.Properties != nil {
				props = append(props, (*v.Properties)...)
			}
			v.Properties = &props
			vulnerabilities = append(vulnerabilities, v)
		}
	}
	sort.SliceStable(vulnerabilities, func(i, j int) bool {
		if vulnerabilities[i].ID != vulnerabilities[j].ID {
			return vulnerabilities[i].ID < vulnerabilities[j].ID
		}
		return vulnerabilities[i].BOMRef < vulnerabilities[j].BOMRef
	})
	bom.Vulnerabilities = &vulnerabilities
}
