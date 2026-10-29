package cyclonedx

import (
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	"github.com/aquasecurity/trivy/pkg/sbom/cyclonedx"
	"github.com/aquasecurity/trivy/pkg/types"
)

// PropertyComponentGroup labels every component in the emitted BOM as an application
// component, a system component, or one the rules could not place.
//
// CycloneDX designates "properties" as the extension point for data the standard does
// not model, so the label lives there rather than in "group" (already carrying maven
// groupIds and npm scopes) or "scope" (a required/optional/excluded enum). The name is
// namespaced because an un-namespaced property can collide with another tool's.
const PropertyComponentGroup = "bolt:component:group"

const (
	// GroupApp marks a component that belongs to the application: language packages and
	// the third-party OSS a binary bundles.
	GroupApp = "app-cmp"
	// GroupSys marks a component that belongs to the underlying system: OS packages and
	// the shared libraries a binary links against.
	GroupSys = "sys-cmp"
	// GroupUnknown marks a component no rule placed on either side.
	//
	// It is deliberately not GroupSys. Labelling an unclassified component a system
	// component asserts something the rules never established, and it left a consumer
	// unable to tell a deb package from the container image root or from a purl type
	// this file has never heard of. Both now carry their own label.
	GroupUnknown = "unknown-cmp"
)

// propertyMetadata names the generator that contributed a component. Written by
// customResourceSource, read back here to classify what the binary SBOM generators found.
const propertyMetadata = "metadata"

// propertyTrivyClass is the result class Trivy records on the aggregate node of each
// result, e.g. "aquasecurity:trivy:Class".
const propertyTrivyClass = cyclonedx.Namespace + core.PropertyClass

// purlTypeFile identifies runtime libraries. BLint and legacy graphs use sonames
// such as "pkg:file/libc.so.6"; recursive libtree graphs use the resolved file path,
// e.g. "pkg:file/usr/lib/libc.so.6". Missing graph nodes carry no file PURL.
const purlTypeFile = "file"

// appPurlTypes are the purl types of language ecosystems. A component published to one
// of these belongs to the application.
//
// Every ecosystem Trivy can emit must be listed here, otherwise its packages fall through
// to the system default: conda, gradle and julia are here because pkg/purl emits them, not
// because a binary SBOM generator produces them. An ecosystem added to Trivy later and not
// added here is silently classified as a system component.
var appPurlTypes = map[string]struct{}{
	"npm": {}, "pypi": {}, "maven": {}, "gem": {}, "cargo": {},
	"golang": {}, "nuget": {}, "composer": {}, "hex": {}, "swift": {},
	"cocoapods": {}, "conan": {}, "hackage": {}, "pub": {}, "cran": {},
	"bitnami": {}, "conda": {}, "gradle": {}, "julia": {},
}

// sysPurlTypes are the purl types of OS package managers.
//
// "alpine" never appears in practice -- Trivy emits apk packages as pkg:apk/alpine/...
// (see pkg/purl/purl.go) -- but matching it costs nothing and guards against a fragment
// from some other tool that uses it.
var sysPurlTypes = map[string]struct{}{
	"deb": {}, "rpm": {}, "apk": {}, "alpine": {},
}

// purlType returns the type segment of a purl, e.g. "golang" for
// "pkg:golang/github.com/foo/bar@v1.0.0", or "" when the string is not a purl.
func purlType(purl string) string {
	p := strings.ToLower(strings.TrimSpace(purl))
	if !strings.HasPrefix(p, "pkg:") {
		return ""
	}
	p = strings.TrimPrefix(p, "pkg:")
	i := strings.IndexByte(p, '/')
	if i < 0 {
		return ""
	}
	return p[:i]
}

// componentProperties returns the component's properties, or nil when it has none.
func componentProperties(component cdx.Component) []cdx.Property {
	if component.Properties == nil {
		return nil
	}
	return *component.Properties
}

// classifyComponent decides whether a component is an application component, a system
// component, or neither.
//
// The rules are ordered and the first match wins:
//
//  0. resolved libtree library root with generic/no PURL -> sys
//  1. purl pkg:file/                  -> sys
//  2. purl of a language ecosystem    -> app
//  3. purl of an OS package manager   -> sys
//  4. binary generator tag or resolved libtree application root -> app
//  5. trivy Class lang-pkgs           -> app
//  6. trivy Class os-pkgs             -> sys
//  7. anything else                   -> unknown
//
// Rule 0 uses the scanned ELF's kind to refine a generic generator root. It
// excludes bundled components and preserves the ecosystem-specific rules.
// The order carries as much weight as the rules themselves:
//
// Rules 1-3 come before rule 4 deliberately. A system library BLint reported
// (pkg:file/libc.so.6) also carries the bom_blint tag, so rule 4 would otherwise call it
// an application component; and a Go dependency BLint found should be classified on the
// strength of its purl, not on which tool happened to see it.
//
// Rule 4 catches what the binary SBOM generators found without a usable purl. bin-sbom
// emits everything as pkg:generic/<name>, so without this rule every library it detects --
// hiredis, lua, ziparchive -- would fall through to rule 7, which is the opposite of what
// it exists to find. Matching pkg:generic/ directly would be wrong: that type means
// "ecosystem unknown" and is not exclusive to bin-sbom. Rule 4 also covers the scanned
// binary's own application root component. A resolved
// application root from libtree is also known even when binary SBOM engines are
// disabled; unresolved graph nodes do not satisfy that condition.
//
// Rules 5-6 come last because the Class property only appears on the aggregate node of
// each result, never on individual packages -- those already matched by purl above.
//
// Rule 7 reports that no rule applied rather than quietly defaulting to the system side.
// It takes in the container image or filesystem root, a purl whose type is in neither
// table above, a result node whose Class is neither lang-pkgs nor os-pkgs, and anything
// carrying neither a purl nor properties. The operating-system node is not among them: it
// is the result node for os-pkgs, so it matches rule 6.
func classifyComponent(component cdx.Component) string {
	t := purlType(component.PackageURL)
	props := componentProperties(component)
	// A generic generator identity does not determine the scanned ELF's role.
	// Limit this refinement to the resolved subject root, not packages bundled
	// in that binary or libraries identified by an ecosystem-specific PURL.
	if component.Type == cdx.ComponentTypeLibrary && (t == "" || t == "generic") {
		root, resolved, library := false, false, false
		for _, p := range props {
			switch p.Name {
			case "bolt:libtree:root":
				root = p.Value == "true"
			case "bolt:libtree:status":
				resolved = p.Value == "resolved"
			case "bolt:libtree:kind":
				library = p.Value == "library"
			}
		}
		if root && resolved && library {
			return GroupSys
		}
	}
	switch {
	case t == purlTypeFile:
		return GroupSys
	case has(appPurlTypes, t):
		return GroupApp
	case has(sysPurlTypes, t):
		return GroupSys
	}

	libtree, resolved := false, false
	for _, p := range props {
		if p.Name == "bolt:libtree:status" && p.Value == "resolved" {
			resolved = true
		}
		if p.Name != propertyMetadata {
			continue
		}
		if p.Value == sourceTagBinSBOM || p.Value == sourceTagBomBlint {
			return GroupApp
		}
		libtree = libtree || p.Value == sourceTagLibtree
	}
	if libtree && resolved && component.Type == cdx.ComponentTypeApplication {
		return GroupApp
	}

	for _, p := range props {
		if p.Name != propertyTrivyClass {
			continue
		}
		switch p.Value {
		case string(types.ClassLangPkg):
			return GroupApp
		case string(types.ClassOSPkg):
			return GroupSys
		}
	}

	return GroupUnknown
}

func has(set map[string]struct{}, key string) bool {
	if key == "" {
		return false
	}
	_, ok := set[key]
	return ok
}

// applyComponentGroups labels every component in the BOM, including the metadata
// component, which sits outside the components array.
//
// This runs once the BOM is complete -- after the Trivy components, the binary SBOM
// fragments and the libtree graph have all been merged -- so that a single pass sees
// every component exactly once.
func applyComponentGroups(bom *cdx.BOM) {
	if bom == nil {
		return
	}
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		setComponentGroup(bom.Metadata.Component)
	}
	if bom.Components == nil {
		return
	}
	for i := range *bom.Components {
		setComponentGroup(&(*bom.Components)[i])
	}
}

// setComponentGroup attaches the label to a component and its nested components.
//
// A component that already carries the property keeps the value it has: none of the
// generators emit this property, so finding one means the component came from an SBOM
// that had already been classified.
func setComponentGroup(component *cdx.Component) {
	if !hasComponentGroup(*component) {
		addProperties(component, []cdx.Property{
			{
				Name:  PropertyComponentGroup,
				Value: classifyComponent(*component),
			},
		})
	}

	if component.Components == nil {
		return
	}
	for i := range *component.Components {
		setComponentGroup(&(*component.Components)[i])
	}
}

func hasComponentGroup(component cdx.Component) bool {
	for _, p := range componentProperties(component) {
		if p.Name == PropertyComponentGroup {
			return true
		}
	}
	return false
}
