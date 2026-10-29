// Package binary connects binary SBOM fragments to the normal vulnerability
// result pipeline. It never changes an inventory identity into a guessed package.
package binary

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	version "github.com/aquasecurity/go-version/pkg/version"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/library"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/types"
)

const ResultType ftypes.TargetType = "binary"

type detector interface {
	GetAdvisories(string) ([]dbTypes.Advisory, error)
	DetectVulnerabilitiesFromAdvisories(string, string, string, []dbTypes.Advisory) ([]types.DetectedVulnerability, error)
}

type Scanner struct {
	newDriver func(ftypes.LangType) (detector, bool)
}

func NewScanner() *Scanner {
	return &Scanner{newDriver: func(kind ftypes.LangType) (detector, bool) {
		driver, ok := library.NewDriver(kind)
		return &driver, ok
	}}
}

type assessment struct {
	findings []types.DetectedVulnerability
	status   string
	reason   string
}

// Scan returns ordinary results so filling details, ignore/severity/VEX filters,
// JSON and CycloneDX all see the findings. Fragments remain the full inventory,
// including unsupported and unversioned components. Inputs are not mutated.
func (s *Scanner) Scan(ctx context.Context, resources []ftypes.CustomResource, opts types.ScanOptions) (types.Results, []ftypes.CustomResource, error) {
	updated := append([]ftypes.CustomResource(nil), resources...)
	requested := opts.Scanners.Enabled(types.VulnerabilityScanner) && slices.Contains(opts.PkgTypes, types.PkgTypeLibrary)
	notRequestedReason := "not-requested"
	// Binary inventory is attached directly to the subject binary. Respect the
	// same relationship selection as ordinary packages before querying the DB.
	if requested && !slices.Contains(opts.PkgRelationships, ftypes.RelationshipDirect) {
		requested = false
		notRequestedReason = "relationship-excluded"
	}
	results := map[string]*types.Result{}
	packages := map[string]map[string]bool{}
	cache := map[string]assessment{}
	for i, resource := range resources {
		if resource.Type != ftypes.CustomResourceCycloneDXBinSBOM && resource.Type != ftypes.CustomResourceCycloneDXBomBlint {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		bom, err := decodeFragment(resource.Data)
		if err != nil {
			log.Warn("Cannot scan binary SBOM fragment", log.FilePath(resource.FilePath), log.Err(err))
			continue
		}
		components := scopeReferences(bom, resource.FilePath)
		for _, component := range components {
			if component.Name == "" || (component.Type != cdx.ComponentTypeLibrary && component.Type != cdx.ComponentTypeApplication) {
				continue
			}
			// The unnamed-version subject binary is a container for its dependencies,
			// not necessarily itself a package in an advisory ecosystem.
			if bom.Metadata != nil && component == bom.Metadata.Component && component.PackageURL == "" {
				continue
			}
			var parsed *purl.PackageURL
			var parseErr error
			if component.PackageURL != "" {
				parsed, parseErr = purl.FromString(component.PackageURL)
			}
			pkg := componentPackage(*component, parsed, resource.FilePath)
			outcome := assessment{status: "not-scanned", reason: notRequestedReason}
			if requested {
				if parseErr != nil {
					outcome.reason = "invalid-package-url"
				} else {
					identity, reason := lookupIdentity(*component, parsed)
					if reason != "" {
						outcome.reason = reason
					} else {
						uncertain := uncertainVersion(*component, parsed, resource.Type, identity)
						key := string(identity.kind) + "\x00" + identity.name + "\x00" + pkg.Version + "\x00" + uncertain + "\x00" + identity.basis
						var ok bool
						outcome, ok = cache[key]
						if !ok {
							outcome, err = s.assess(ctx, identity, pkg.Version, uncertain)
							if err != nil {
								return nil, nil, fmt.Errorf("binary vulnerability scan of %s (%s): %w", component.Name, resource.FilePath, err)
							}
							cache[key] = outcome
						}
						setProperty(component, "bolt:binary:advisory-identity", string(identity.kind)+":"+identity.name)
						setProperty(component, "bolt:binary:identity-basis", identity.basis)
						setProperty(component, "bolt:binary:identity-source", identity.source)
					}
				}
			}
			setProperty(component, PropertyScanStatus, outcome.status)
			setProperty(component, PropertyScanReason, outcome.reason)
			if !requested {
				continue
			}
			result, ok := results[resource.FilePath]
			if !ok {
				result = &types.Result{Target: resource.FilePath, Class: types.ClassLangPkg, Type: ResultType}
				results[resource.FilePath] = result
				packages[resource.FilePath] = map[string]bool{}
			}
			if !packages[resource.FilePath][pkg.Identifier.UID] {
				result.Packages = append(result.Packages, pkg)
				packages[resource.FilePath][pkg.Identifier.UID] = true
			}
			for _, finding := range outcome.findings {
				finding.PkgID, finding.PkgName, finding.PkgPath = pkg.ID, pkg.Name, resource.FilePath
				finding.PkgIdentifier = pkg.Identifier
				result.Vulnerabilities = append(result.Vulnerabilities, finding)
			}
		}
		flattenComponents(bom, components)
		raw, err := json.Marshal(bom)
		if err != nil {
			return nil, nil, fmt.Errorf("encode scanned binary SBOM: %w", err)
		}
		updated[i].Data = raw
	}
	var output types.Results
	for _, result := range results {
		result.Vulnerabilities = uniqueFindings(result.Vulnerabilities)
		sort.Slice(result.Packages, func(i, j int) bool { return result.Packages[i].ID < result.Packages[j].ID })
		output = append(output, *result)
	}
	sort.Slice(output, func(i, j int) bool { return output[i].Target < output[j].Target })
	return output, updated, nil
}

func (s *Scanner) assess(ctx context.Context, id identity, reportedVersion, uncertain string) (assessment, error) {
	if err := ctx.Err(); err != nil {
		return assessment{}, err
	}
	driver, ok := s.newDriver(id.kind)
	if !ok {
		return assessment{status: "not-scanned", reason: "unsupported-advisory-ecosystem"}, nil
	}
	// Inspect coverage even for a known version: no advisory data is not proof of
	// safety, and the versionless path needs candidates rather than a silent skip.
	advisories, err := driver.GetAdvisories(id.name)
	if err != nil {
		return assessment{}, err
	}
	if len(advisories) == 0 {
		return assessment{status: "no-advisories", reason: "no-advisories-for-identity"}, nil
	}
	var findings []types.DetectedVulnerability
	if uncertain == "" {
		findings, err = driver.DetectVulnerabilitiesFromAdvisories("", id.name, reportedVersion, advisories)
		if err != nil {
			// A malformed version or advisory range is uncertainty, not evidence
			// that the installed component is outside the vulnerable range.
			uncertain = "version-comparison-failed"
			log.DebugContext(ctx, "Cannot evaluate binary component version", log.String("package", id.name), log.Err(err))
		}
	}
	if uncertain != "" {
		findings = nil
		for _, adv := range advisories {
			findings = append(findings, types.DetectedVulnerability{VulnerabilityID: adv.VulnerabilityID,
				DataSource: adv.DataSource, Custom: adv.Custom})
		}
	}
	status, reason := "scanned", "version-range-evaluated"
	if uncertain != "" {
		status, reason = "candidate", uncertain
	}
	// Cross-ecosystem source mappings identify an upstream project; they do not
	// establish that package-specific patches or build conditions are identical.
	if id.basis == "upstream-project-mapping" && len(findings) != 0 && uncertain == "" {
		status, reason = "candidate", "upstream-advisory-mapping"
	}
	for i := range findings {
		assessmentName := "affected"
		if status == "candidate" {
			assessmentName = "candidate"
			findings[i].InstalledVersion = ""
			findings[i].FixedVersion = ""
			findings[i].Status = dbTypes.StatusUnderInvestigation
		}
		custom := map[string]any{PropertyAssessment: assessmentName,
			"bolt:binary:reason": reason, "bolt:binary:reported-version": reportedVersion,
			"bolt:binary:identity-basis": id.basis}
		if findings[i].Custom != nil {
			custom["advisory"] = findings[i].Custom
		}
		findings[i].Custom = custom
	}
	return assessment{findings: findings, status: status, reason: reason}, nil
}

func uncertainVersion(c cdx.Component, p *purl.PackageURL, generator string, id identity) string {
	versionSources := propertyValues(c, PropertyVersionSource)
	if slices.Contains(versionSources, "reference-metadata") ||
		(generator == ftypes.CustomResourceCycloneDXBinSBOM && (len(versionSources) != 1 || versionSources[0] != "detected")) {
		return "reference-version-only"
	}
	if c.Version == "" && (p == nil || p.Version == "") {
		return "missing-version"
	}
	if c.Version != "" && p != nil && p.Version != "" && c.Version != p.Version {
		return "conflicting-versions"
	}
	ver := c.Version
	if ver == "" && p != nil {
		ver = p.Version
	}
	commit := strings.TrimPrefix(ver, "git+")
	if id.basis == "upstream-project-mapping" && (len(commit) == 40 || len(commit) == 64) {
		if _, err := hex.DecodeString(commit); err == nil {
			return "commit-version-not-resolved"
		}
	}
	// Conan ranges use the generic semver-like comparer. Invalid raw tags must
	// not fall through its bool-only error path and appear unaffected.
	if id.kind == ftypes.Conan {
		if _, err := version.Parse(ver); err != nil {
			return "unparseable-version"
		}
	}
	return ""
}

func componentPackage(c cdx.Component, parsed *purl.PackageURL, path string) ftypes.Package {
	pkg := ftypes.Package{ID: c.BOMRef, Name: c.Name, Version: c.Version, FilePath: path,
		Identifier: ftypes.PkgIdentifier{UID: c.BOMRef, BOMRef: c.BOMRef}, Relationship: ftypes.RelationshipDirect}
	if parsed != nil {
		pkg.Identifier.PURL = parsed.Unwrap()
		if pkg.Version == "" {
			pkg.Version = parsed.Version
		}
	}
	return pkg
}

func uniqueFindings(input []types.DetectedVulnerability) []types.DetectedVulnerability {
	seen := map[string]int{}
	var output []types.DetectedVulnerability
	for _, finding := range input {
		key := finding.VulnerabilityID + "\x00" + finding.PkgIdentifier.BOMRef
		if index, ok := seen[key]; ok {
			// A corroborated installed version takes precedence over a candidate.
			if finding.Status != dbTypes.StatusUnderInvestigation {
				output[index] = finding
			}
			continue
		}
		seen[key] = len(output)
		output = append(output, finding)
	}
	sort.Slice(output, func(i, j int) bool {
		if output[i].PkgID != output[j].PkgID {
			return output[i].PkgID < output[j].PkgID
		}
		return output[i].VulnerabilityID < output[j].VulnerabilityID
	})
	return output
}

func decodeFragment(data any) (*cdx.BOM, error) {
	var raw []byte
	switch value := data.(type) {
	case []byte:
		raw = value
	case string:
		var err error
		raw, err = base64.StdEncoding.DecodeString(value)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported fragment data type %T", data)
	}
	// BLint may prefix its JSON with a C-style diagnostic comment. Never strip
	// comment-like text inside JSON strings (URLs, evidence, descriptions).
	raw = []byte(strings.TrimSpace(string(raw)))
	for strings.HasPrefix(string(raw), "/*") {
		end := strings.Index(string(raw), "*/")
		if end < 0 {
			return nil, fmt.Errorf("unterminated binary SBOM comment")
		}
		raw = []byte(strings.TrimSpace(string(raw[end+2:])))
	}
	var bom cdx.BOM
	if err := json.Unmarshal(raw, &bom); err != nil {
		return nil, err
	}
	return &bom, nil
}

func scopeReferences(bom *cdx.BOM, path string) []*cdx.Component {
	var components []*cdx.Component
	var walk func(*cdx.Component)
	walk = func(c *cdx.Component) {
		components = append(components, c)
		if c.Components != nil {
			for i := range *c.Components {
				walk(&(*c.Components)[i])
			}
		}
	}
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		walk(bom.Metadata.Component)
	}
	if bom.Components != nil {
		for i := range *bom.Components {
			walk(&(*bom.Components)[i])
		}
	}
	refs := map[string]string{}
	for _, c := range components {
		original := c.BOMRef
		sourceRef := propertyValues(*c, "bolt:binary:source-ref")
		if len(sourceRef) == 0 && original != "" {
			setProperty(c, "bolt:binary:source-ref", original)
			sourceRef = []string{original}
		}
		key := c.PackageURL
		if key == "" {
			key = strings.Join(sourceRef, ",")
		}
		if key == "" {
			key = string(c.Type) + ":" + c.Group + ":" + c.Name + "@" + c.Version
		}
		ids := propertyValues(*c, PropertyComponentID)
		slices.Sort(ids)
		var repositories []string
		if c.ExternalReferences != nil {
			for _, external := range *c.ExternalReferences {
				if external.Type == cdx.ERTypeVCS {
					repository := canonicalRepository(external.URL)
					if repository == "" {
						repository = external.URL
					}
					repositories = append(repositories, repository)
				}
			}
		}
		slices.Sort(repositories)
		key += "\x00" + string(c.Type) + "\x00" + c.Version + "\x00" + strings.Join(ids, ",") + "\x00" + strings.Join(repositories, ",") + "\x00" + c.CPE
		sum := sha256.Sum256([]byte(path + "\x00" + key))
		ref := "urn:bolt:binary:" + hex.EncodeToString(sum[:])
		if original != "" {
			refs[original] = ref
		}
		c.BOMRef = ref
		setProperty(c, "binary:file:path", path)
	}
	if bom.Dependencies != nil {
		for i := range *bom.Dependencies {
			dep := &(*bom.Dependencies)[i]
			if ref, ok := refs[dep.Ref]; ok {
				dep.Ref = ref
			}
			if dep.Dependencies != nil {
				for j, old := range *dep.Dependencies {
					if ref, ok := refs[old]; ok {
						(*dep.Dependencies)[j] = ref
					}
				}
			}
		}
	}
	return components
}

// Represent nested inventory once, at the top level, retaining its containment
// edges. Otherwise the ordinary package serializer and nested fragment would
// publish the same bom-ref twice, and nested findings could become orphaned.
func flattenComponents(bom *cdx.BOM, components []*cdx.Component) {
	var root *cdx.Component
	if bom.Metadata != nil {
		root = bom.Metadata.Component
	}
	var flat []cdx.Component
	for _, component := range components {
		if component.Components != nil {
			var children []string
			for _, child := range *component.Components {
				children = append(children, child.BOMRef)
			}
			if len(children) != 0 {
				if bom.Dependencies == nil {
					bom.Dependencies = &[]cdx.Dependency{}
				}
				*bom.Dependencies = append(*bom.Dependencies, cdx.Dependency{Ref: component.BOMRef, Dependencies: &children})
			}
			component.Components = nil
		}
		if component != root {
			flat = append(flat, *component)
		}
	}
	bom.Components = &flat
}
