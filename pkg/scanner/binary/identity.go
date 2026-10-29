package binary

import (
	_ "embed"
	"encoding/json"
	"net/url"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	PropertyVersionSource = "bolt:binary:version-source"
	PropertyComponentID   = "bolt:binary:component-id"
	PropertyScanStatus    = "bolt:binary:vulnerability-status"
	PropertyScanReason    = "bolt:binary:vulnerability-reason"
	PropertyAssessment    = "bolt:binary:assessment"
)

// Lookup identity is deliberately separate from the component's inventory PURL.
// A source project covered by the Conan advisory catalog is not a Conan install.
type identity struct {
	kind   ftypes.LangType
	name   string
	basis  string
	source string
}

type projectMapping struct {
	ComponentIDs []string `json:"component_ids"`
	Repositories []string `json:"repositories"`
	Package      string   `json:"package"`
	Source       string   `json:"source"`
}

//go:embed projects.json
var projectData []byte

var projects = func() []projectMapping {
	var entries []projectMapping
	if err := json.Unmarshal(projectData, &entries); err != nil {
		panic("invalid embedded binary project mappings: " + err.Error())
	}
	return entries
}()

func lookupIdentity(c cdx.Component, p *purl.PackageURL) (identity, string) {
	if p != nil && p.Class() == types.ClassLangPkg {
		return identity{kind: p.LangType(), name: p.Package().Name, basis: "package-url"}, ""
	}
	if p != nil && p.Type != "generic" && p.Type != "github" && p.Type != "gitlab" {
		return identity{}, "unsupported-package-type"
	}
	ids := propertyValues(c, PropertyComponentID)
	if len(ids) > 1 {
		return identity{}, "ambiguous-project-identity"
	}
	repos := map[string]bool{}
	if c.ExternalReferences != nil {
		for _, ref := range *c.ExternalReferences {
			if ref.Type == cdx.ERTypeVCS {
				repos[canonicalRepository(ref.URL)] = true
			}
		}
	}
	if p != nil && (p.Type == "github" || p.Type == "gitlab") {
		repos[canonicalRepository("https://"+p.Type+".com/"+p.Namespace+"/"+p.Name)] = true
	}
	var matches []identity
	for _, project := range projects {
		matched := false
		for _, id := range project.ComponentIDs {
			matched = matched || (len(ids) == 1 && ids[0] == id)
		}
		for _, repo := range project.Repositories {
			matched = matched || repos[canonicalRepository(repo)]
		}
		if matched {
			matches = append(matches, identity{kind: ftypes.Conan, name: project.Package,
				basis: "upstream-project-mapping", source: project.Source})
		}
	}
	if len(matches) == 1 {
		return matches[0], ""
	}
	if len(matches) > 1 {
		return identity{}, "ambiguous-project-identity"
	}
	return identity{}, "unmapped-project-identity"
}

func canonicalRepository(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return ""
	}
	// Do not confuse a release/archive URL or a lookalike host with a repository.
	path := strings.TrimSuffix(strings.TrimRight(u.Path, "/"), ".git")
	if path == "" {
		return ""
	}
	return strings.ToLower(u.Host) + path
}

func propertyValues(c cdx.Component, name string) []string {
	var values []string
	seen := map[string]bool{}
	if c.Properties != nil {
		for _, p := range *c.Properties {
			if p.Name == name && p.Value != "" && !seen[p.Value] {
				values = append(values, p.Value)
				seen[p.Value] = true
			}
		}
	}
	return values
}

func setProperty(c *cdx.Component, name, value string) {
	var props []cdx.Property
	if c.Properties != nil {
		for _, prop := range *c.Properties {
			if prop.Name != name {
				props = append(props, prop)
			}
		}
	}
	if value != "" {
		props = append(props, cdx.Property{Name: name, Value: value})
	}
	c.Properties = &props
}
