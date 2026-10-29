package image

import (
	"strings"

	"github.com/aquasecurity/trivy/pkg/log"
)

// effectiveUserLayers is the existing binary-analysis scope, shared by the
// external generators and recursive ELF roots. Dependency lookup may still
// read base-layer libraries referenced by those roots.
func (a Artifact) effectiveUserLayers(userDiffIDs []string, layerKeyMap map[string]LayerInfo) []string {
	isPkgInstallRun := func(createdBy string) bool {
		s := strings.ToLower(createdBy)
		return strings.Contains(s, "apt-get install") ||
			strings.Contains(s, "apt install") ||
			strings.Contains(s, "yum install") ||
			strings.Contains(s, "dnf install") ||
			strings.Contains(s, "microdnf install") ||
			strings.Contains(s, "apk add")
	}
	isFetchRun := func(createdBy string) bool {
		s := strings.ToLower(createdBy)
		return strings.Contains(s, "git clone") ||
			strings.Contains(s, "curl ") ||
			strings.Contains(s, "wget ") ||
			strings.Contains(s, "tar -x")
	}
	createdByByDiff := make(map[string]string, len(layerKeyMap))
	for _, li := range layerKeyMap {
		createdByByDiff[li.DiffID] = li.CreatedBy
	}
	var effective []string
	for _, d := range userDiffIDs {
		cb := createdByByDiff[d]
		if (isCopyOrAddLayer(cb) || isFetchRun(cb)) && !isPkgInstallRun(cb) {
			effective = append(effective, d)
		}
	}
	// Preserve the original fallback, including its treatment of install-only
	// histories: when no content layer matches, use the final user layer.
	if len(effective) == 0 && len(userDiffIDs) > 0 {
		effective = []string{userDiffIDs[len(userDiffIDs)-1]}
		a.logger.Debug("inspect: fallback effective user layer", log.String("diff_id", effective[0]))
	}
	return effective
}
