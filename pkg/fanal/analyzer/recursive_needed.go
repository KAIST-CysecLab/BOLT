package analyzer

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"path"
	"path/filepath"

	"github.com/aquasecurity/trivy/pkg/fanal/elfdeps"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

// AnalyzeELFDependencies also accepts final-image hard links that are not
// visited by the ordinary regular-file layer walker.
func AnalyzeELFDependencies(ctx context.Context, result *AnalysisResult, resolver *elfdeps.Resolver, filePath string) error {
	// Walker paths are relative to the target root, not the image WORKDIR.
	graph, err := resolver.Resolve(ctx, path.Clean("/"+filepath.ToSlash(filePath)))
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// A lower-layer file can be removed or replaced by a non-ELF file in
		// the final image. It must not contribute a stale dependency graph.
		if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, elfdeps.ErrNotELF) {
			log.Warn("Unable to resolve ELF dependencies", log.FilePath(filePath), log.Err(err))
		}
		return nil
	}
	if len(graph) == 0 {
		return nil
	}
	raw, err := json.Marshal(graph)
	if err != nil {
		return err
	}
	result.m.Lock()
	defer result.m.Unlock()
	result.CustomResources = append(result.CustomResources, types.CustomResource{
		Type: "libtree", FilePath: filePath, Data: raw,
	})
	return nil
}
