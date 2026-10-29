package local

import (
	"context"
	"debug/elf"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/elfdeps"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
)

func TestRecursiveELFAnalysisFollowsExplicitRootSymlink(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "actual")
	require.NoError(t, os.Mkdir(real, 0755))
	ignoredELF(t, filepath.Join(real, "program"), elf.ET_EXEC)
	for _, target := range []string{real, filepath.Join(real, "program")} {
		t.Run(filepath.Base(target), func(t *testing.T) {
			alias := filepath.Join(root, "alias-"+filepath.Base(target))
			if err := os.Symlink(target, alias); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			c := cache.NewMemoryCache()
			a, err := NewArtifact(alias, c, walker.NewFS(), artifact.Option{Libtree: true, Parallel: 1, BinarySBOM: []string{"none"}})
			require.NoError(t, err)
			ref, err := a.Inspect(context.Background())
			require.NoError(t, err)
			require.Equal(t, alias, ref.Name)
			blob, err := c.GetBlob(ref.BlobIDs[0])
			require.NoError(t, err)
			var graph []elfdeps.Node
			for _, resource := range blob.CustomResources {
				if resource.Type == "libtree" {
					require.NoError(t, json.Unmarshal(resource.Data.([]byte), &graph))
				}
			}
			require.Len(t, graph, 1)
			require.Equal(t, "/program", graph[0].Path)
		})
	}
}
