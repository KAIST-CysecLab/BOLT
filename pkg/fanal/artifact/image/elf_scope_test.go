package image_test

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/applier"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	imageartifact "github.com/aquasecurity/trivy/pkg/fanal/artifact/image"
	"github.com/aquasecurity/trivy/pkg/fanal/elfdeps"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

type scopedELFImage struct{ recursiveRoutingImage }

func (i scopedELFImage) ID() (string, error) {
	hash, err := i.ConfigName()
	return hash.String(), err
}

type scopeFile struct {
	name string
	data []byte
}

func scopeLayer(t *testing.T, files ...scopeFile) v1.Layer {
	t.Helper()
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	for _, file := range files {
		require.NoError(t, w.WriteHeader(&tar.Header{Name: file.name, Mode: 0755, Size: int64(len(file.data))}))
		_, err := w.Write(file.data)
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	return static.NewLayer(buf.Bytes(), v1types.OCIUncompressedLayer)
}

// GCC creates genuine ET_EXEC/DT_NEEDED fixtures. Neither the executable nor
// its library is executed, and no compiler or linker searches target libraries
// outside the explicitly linked fixture shared object.
func scopeELFFixtures(t *testing.T) (app, library []byte) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("ELF compiler fixture requires Linux")
	}
	compiler, err := exec.LookPath("gcc")
	if err != nil {
		t.Skip("gcc is required to build real ELF scope fixtures")
	}
	directory := t.TempDir()
	libPath, appPath := filepath.Join(directory, "libfixture.so"), filepath.Join(directory, "app")
	compile := func(source string, args ...string) {
		t.Helper()
		command := exec.Command(compiler, args...)
		command.Stdin = strings.NewReader(source)
		output, err := command.CombinedOutput()
		require.NoError(t, err, "%s", output)
	}
	compile("int fixture(void) { return 7; }\n", "-shared", "-nostdlib", "-fPIC", "-x", "c", "-", "-o", libPath, "-Wl,-soname,libfixture.so")
	compile("extern int fixture(void); int entry(void) { return fixture(); }\n",
		"-nostdlib", "-no-pie", "-x", "c", "-", "-x", "none", "-o", appPath,
		"-Wl,-e,entry", "-Wl,--no-as-needed", "-Wl,-rpath,/lib", libPath)
	app, err = os.ReadFile(appPath)
	require.NoError(t, err)
	library, err = os.ReadFile(libPath)
	require.NoError(t, err)
	return app, library
}

func scopeImage(t *testing.T, layers []v1.Layer, history []v1.History) v1.Image {
	t.Helper()
	img, err := mutate.AppendLayers(empty.Image, layers...)
	require.NoError(t, err)
	config, err := img.ConfigFile()
	require.NoError(t, err)
	config.History = history
	img, err = mutate.ConfigFile(img, config)
	require.NoError(t, err)
	return img
}

func inspectScope(t *testing.T, img v1.Image, c *cache.MemoryCache) (artifact.Reference, map[string][]elfdeps.Node) {
	t.Helper()
	a, err := imageartifact.NewArtifact(scopedELFImage{recursiveRoutingImage{Image: img}}, c, artifact.Option{
		Libtree: true, Parallel: 1, BinarySBOM: []string{"none"},
	})
	require.NoError(t, err)
	ref, err := a.Inspect(context.Background())
	require.NoError(t, err)
	var blobs []types.BlobInfo
	for _, id := range ref.BlobIDs {
		blob, err := c.GetBlob(id)
		require.NoError(t, err)
		blobs = append(blobs, blob)
	}
	graphs := make(map[string][]elfdeps.Node)
	for _, resource := range applier.ApplyLayers(blobs).CustomResources {
		if resource.Type != "libtree" {
			continue
		}
		var graph []elfdeps.Node
		require.NoError(t, json.Unmarshal(resource.Data.([]byte), &graph))
		_, duplicate := graphs[resource.FilePath]
		require.False(t, duplicate, "one final graph per eligible root")
		graphs[resource.FilePath] = graph
	}
	return ref, graphs
}

func scopeHistory(userCommands ...string) []v1.History {
	history := []v1.History{{CreatedBy: "ADD base /"}, {CreatedBy: "CMD [\"/bin/sh\"]", EmptyLayer: true}}
	for _, command := range userCommands {
		history = append(history, v1.History{CreatedBy: command})
	}
	return history
}

func requireScopedApp(t *testing.T, graphs map[string][]elfdeps.Node, rootPath string) {
	t.Helper()
	require.Len(t, graphs, 1, "base ELFs must not become independent roots")
	graph, ok := graphs[rootPath]
	require.True(t, ok, "missing effective user root %s", rootPath)
	require.Len(t, graph, 2)
	require.Equal(t, "/"+rootPath, graph[0].Path)
	require.Equal(t, "application", graph[0].Kind)
	require.Equal(t, "/lib/libfixture.so", graph[1].Path)
	require.Equal(t, "resolved", graph[1].Status)
	require.Equal(t, []string{graph[1].ID}, graph[0].DependsOn)
	for _, node := range graph {
		require.NotEqual(t, "/bin/ls", node.Path, "unreferenced base executable must be absent")
	}
}

func TestRecursiveELFRootScopeUsesExistingEffectiveUserLayerPolicy(t *testing.T) {
	app, library := scopeELFFixtures(t)
	base := scopeLayer(t, scopeFile{"lib/libfixture.so", library}, scopeFile{"bin/ls", app})
	application := scopeLayer(t, scopeFile{"opt/app", app})
	for _, command := range []string{
		"COPY app /opt/app",
		"ADD app.tar /opt",
		"/bin/sh -c curl https://example.invalid/app -o /opt/app",
	} {
		t.Run(command, func(t *testing.T) {
			img := scopeImage(t, []v1.Layer{base, application}, scopeHistory(command))
			_, graphs := inspectScope(t, img, cache.NewMemoryCache())
			requireScopedApp(t, graphs, "opt/app")
		})
	}
	t.Run("base only", func(t *testing.T) {
		img := scopeImage(t, []v1.Layer{base}, scopeHistory())
		_, graphs := inspectScope(t, img, cache.NewMemoryCache())
		require.Empty(t, graphs)
	})
	t.Run("history absent", func(t *testing.T) {
		img := scopeImage(t, []v1.Layer{base, application}, nil)
		_, graphs := inspectScope(t, img, cache.NewMemoryCache())
		require.Empty(t, graphs)
	})
	t.Run("base boundary unknown", func(t *testing.T) {
		img := scopeImage(t, []v1.Layer{base, application}, []v1.History{{CreatedBy: "ADD base /"}, {CreatedBy: "COPY app /opt/app"}})
		_, graphs := inspectScope(t, img, cache.NewMemoryCache())
		require.Empty(t, graphs)
	})
	t.Run("package install excluded even when fetching", func(t *testing.T) {
		installed := scopeLayer(t, scopeFile{"opt/pkg-tool", app})
		img := scopeImage(t, []v1.Layer{base, application, installed}, scopeHistory(
			"COPY app /opt/app", "/bin/sh -c apt-get install -y curl && curl https://example.invalid/tool -o /opt/pkg-tool"))
		_, graphs := inspectScope(t, img, cache.NewMemoryCache())
		requireScopedApp(t, graphs, "opt/app")
	})
	t.Run("last user layer fallback", func(t *testing.T) {
		last := scopeLayer(t, scopeFile{"opt/last", app})
		img := scopeImage(t, []v1.Layer{base, application, last}, scopeHistory("/bin/sh -c make app", "/bin/sh -c make last"))
		_, graphs := inspectScope(t, img, cache.NewMemoryCache())
		requireScopedApp(t, graphs, "opt/last")
	})
}

func TestRecursiveELFRootScopeFollowsFinalProducerAndPartialCache(t *testing.T) {
	app, library := scopeELFFixtures(t)
	base := scopeLayer(t, scopeFile{"lib/libfixture.so", library}, scopeFile{"bin/ls", app})
	application := scopeLayer(t, scopeFile{"opt/app", app})
	t.Run("surviving root and referenced base DSO across partial cache", func(t *testing.T) {
		last := scopeLayer(t, scopeFile{"notes", []byte("non-effective final layer")})
		img := scopeImage(t, []v1.Layer{base, application, last}, scopeHistory("COPY app /opt/app", "/bin/sh -c echo ready > /notes"))
		c := cache.NewMemoryCache()
		ref, original := inspectScope(t, img, c)
		requireScopedApp(t, original, "opt/app")
		for _, id := range ref.BlobIDs {
			require.NoError(t, c.DeleteBlobs([]string{id}))
			_, repeated := inspectScope(t, img, c)
			require.Equal(t, original, repeated, "cache misses must not change effective-layer selection")
		}
		_, repeated := inspectScope(t, img, c)
		require.Equal(t, original, repeated)
	})
	for _, replacement := range []struct {
		name string
		file scopeFile
	}{
		{"non-effective ELF overwrite", scopeFile{"opt/app", append(append([]byte(nil), app...), []byte("upper rewrite")...)}},
		{"non-effective text overwrite", scopeFile{"opt/app", []byte("ordinary text")}},
		{"non-effective whiteout", scopeFile{"opt/.wh.app", nil}},
	} {
		t.Run(replacement.name, func(t *testing.T) {
			last := scopeLayer(t, replacement.file)
			img := scopeImage(t, []v1.Layer{base, application, last}, scopeHistory("COPY app /opt/app", "/bin/sh -c modify /opt/app"))
			_, graphs := inspectScope(t, img, cache.NewMemoryCache())
			require.Empty(t, graphs, "only surviving files whose final producer is effective are roots")
		})
	}
}
