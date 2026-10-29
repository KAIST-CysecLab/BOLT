package image

import (
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
)

func TestRecursiveDependenciesCacheIsScopedToFinalImage(t *testing.T) {
	a := Artifact{artifactOption: artifact.Option{Libtree: true}}
	_, first, err := a.calcCacheKeys("image-one", []string{"shared-layer"})
	require.NoError(t, err)
	_, second, err := a.calcCacheKeys("image-two", []string{"shared-layer"})
	require.NoError(t, err)
	require.NotEqual(t, first, second, "upper layers and loader ENV affect dependency resolution")
	_, repeat, err := a.calcCacheKeys("image-one", []string{"shared-layer"})
	require.NoError(t, err)
	require.Equal(t, first, repeat)

	a.artifactOption.Libtree = false
	_, first, err = a.calcCacheKeys("image-one", []string{"shared-layer"})
	require.NoError(t, err)
	_, second, err = a.calcCacheKeys("image-two", []string{"shared-layer"})
	require.NoError(t, err)
	require.Equal(t, first, second, "ordinary analysis retains shared layer caching")
}

func TestDependencyOptionsUsesImageEnvironment(t *testing.T) {
	t.Setenv("LD_LIBRARY_PATH", "/host-only")
	config := &v1.ConfigFile{Config: v1.Config{
		Env: []string{"PATH=/bin", "LD_LIBRARY_PATH=/image/lib;$ORIGIN/extra:"}, WorkingDir: "/app",
	}}
	opts := dependencyOptions(config)
	require.Equal(t, []string{"/image/lib;$ORIGIN/extra:"}, opts.LibraryPath)
	require.Equal(t, "/app", opts.WorkingDir)
	config.Config.Env = nil
	require.Empty(t, dependencyOptions(config).LibraryPath)
	config.Config.Env = []string{"LD_LIBRARY_PATH="}
	require.Empty(t, dependencyOptions(config).LibraryPath)
	config.Config.Env = []string{"LD_LIBRARY_PATH=:"}
	require.Equal(t, []string{":"}, dependencyOptions(config).LibraryPath)
}
