package image

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/elfdeps"
)

func TestImageLibraryPathPreservesTargetLoaderSyntax(t *testing.T) {
	compiler, err := exec.LookPath("gcc")
	if err != nil {
		t.Skip("gcc is needed for ELF fixtures")
	}
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "work"), 0755))
	build := func(args ...string) {
		t.Helper()
		cmd := exec.Command(compiler, append([]string{"-nostdlib", "-fPIC", "-x", "c", "-", "-x", "none"}, args...)...)
		cmd.Stdin = strings.NewReader("void entry(void) {}")
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "%s", output)
	}
	lib := filepath.Join(root, "work/libcwd.so")
	build("-shared", "-Wl,-soname,libcwd.so", "-o", lib)
	for name, interpreter := range map[string]string{"gnu": "/lib64/ld-linux-x86-64.so.2", "musl": "/lib/ld-musl-x86_64.so.1"} {
		build("-Wl,-e,entry", "-Wl,--no-as-needed", "-Wl,--dynamic-linker,"+interpreter, "-o", filepath.Join(root, name), lib)
	}
	target, err := elfdeps.NewLocalFS(root)
	require.NoError(t, err)
	for _, tt := range []struct {
		loader, value, status string
	}{
		{"gnu", "", "missing"},
		{"gnu", ":", "resolved"},
		{"gnu", "/absent::/also-absent", "resolved"},
		{"gnu", "/absent:/also-absent", "missing"},
		{"gnu", "/work;/absent", "resolved"},
		{"musl", ":", "missing"},
		{"musl", "/work;/absent", "missing"},
		{"musl", "/work:/absent", "resolved"},
	} {
		t.Run(tt.loader+"/"+tt.value, func(t *testing.T) {
			cfg := &v1.ConfigFile{Config: v1.Config{WorkingDir: "/work", Env: []string{"LD_LIBRARY_PATH=" + tt.value}}}
			resolver := elfdeps.NewResolver(target, dependencyOptions(cfg))
			graph, err := resolver.Resolve(context.Background(), "/"+tt.loader)
			require.NoError(t, err)
			require.Len(t, graph, 2)
			require.Equal(t, tt.status, graph[1].Status)
			if tt.status == "resolved" {
				require.Equal(t, "/work/libcwd.so", graph[1].Path)
			}
		})
	}
}
