package elfdeps

import (
	"context"
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExecutableSharedObjectKindFollowsDependencyRole(t *testing.T) {
	compiler, err := exec.LookPath("gcc")
	if err != nil {
		t.Skip("gcc is required to build real ELF fixtures")
	}
	root := t.TempDir()
	ordinary := compileLibrary(t, root, "/lib/libordinary.so", "libordinary.so", nil, "", false)
	executableLibrary := filepath.Join(root, "lib", "libexecutable.so")
	// Like glibc's libc.so.6, this is an ET_DYN shared object with PT_INTERP,
	// but without DF_1_PIE. It can be inspected as an executable root and
	// loaded as a DT_NEEDED library. The test never executes the fixture.
	command := exec.Command(compiler, "-shared", "-nostdlib", "-fPIC", "-x", "c", "-", "-x", "none",
		"-o", executableLibrary, "-Wl,-soname,libexecutable.so", "-Wl,-e,fixture", "-Wl,--no-as-needed",
		"-Wl,--enable-new-dtags", "-Wl,-rpath,$ORIGIN", ordinary)
	command.Stdin = strings.NewReader(`
__attribute__((section(".interp"), used))
const char fixture_interpreter[] = "/target/ld-fixture.so";
int fixture(void) { return 0; }
`)
	output, err := command.CombinedOutput()
	require.NoError(t, err, "%s", output)

	file, err := elf.Open(executableLibrary)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, file.Close()) })
	require.Equal(t, elf.ET_DYN, file.Type)
	var hasInterpreter bool
	for _, program := range file.Progs {
		hasInterpreter = hasInterpreter || program.Type == elf.PT_INTERP
	}
	require.True(t, hasInterpreter)
	flags, err := file.DynValue(elf.DT_FLAGS_1)
	require.NoError(t, err)
	for _, flag := range flags {
		require.Zero(t, flag&uint64(elf.DF_1_PIE))
	}
	require.NoError(t, os.Chmod(executableLibrary, 0755))
	compileLibrary(t, root, "/parent.so", "parent.so", []string{executableLibrary}, "/lib", true)
	resolver := targetResolver(t, root, Options{})

	// Reuse one resolver to ensure contextual classification does not mutate
	// cached metadata when the same file is later resolved as an independent root.
	for _, input := range []string{"/lib/libexecutable.so", "/parent.so", "/lib/libexecutable.so"} {
		nodes, err := resolver.Resolve(context.Background(), input)
		require.NoError(t, err)
		executable := nodeByPath(t, nodes, "/lib/libexecutable.so")
		require.Equal(t, "resolved", executable.Status)
		if input == "/parent.so" {
			require.Equal(t, "library", executable.Kind)
			require.Contains(t, nodes[0].DependsOn, executable.ID)
		} else {
			require.Equal(t, "application", executable.Kind)
			require.Equal(t, executable.ID, nodes[0].ID)
		}
		ordinaryNode := nodeByPath(t, nodes, "/lib/libordinary.so")
		require.Equal(t, "library", ordinaryNode.Kind)
		require.Contains(t, executable.DependsOn, ordinaryNode.ID)
	}
}
