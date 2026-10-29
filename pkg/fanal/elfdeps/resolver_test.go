package elfdeps

import (
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// The compiler only creates fixtures. Tests never execute these target files,
// nor load their dependencies into the test process.
func compileLibrary(t *testing.T, root, target, soname string, dependencies []string, rpath string, runpath bool, extraArgs ...string) string {
	t.Helper()
	compiler, err := exec.LookPath("gcc")
	if err != nil {
		t.Skip("gcc is required to build real ELF fixtures")
	}
	output := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(target, "/")))
	require.NoError(t, os.MkdirAll(filepath.Dir(output), 0755))
	args := []string{"-shared", "-nostdlib", "-fPIC", "-x", "c", "-", "-x", "none", "-o", output,
		"-Wl,-soname," + soname, "-Wl,--no-as-needed"}
	if rpath != "" {
		dtags := "--disable-new-dtags"
		if runpath {
			dtags = "--enable-new-dtags"
		}
		args = append(args, "-Wl,"+dtags, "-Wl,-rpath,"+rpath)
	}
	args = append(args, extraArgs...)
	args = append(args, dependencies...)
	command := exec.Command(compiler, args...)
	command.Stdin = strings.NewReader("int fixture(void) { return 7; }\n")
	log, err := command.CombinedOutput()
	require.NoError(t, err, "%s", log)
	return output
}

func targetResolver(t *testing.T, root string, opts Options) *Resolver {
	t.Helper()
	filesystem, err := NewLocalFS(root)
	require.NoError(t, err)
	return NewResolver(filesystem, opts)
}

func nodeByPath(t *testing.T, nodes []Node, name string) Node {
	t.Helper()
	for _, node := range nodes {
		if node.Path == name {
			return node
		}
	}
	t.Fatalf("missing node %q: %+v", name, nodes)
	return Node{}
}

func TestRPathIsInheritedAndRunPathIsDirect(t *testing.T) {
	root := t.TempDir()
	b := compileLibrary(t, root, "/private/libb.so", "libb.so", nil, "", false)
	a := compileLibrary(t, root, "/private/liba.so", "liba.so", []string{b}, "", false)
	compileLibrary(t, root, "/app/rpath.so", "root.so", []string{a}, "$ORIGIN/../private", false)
	compileLibrary(t, root, "/app/runpath.so", "root.so", []string{a}, "${ORIGIN}/../private", true)
	resolver := targetResolver(t, root, Options{})
	nodes, err := resolver.Resolve(context.Background(), "/app/rpath.so")
	require.NoError(t, err)
	require.Len(t, nodes, 3)
	require.Equal(t, []string{nodeByPath(t, nodes, "/private/libb.so").ID}, nodeByPath(t, nodes, "/private/liba.so").DependsOn)
	require.Equal(t, "library", nodes[0].Kind)

	nodes, err = resolver.Resolve(context.Background(), "/app/runpath.so")
	require.NoError(t, err)
	require.Len(t, nodes, 3)
	require.Equal(t, "missing", nodes[2].Status)
	require.Empty(t, nodes[2].Path)
	require.NotEqual(t, nodes[0].ID, nodes[2].ID)

	// The metadata cache must not leak the first root's inherited RPATH into
	// the second root, and target library-path applies to all generations.
	nodes, err = targetResolver(t, root, Options{LibraryPath: []string{"/private"}}).Resolve(context.Background(), "/app/runpath.so")
	require.NoError(t, err)
	require.Equal(t, "resolved", nodes[2].Status)
}

func TestLibraryPathPrecedenceAndHostIsolation(t *testing.T) {
	root := t.TempDir()
	first := compileLibrary(t, root, "/rpath/libchoice.so", "libchoice.so", nil, "", false)
	compileLibrary(t, root, "/env/libchoice.so", "libchoice.so", nil, "", false)
	compileLibrary(t, root, "/root-rpath.so", "root.so", []string{first}, "/rpath", false)
	compileLibrary(t, root, "/root-runpath.so", "root.so", []string{first}, "/rpath", true)
	resolver := targetResolver(t, root, Options{LibraryPath: []string{"/env"}})
	for input, want := range map[string]string{"/root-rpath.so": "/rpath/libchoice.so", "/root-runpath.so": "/env/libchoice.so"} {
		nodes, err := resolver.Resolve(context.Background(), input)
		require.NoError(t, err)
		require.Equal(t, want, nodes[1].Path)
	}
	compileLibrary(t, root, "/no-path.so", "root.so", []string{first}, "", false)
	t.Setenv("LD_LIBRARY_PATH", filepath.Join(root, "rpath"))
	nodes, err := targetResolver(t, root, Options{}).Resolve(context.Background(), "/no-path.so")
	require.NoError(t, err)
	require.Equal(t, "missing", nodes[1].Status, "host environment and arbitrary same-basename files must not be searched")
}

func TestCyclesSharedEdgesAndCanonicalSymlinks(t *testing.T) {
	root := t.TempDir()
	c := compileLibrary(t, root, "/real/libc-fixture.so", "libc-fixture.so", nil, "", false)
	a := compileLibrary(t, root, "/real/liba.so", "liba.so", []string{c}, "$ORIGIN", false)
	b := compileLibrary(t, root, "/real/libb.so", "libb.so", []string{a, c}, "$ORIGIN", false)
	compileLibrary(t, root, "/real/liba.so", "liba.so", []string{b, c}, "$ORIGIN", false)
	compileLibrary(t, root, "/bin/root.so", "root.so", []string{a, b}, "/alias", false)
	require.NoError(t, os.Symlink("/real", filepath.Join(root, "alias")))
	require.NoError(t, os.Symlink("/bin/root.so", filepath.Join(root, "entry.so")))
	nodes, err := targetResolver(t, root, Options{}).Resolve(context.Background(), "/entry.so")
	require.NoError(t, err)
	require.Len(t, nodes, 4)
	require.Equal(t, "/bin/root.so", nodes[0].ID)
	aNode := nodeByPath(t, nodes, "/real/liba.so")
	bNode := nodeByPath(t, nodes, "/real/libb.so")
	cNode := nodeByPath(t, nodes, "/real/libc-fixture.so")
	require.Contains(t, aNode.DependsOn, bNode.ID)
	require.Contains(t, bNode.DependsOn, aNode.ID)
	require.Contains(t, aNode.DependsOn, cNode.ID)
	require.Contains(t, bNode.DependsOn, cNode.ID)
}

func TestSymlinkParentTraversalInNeededAndSearchPath(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "other/sub"), 0755))
	require.NoError(t, os.Symlink("/other/sub", filepath.Join(root, "alias")))
	library := compileLibrary(t, root, "/other/libfixture.so", "/alias/../libfixture.so", nil, "", false)
	compileLibrary(t, root, "/needed.so", "root.so", []string{library}, "", false)
	nodes, err := targetResolver(t, root, Options{}).Resolve(context.Background(), "/needed.so")
	require.NoError(t, err)
	require.Equal(t, "/other/libfixture.so", nodes[1].Path)

	library = compileLibrary(t, root, "/other/libfixture.so", "libfixture.so", nil, "", false)
	compileLibrary(t, root, "/search.so", "root.so", []string{library}, "/alias/..", false)
	nodes, err = targetResolver(t, root, Options{}).Resolve(context.Background(), "/search.so")
	require.NoError(t, err)
	require.Equal(t, "/other/libfixture.so", nodes[1].Path)
}

func TestDSOOriginUsesLoadAliasWithoutChangingCanonicalIdentity(t *testing.T) {
	root := t.TempDir()
	b := compileLibrary(t, root, "/bundle/libb.so", "libb.so", nil, "", false)
	a := compileLibrary(t, root, "/shared/liba.so", "liba.so", []string{b}, "$ORIGIN", true)
	require.NoError(t, os.Symlink("/shared/liba.so", filepath.Join(root, "bundle/liba.so")))
	compileLibrary(t, root, "/alias-root.so", "root.so", []string{a}, "/bundle", true)
	compileLibrary(t, root, "/direct-root.so", "root.so", []string{a}, "/shared", true)
	resolver := targetResolver(t, root, Options{})
	nodes, err := resolver.Resolve(context.Background(), "/alias-root.so")
	require.NoError(t, err)
	require.Equal(t, "/shared/liba.so", nodes[1].Path)
	require.NotEqual(t, nodes[0].ID, nodes[1].ID)
	require.Equal(t, "/bundle/libb.so", nodes[2].Path)
	// Reusing the parsed metadata must not reuse an earlier root's origin.
	nodes, err = resolver.Resolve(context.Background(), "/direct-root.so")
	require.NoError(t, err)
	require.Equal(t, "missing", nodes[2].Status)
}

func TestMuslEnvironmentRunpathInheritanceAndPathConfiguration(t *testing.T) {
	root := t.TempDir()
	b := compileLibrary(t, root, "/private/libb.so", "libb.so", nil, "", false)
	a := compileLibrary(t, root, "/private/liba.so", "liba.so", []string{b}, "", false)
	compileLibrary(t, root, "/env/liba.so", "liba.so", nil, "", false)
	compiler, err := exec.LookPath("gcc")
	require.NoError(t, err)
	for _, runpath := range []bool{false, true} {
		name, dtags := "rpath", "--disable-new-dtags"
		if runpath {
			name, dtags = "runpath", "--enable-new-dtags"
		}
		command := exec.Command(compiler, "-nostdlib", "-fPIC", "-x", "c", "-", "-x", "none",
			"-o", filepath.Join(root, name), "-Wl,-e,fixture", "-Wl,--dynamic-linker,/lib/ld-musl-x86_64.so.1",
			"-Wl,--no-as-needed", "-Wl,--allow-shlib-undefined", "-Wl,"+dtags, "-Wl,-rpath,/private", a)
		command.Stdin = strings.NewReader("int fixture(void) { return 7; }\n")
		output, err := command.CombinedOutput()
		require.NoError(t, err, "%s", output)
		nodes, err := targetResolver(t, root, Options{}).Resolve(context.Background(), "/"+name)
		require.NoError(t, err)
		require.Equal(t, "application", nodes[0].Kind)
		require.Equal(t, "/private/libb.so", nodes[2].Path, "musl inherits RUNPATH as well as RPATH")
		nodes, err = targetResolver(t, root, Options{LibraryPath: []string{"/env"}}).Resolve(context.Background(), "/"+name)
		require.NoError(t, err)
		require.Equal(t, "/env/liba.so", nodes[1].Path, "musl environment precedes both path tags")
	}
	// The target configuration supplies paths to indirect dependencies too.
	require.NoError(t, os.MkdirAll(filepath.Join(root, "etc"), 0755))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "configured"), 0755))
	require.NoError(t, os.Rename(b, filepath.Join(root, "configured/libb.so")))
	require.NoError(t, os.WriteFile(filepath.Join(root, "etc/ld-musl-x86_64.path"), []byte("/configured\n"), 0644))
	nodes, err := targetResolver(t, root, Options{}).Resolve(context.Background(), "/runpath")
	require.NoError(t, err)
	require.Equal(t, "/configured/libb.so", nodes[2].Path)
}

func TestTargetConfigurationAndWorkingDirectory(t *testing.T) {
	root := t.TempDir()
	library := compileLibrary(t, root, "/configured/libfixture.so", "libfixture.so", nil, "", false)
	compileLibrary(t, root, "/work/root.so", "root.so", []string{library}, "", false)
	require.NoError(t, os.MkdirAll(filepath.Join(root, "etc/ld.so.conf.d"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "etc/ld.so.conf"), []byte("include ld.so.conf.d/*.conf\n"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "etc/ld.so.conf.d/fixture.conf"), []byte("# target only\n/configured\ninclude /etc/ld.so.conf\n"), 0644))
	nodes, err := targetResolver(t, root, Options{WorkingDir: "/work"}).Resolve(context.Background(), "root.so")
	require.NoError(t, err)
	require.Equal(t, "/configured/libfixture.so", nodes[1].Path)
	require.Contains(t, nodes[1].Reason, "ld.so.cache")
}

func TestNodefaultlibRetainsConfiguredDirectories(t *testing.T) {
	root := t.TempDir()
	custom := compileLibrary(t, root, "/custom/libcustom.so", "libcustom.so", nil, "", false)
	standard := compileLibrary(t, root, "/lib/libstandard.so", "libstandard.so", nil, "", false)
	compileLibrary(t, root, "/root.so", "root.so", []string{custom, standard}, "", false, "-Wl,-z,nodefaultlib")
	require.NoError(t, os.MkdirAll(filepath.Join(root, "etc"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "etc/ld.so.conf"), []byte("/custom\n/lib\n"), 0644))
	nodes, err := targetResolver(t, root, Options{}).Resolve(context.Background(), "/root.so")
	require.NoError(t, err)
	require.Equal(t, "/custom/libcustom.so", nodes[1].Path)
	require.Equal(t, "missing", nodes[2].Status)
}

func TestSectionlessDynamicELFAndArchitectureCheck(t *testing.T) {
	root := t.TempDir()
	library := compileLibrary(t, root, "/valid/libfixture.so", "libfixture.so", nil, "", false)
	input := compileLibrary(t, root, "/root.so", "root.so", []string{library}, "/invalid:/valid", false)
	data, err := os.ReadFile(input)
	require.NoError(t, err)
	if elf.Class(data[4]) != elf.ELFCLASS64 || elf.Data(data[5]) != elf.ELFDATA2LSB {
		t.Skip("fixture mutation expects little-endian ELF64")
	}
	clear(data[40:48]) // e_shoff
	clear(data[60:64]) // e_shnum and e_shstrndx
	require.NoError(t, os.WriteFile(input, data, 0644))
	wrong, err := os.ReadFile(library)
	require.NoError(t, err)
	binary.LittleEndian.PutUint16(wrong[18:20], uint16(elf.EM_NONE))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "invalid"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "invalid/libfixture.so"), wrong, 0644))
	nodes, err := targetResolver(t, root, Options{}).Resolve(context.Background(), "/root.so")
	require.NoError(t, err)
	require.Equal(t, "/valid/libfixture.so", nodes[1].Path)
	require.NoError(t, os.Remove(library))
	nodes, err = targetResolver(t, root, Options{}).Resolve(context.Background(), "/root.so")
	require.NoError(t, err)
	require.Equal(t, "missing", nodes[1].Status)
	require.Contains(t, nodes[1].Reason, "incompatible ELF")
}

func TestExecutableAndCorruptFirstCandidatesAreNotResolvedAsLibraries(t *testing.T) {
	root := t.TempDir()
	library := compileLibrary(t, root, "/first/libfixture.so", "libfixture.so", nil, "", false)
	compileLibrary(t, root, "/fallback/libfixture.so", "libfixture.so", nil, "", false)
	compileLibrary(t, root, "/root.so", "root.so", []string{library}, "/first:/fallback", false)
	compiler, err := exec.LookPath("gcc")
	require.NoError(t, err)
	command := exec.Command(compiler, "-nostdlib", "-pie", "-x", "c", "-", "-o", library, "-Wl,-e,fixture")
	command.Stdin = strings.NewReader("int fixture(void) { return 7; }\n")
	output, err := command.CombinedOutput()
	require.NoError(t, err, "%s", output)
	nodes, err := targetResolver(t, root, Options{}).Resolve(context.Background(), "/root.so")
	require.NoError(t, err)
	require.Equal(t, "missing", nodes[1].Status)
	require.Contains(t, nodes[1].Reason, "executable")
	require.NoError(t, os.WriteFile(library, []byte("invalid library"), 0644))
	nodes, err = targetResolver(t, root, Options{}).Resolve(context.Background(), "/root.so")
	require.NoError(t, err)
	require.Equal(t, "missing", nodes[1].Status)
	require.Contains(t, nodes[1].Reason, "not a supported ELF")
}

func TestConcurrentResolveAndCancellation(t *testing.T) {
	root := t.TempDir()
	library := compileLibrary(t, root, "/lib/libfixture.so", "libfixture.so", nil, "", false)
	compileLibrary(t, root, "/root.so", "root.so", []string{library}, "", false)
	resolver := targetResolver(t, root, Options{})
	var wait sync.WaitGroup
	errorsSeen := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			nodes, err := resolver.Resolve(context.Background(), "/root.so")
			if err == nil && (len(nodes) != 2 || nodes[1].Status != "resolved") {
				err = errors.New("incorrect concurrent graph")
			}
			errorsSeen <- err
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		require.NoError(t, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := resolver.Resolve(ctx, "/root.so")
	require.ErrorIs(t, err, context.Canceled)
	require.NoError(t, os.WriteFile(filepath.Join(root, "text"), []byte("hello"), 0644))
	_, err = resolver.Resolve(context.Background(), "/text")
	require.ErrorIs(t, err, ErrNotELF)
}
