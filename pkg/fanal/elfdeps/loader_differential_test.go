package elfdeps

import (
	"context"
	"debug/elf"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The oracle is the trusted host glibc loader in --list mode. It only inspects
// harmless ELF fixtures compiled from the constant C source below. This test
// never executes repository, image, downloaded or user-provided binaries.
type differentialFixture struct {
	t        *testing.T
	root     string
	compiler string
	builds   [][]string
}

type differentialRequest struct {
	input       string
	environment string
	workingDir  string
	want        map[string]string
	missing     string
	knownLimit  string
}

type differentialEvidence struct {
	Scenario               string
	Input                  string
	TargetLibraryPath      string
	TargetWorkingDirectory string
	BuildCommands          [][]string
	LoaderCommand          []string
	LoaderOutput           string
	LoaderError            string
	LoaderFiles            map[string]string
	LoaderMissing          string
	ResolverNodes          []Node
	ResolverFiles          map[string]string
	ResolverMissing        []string
	Matches                bool
	KnownLimitation        string
	ConservativeUnresolved bool
}

func (f *differentialFixture) host(name string) string { return f.root + name }

func (f *differentialFixture) build(name, soname string, dependencies []string, search string, runpath bool, extra ...string) string {
	f.t.Helper()
	output := f.host(name)
	require.NoError(f.t, os.MkdirAll(filepath.Dir(output), 0755))
	args := []string{"-x", "c", "-", "-x", "none", "-Wl,--no-as-needed", "-Wl,--allow-shlib-undefined", "-o", output}
	source := "int main(void) { return 0; }\n"
	if soname != "" {
		args = append(args, "-shared", "-nostdlib", "-fPIC", "-Wl,-soname,"+soname)
		source = "int fixture_marker(void) { return 0; }\n"
	}
	if search != "" {
		dtags := "--disable-new-dtags"
		if runpath {
			dtags = "--enable-new-dtags"
		}
		args = append(args, "-Wl,"+dtags, "-Wl,-rpath,"+search)
	}
	args = append(args, extra...)
	args = append(args, dependencies...)
	f.builds = append(f.builds, append([]string{f.compiler}, args...))
	command := exec.Command(f.compiler, args...)
	command.Stdin = strings.NewReader(source)
	outputLog, err := command.CombinedOutput()
	if err != nil && len(extra) > 0 && extra[0] == "-m32" {
		f.t.Skipf("host compiler has no ELF32 support: %s", outputLog)
	}
	require.NoError(f.t, err, "%s", outputLog)
	return output
}

func (f *differentialFixture) link(target, name string) {
	f.t.Helper()
	require.NoError(f.t, os.MkdirAll(filepath.Dir(f.host(name)), 0755))
	require.NoError(f.t, os.Symlink(target, f.host(name)))
}

func differentialInterpreter(t *testing.T, name, family string) string {
	t.Helper()
	file, err := elf.Open(name)
	require.NoError(t, err)
	defer file.Close()
	for _, p := range file.Progs {
		if p.Type == elf.PT_INTERP {
			data := make([]byte, p.Filesz)
			_, err = p.ReadAt(data, 0)
			require.NoError(t, err)
			interpreter := strings.TrimRight(string(data), "\x00")
			if !strings.Contains(filepath.Base(interpreter), family) {
				t.Skipf("this differential oracle requires a %s compiler", family)
			}
			return interpreter
		}
	}
	t.Fatal("compiled executable has no PT_INTERP")
	return ""
}

func differentialEnvironment(root, libraryPath string) []string {
	var environment []string
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "LD_") && !strings.HasPrefix(value, "GLIBC_TUNABLES=") && !strings.HasPrefix(value, "LC_ALL=") {
			environment = append(environment, value)
		}
	}
	environment = append(environment, "LC_ALL=C")
	if libraryPath != "" {
		parts := strings.Split(libraryPath, ":")
		for i, part := range parts {
			if strings.HasPrefix(part, "/") {
				parts[i] = root + part
			}
		}
		environment = append(environment, "LD_LIBRARY_PATH="+strings.Join(parts, ":"))
	}
	return environment
}

func TestLoaderDifferential(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("glibc x86-64 loader oracle")
	}
	compiler, err := exec.LookPath("gcc")
	if err != nil {
		t.Skip("gcc required for self-built loader fixtures")
	}
	directory := t.TempDir()
	if retained := os.Getenv("BOLT_ELF_LOADER_AUDIT_DIR"); retained != "" {
		require.NoError(t, os.MkdirAll(retained, 0755))
		directory, err = os.MkdirTemp(retained, "run-")
		require.NoError(t, err)
	}
	var evidence []differentialEvidence
	t.Cleanup(func() {
		data, marshalErr := json.MarshalIndent(evidence, "", "  ")
		require.NoError(t, marshalErr)
		require.NoError(t, os.WriteFile(filepath.Join(directory, "loader-comparison.json"), append(data, '\n'), 0644))
		t.Logf("differential evidence: %s", filepath.Join(directory, "loader-comparison.json"))
	})
	const choice = "libbolt_choice.so"
	const a = "libbolt_a.so"
	const b = "libbolt_b.so"
	const c = "libbolt_c.so"
	cases := []struct {
		name    string
		prepare func(*differentialFixture) []differentialRequest
	}{
		{"rpath_before_environment", func(f *differentialFixture) []differentialRequest {
			lib := f.build("/rpath/"+choice, choice, nil, "", false)
			f.build("/env/"+choice, choice, nil, "", false)
			f.build("/bin/app", "", []string{lib}, "$ORIGIN/../rpath", false)
			return []differentialRequest{{input: "/bin/app", environment: "/env", want: map[string]string{choice: "/rpath/" + choice}}}
		}},
		{"environment_before_runpath", func(f *differentialFixture) []differentialRequest {
			lib := f.build("/runpath/"+choice, choice, nil, "", false)
			f.build("/env/"+choice, choice, nil, "", false)
			f.build("/bin/app", "", []string{lib}, "$ORIGIN/../runpath", true)
			return []differentialRequest{{input: "/bin/app", environment: "/env", want: map[string]string{choice: "/env/" + choice}}}
		}},
		{"ancestor_rpath_is_inherited", func(f *differentialFixture) []differentialRequest {
			child := f.build("/private/"+b, b, nil, "", false)
			parent := f.build("/private/"+a, a, []string{child}, "", false)
			f.build("/bin/app", "", []string{parent}, "$ORIGIN/../private", false)
			return []differentialRequest{{input: "/bin/app", want: map[string]string{a: "/private/" + a, b: "/private/" + b}}}
		}},
		{"runpath_is_not_inherited", func(f *differentialFixture) []differentialRequest {
			child := f.build("/private/"+b, b, nil, "", false)
			parent := f.build("/private/"+a, a, []string{child}, "", false)
			f.build("/bin/app", "", []string{parent}, "$ORIGIN/../private", true)
			return []differentialRequest{{input: "/bin/app", missing: b}}
		}},
		{"child_runpath_suppresses_ancestor_rpath", func(f *differentialFixture) []differentialRequest {
			child := f.build("/child/"+choice, choice, nil, "", false)
			f.build("/ancestor/"+choice, choice, nil, "", false)
			parent := f.build("/ancestor/"+a, a, []string{child}, "$ORIGIN/../child", true)
			f.build("/bin/app", "", []string{parent}, "$ORIGIN/../ancestor", false)
			return []differentialRequest{{input: "/bin/app", want: map[string]string{a: "/ancestor/" + a, choice: "/child/" + choice}}}
		}},
		{"duplicate_soname_breadth_first", func(f *differentialFixture) []differentialRequest {
			first := f.build("/first/"+choice, choice, nil, "", false)
			second := f.build("/second/"+choice, choice, nil, "", false)
			middle := f.build("/first/"+c, c, []string{first}, "$ORIGIN", true)
			left := f.build("/first/"+a, a, []string{middle}, "$ORIGIN", true)
			right := f.build("/second/"+b, b, []string{second}, "$ORIGIN", true)
			f.build("/bin/app", "", []string{left, right}, "$ORIGIN/../first:$ORIGIN/../second", true)
			return []differentialRequest{{input: "/bin/app", want: map[string]string{a: "/first/" + a, b: "/second/" + b, c: "/first/" + c, choice: "/second/" + choice}}}
		}},
		{"dso_alias_origin_and_cache_isolation", func(f *differentialFixture) []differentialRequest {
			child := f.build("/bundle/"+b, b, nil, "", false)
			f.build("/shared/"+b, b, nil, "", false)
			parent := f.build("/shared/"+a, a, []string{child}, "$ORIGIN", true)
			f.link("../shared/"+a, "/bundle/"+a)
			f.build("/bin/alias-app", "", []string{parent}, "$ORIGIN/../bundle", true)
			f.build("/bin/direct-app", "", []string{parent}, "$ORIGIN/../shared", true)
			return []differentialRequest{
				{input: "/bin/alias-app", want: map[string]string{a: "/shared/" + a, b: "/bundle/" + b}},
				{input: "/bin/direct-app", want: map[string]string{a: "/shared/" + a, b: "/shared/" + b}},
			}
		}},
		{"symlink_then_parent_traversal", func(f *differentialFixture) []differentialRequest {
			lib := f.build("/deep/pick/"+choice, choice, nil, "", false)
			f.build("/pick/"+choice, choice, nil, "", false)
			require.NoError(f.t, os.MkdirAll(f.host("/deep/middle"), 0755))
			f.link("deep/middle", "/alias")
			f.build("/bin/app", "", []string{lib}, "$ORIGIN/../alias/../pick", true)
			return []differentialRequest{{input: "/bin/app", want: map[string]string{choice: "/deep/pick/" + choice}}}
		}},
		{"incompatible_elf32_candidate_is_skipped", func(f *differentialFixture) []differentialRequest {
			f.build("/wrong/"+choice, choice, nil, "", false, "-m32")
			lib := f.build("/valid/"+choice, choice, nil, "", false)
			f.build("/bin/app", "", []string{lib}, "$ORIGIN/../wrong:$ORIGIN/../valid", true)
			return []differentialRequest{{input: "/bin/app", want: map[string]string{choice: "/valid/" + choice}}}
		}},
		{"environment_colon_uses_working_directory", func(f *differentialFixture) []differentialRequest {
			lib := f.build("/work/"+choice, choice, nil, "", false)
			f.build("/bin/app", "", []string{lib}, "", false)
			return []differentialRequest{{input: "/bin/app", environment: ":", workingDir: "/work", want: map[string]string{choice: "/work/" + choice}}}
		}},
		{"environment_middle_empty_uses_working_directory", func(f *differentialFixture) []differentialRequest {
			lib := f.build("/work/"+choice, choice, nil, "", false)
			require.NoError(f.t, os.MkdirAll(f.host("/other"), 0755))
			f.build("/bin/app", "", []string{lib}, "", false)
			return []differentialRequest{{input: "/bin/app", environment: "/other::/other", workingDir: "/work", want: map[string]string{choice: "/work/" + choice}}}
		}},
		{"unsupported_lib_token_shadows_fallback", func(f *differentialFixture) []differentialRequest {
			for _, directory := range []string{"lib", "lib64", "lib/x86_64-linux-gnu"} {
				f.build("/tokens/"+directory+"/"+choice, choice, nil, "", false)
			}
			fallback := f.build("/fallback/"+choice, choice, nil, "", false)
			f.build("/bin/app", "", []string{fallback}, "$ORIGIN/../tokens/$LIB:$ORIGIN/../fallback", true)
			return []differentialRequest{{input: "/bin/app", knownLimit: "$LIB expansion depends on the target loader; the resolver conservatively leaves this dependency unresolved"}}
		}},
	}
	loadedPattern := regexp.MustCompile(`(?m)^\s*(libbolt_[^\s]+)(?:\s+=>\s+(\S+))?\s+\(0x`)
	missingPattern := regexp.MustCompile(`error while loading shared libraries: (libbolt_[^:\s]+):`)
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := &differentialFixture{t: t, root: filepath.Join(directory, testCase.name), compiler: compiler}
			require.NoError(t, os.MkdirAll(fixture.root, 0755))
			requests := testCase.prepare(fixture)
			filesystem, err := NewLocalFS(fixture.root)
			require.NoError(t, err)
			var resolver *Resolver
			for i, request := range requests {
				if request.workingDir == "" {
					request.workingDir = "/"
				}
				if resolver == nil {
					var paths []string
					if request.environment != "" {
						paths = []string{request.environment}
					}
					resolver = NewResolver(filesystem, Options{LibraryPath: paths, WorkingDir: request.workingDir})
				}
				loader := differentialInterpreter(t, fixture.host(request.input), "ld-linux")
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				command := exec.CommandContext(ctx, loader, "--list", fixture.host(request.input))
				command.Dir = fixture.host(request.workingDir)
				command.Env = differentialEnvironment(fixture.root, request.environment)
				output, loaderErr := command.CombinedOutput()
				cancel()
				record := differentialEvidence{Scenario: testCase.name, Input: request.input, TargetLibraryPath: request.environment,
					TargetWorkingDirectory: request.workingDir, BuildCommands: fixture.builds, LoaderCommand: command.Args,
					LoaderOutput: string(output), LoaderFiles: map[string]string{}, ResolverFiles: map[string]string{}, KnownLimitation: request.knownLimit}
				if loaderErr != nil {
					record.LoaderError = loaderErr.Error()
				}
				for _, match := range loadedPattern.FindAllStringSubmatch(string(output), -1) {
					pathname := match[2]
					if pathname == "" {
						// glibc prints only the basename when an empty search
						// element selected the library in the process CWD.
						pathname = match[1]
					}
					if !filepath.IsAbs(pathname) {
						pathname = command.Dir + "/" + pathname
					}
					canonical, err := filepath.EvalSymlinks(pathname)
					require.NoError(t, err)
					require.True(t, strings.HasPrefix(canonical, fixture.root+"/"), "fixture dependency escaped: %s", canonical)
					record.LoaderFiles[match[1]] = strings.TrimPrefix(canonical, fixture.root)
				}
				if match := missingPattern.FindStringSubmatch(string(output)); match != nil {
					record.LoaderMissing = match[1]
				}
				nodes, err := resolver.Resolve(context.Background(), request.input)
				require.NoError(t, err)
				record.ResolverNodes = nodes
				for _, node := range nodes {
					if !strings.HasPrefix(node.Name, "libbolt_") {
						continue
					}
					if node.Status == "resolved" {
						record.ResolverFiles[node.Name] = node.Path
					} else {
						record.ResolverMissing = append(record.ResolverMissing, node.Name)
						if request.knownLimit != "" && node.Name == choice && strings.Contains(node.Reason, "unsupported dynamic string token in loader search path") {
							record.ConservativeUnresolved = true
						}
					}
				}
				sort.Strings(record.ResolverMissing)
				if request.missing != "" {
					record.Matches = record.LoaderMissing == request.missing && reflect.DeepEqual(record.ResolverMissing, []string{request.missing})
				} else {
					record.Matches = loaderErr == nil && len(record.ResolverMissing) == 0 && reflect.DeepEqual(record.LoaderFiles, record.ResolverFiles)
				}
				evidence = append(evidence, record)
				require.NoError(t, os.WriteFile(filepath.Join(fixture.root, fmt.Sprintf("loader-%d.log", i)), output, 0644))
				if request.want != nil {
					require.Equal(t, request.want, record.LoaderFiles, "oracle fixture did not establish the expected loader choice: %s", output)
				}
				if request.missing != "" {
					require.Equal(t, request.missing, record.LoaderMissing, "%s", output)
				} else {
					require.NoError(t, loaderErr, "%s", output)
				}
				if request.knownLimit != "" {
					require.Contains(t, record.LoaderFiles[choice], "/tokens/", "the host must expand $LIB for this boundary test")
					require.True(t, record.ConservativeUnresolved, "unsupported higher-priority token must not select a lower fallback")
					require.Empty(t, record.ResolverFiles)
					t.Logf("documented boundary: parity=%t actual=%v resolver=%v", record.Matches, record.LoaderFiles, record.ResolverFiles)
				} else {
					require.True(t, record.Matches, "actual=%v missing=%s; resolver=%v missing=%v", record.LoaderFiles, record.LoaderMissing, record.ResolverFiles, record.ResolverMissing)
				}
			}
		})
	}
}

func TestUnsupportedSearchTokenPreservesOrder(t *testing.T) {
	compiler, err := exec.LookPath("gcc")
	if err != nil {
		t.Skip("gcc required for ELF fixtures")
	}
	f := &differentialFixture{t: t, root: t.TempDir(), compiler: compiler}
	const choice = "libbolt_order.so"
	good := f.build("/good/"+choice, choice, nil, "", false)
	f.build("/fallback/"+choice, choice, nil, "", false)
	for _, tc := range []struct {
		name   string
		search string
		want   string
	}{
		{"known_first", "$ORIGIN/../good:$ORIGIN/../tokens/$LIB", "/good/" + choice},
		{"missing_then_unknown", "$ORIGIN/../absent:$ORIGIN/../tokens/$LIB:$ORIGIN/../fallback", ""},
		{"unknown_first", "$ORIGIN/../tokens/${PLATFORM}:$ORIGIN/../fallback", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f.build("/bin/"+tc.name, "", []string{good}, tc.search, true)
			fs, err := NewLocalFS(f.root)
			require.NoError(t, err)
			nodes, err := NewResolver(fs, Options{}).Resolve(context.Background(), "/bin/"+tc.name)
			require.NoError(t, err)
			for _, node := range nodes {
				if node.Name != choice {
					continue
				}
				if tc.want != "" {
					require.Equal(t, "resolved", node.Status)
					require.Equal(t, tc.want, node.Path)
				} else {
					require.Equal(t, "missing", node.Status)
					require.Empty(t, node.Path)
					require.Contains(t, node.Reason, "unsupported dynamic string token in loader search path")
				}
				return
			}
			t.Fatalf("expected custom dependency %s", choice)
		})
	}
	t.Run("already_loaded_soname_bypasses_uncertain_search", func(t *testing.T) {
		parent := f.build("/good/libbolt_parent.so", "libbolt_parent.so", []string{good}, "$ORIGIN/../tokens/$LIB:$ORIGIN/../fallback", true)
		f.build("/bin/reuse", "", []string{good, parent}, "$ORIGIN/../good", true)
		fs, err := NewLocalFS(f.root)
		require.NoError(t, err)
		nodes, err := NewResolver(fs, Options{}).Resolve(context.Background(), "/bin/reuse")
		require.NoError(t, err)
		var matches int
		for _, node := range nodes {
			if node.Name == choice {
				matches++
				require.Equal(t, "resolved", node.Status)
				require.Equal(t, "/good/"+choice, node.Path)
			}
		}
		require.Equal(t, 1, matches)
	})
}

func TestMuslLiteralEnvironmentDifferential(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("musl loader oracle requires Linux")
	}
	compiler, err := exec.LookPath("musl-gcc")
	if err != nil {
		t.Skip("musl-gcc is optional")
	}
	directory := t.TempDir()
	if retained := os.Getenv("BOLT_ELF_LOADER_AUDIT_DIR"); retained != "" {
		require.NoError(t, os.MkdirAll(retained, 0755))
		directory, err = os.MkdirTemp(retained, "musl-")
		require.NoError(t, err)
	}
	f := &differentialFixture{t: t, root: directory, compiler: compiler}
	const library = "libbolt_musl.so"
	first := f.build("/left/"+library, library, nil, "", false)
	f.build("/right/"+library, library, nil, "", false)
	f.build("/left;/right/"+library, library, nil, "", false)
	f.build("/work/$ORIGIN/literal/"+library, library, nil, "", false)
	f.build("/bin/app", "", []string{first}, "", false)
	loader := differentialInterpreter(t, f.host("/bin/app"), "ld-musl")
	fs, err := NewLocalFS(f.root)
	require.NoError(t, err)
	var evidence []differentialEvidence
	for _, tc := range []struct{ name, env, want string }{
		{"colon_separates_directories", "/left:/right", "/left/" + library},
		{"semicolon_is_literal", "/left;/right", "/left;/right/" + library},
		{"origin_token_is_literal", "$ORIGIN/literal", "/work/$ORIGIN/literal/" + library},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, loader, "--list", f.host("/bin/app"))
			command.Dir = f.host("/work")
			command.Env = differentialEnvironment(f.root, tc.env)
			output, err := command.CombinedOutput()
			require.NoError(t, err, "%s", output)
			pattern := regexp.MustCompile(`(?m)^\s*libbolt_musl\.so\s+=>\s+(\S+)`)
			match := pattern.FindStringSubmatch(string(output))
			require.Len(t, match, 2, "%s", output)
			pathname := match[1]
			if !filepath.IsAbs(pathname) {
				pathname = command.Dir + "/" + pathname
			}
			canonical, err := filepath.EvalSymlinks(pathname)
			require.NoError(t, err)
			actual := strings.TrimPrefix(canonical, f.root)
			nodes, err := NewResolver(fs, Options{LibraryPath: []string{tc.env}, WorkingDir: "/work"}).Resolve(context.Background(), "/bin/app")
			require.NoError(t, err)
			resolved := map[string]string{}
			for _, node := range nodes {
				if node.Name == library && node.Status == "resolved" {
					resolved[library] = node.Path
				}
			}
			record := differentialEvidence{Scenario: "musl_" + tc.name, Input: "/bin/app", TargetLibraryPath: tc.env, TargetWorkingDirectory: "/work",
				BuildCommands: f.builds, LoaderCommand: command.Args, LoaderOutput: string(output), LoaderFiles: map[string]string{library: actual},
				ResolverNodes: nodes, ResolverFiles: resolved, Matches: actual == tc.want && resolved[library] == actual}
			evidence = append(evidence, record)
			require.NoError(t, os.WriteFile(filepath.Join(directory, tc.name+".log"), output, 0644))
			require.True(t, record.Matches, "actual=%s resolver=%v expected=%s", actual, resolved, tc.want)
		})
	}
	data, err := json.MarshalIndent(evidence, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(directory, "musl-comparison.json"), append(data, '\n'), 0644))
	t.Logf("musl evidence: %s", filepath.Join(directory, "musl-comparison.json"))
}
