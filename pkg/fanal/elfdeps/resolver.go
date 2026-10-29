// Package elfdeps resolves declared ELF dependencies without executing target
// code. Every read is confined to the supplied target filesystem.
package elfdeps

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
)

type File interface {
	io.Reader
	io.ReaderAt
	io.Closer
}

// Open follows target symlinks and returns an absolute canonical virtual path.
// Glob must also operate exclusively inside the target filesystem.
type FS interface {
	Open(name string) (File, string, error)
	Glob(pattern string) ([]string, error)
}

type Options struct {
	LibraryPath []string
	WorkingDir  string
}

type Node struct {
	ID        string   `json:"id,omitempty"`
	Name      string   `json:"name"`
	Path      string   `json:"path,omitempty"`
	DependsOn []string `json:"dependsOn"`
	Status    string   `json:"status,omitempty"`
	Reason    string   `json:"reason,omitempty"`
	Kind      string   `json:"kind,omitempty"`
}

var ErrNotELF = errors.New("not an ELF file")

type elfInfo struct {
	path       string
	loadPath   string // Per-resolution pathname; never stored in parsed metadata.
	class      elf.Class
	machine    elf.Machine
	data       elf.Data
	fileType   elf.Type
	kind       string
	needed     []string
	rpath      []string
	runpath    []string
	hasRunpath bool
	soname     string
	interp     string
	nodefault  bool
	pie        bool
}

type parsedELF struct {
	info *elfInfo
	err  error
}

// Resolver can be shared by concurrent scans of an immutable target filesystem.
// Only parsed metadata is shared; loaded objects and search contexts are per root.
type Resolver struct {
	fs         FS
	opts       Options
	mu         sync.Mutex
	elfs       map[string]parsedELF
	conf       []string
	confLoaded bool
}

func NewResolver(filesystem FS, opts Options) *Resolver {
	opts.LibraryPath = append([]string(nil), opts.LibraryPath...)
	if !path.IsAbs(opts.WorkingDir) {
		opts.WorkingDir = "/"
	}
	return &Resolver{fs: filesystem, opts: opts, elfs: make(map[string]parsedELF)}
}

type loadFrame struct {
	info      *elfInfo
	index     int
	inherited []searchDirectory
}

// Preserve uncertainty at its position in the search order. Dropping an
// unsupported token could incorrectly select a lower-priority library. Literal
// musl environment/configuration paths are deliberately not marked uncertain.
type searchDirectory struct {
	path             string
	unsupportedToken bool
}

// Resolve returns a graph rooted at name, including explicit missing nodes.
// This models DT_NEEDED loading, not dlopen, symbol binding or execution. GNU
// ld.so.cache/hwcaps and secure-execution state are not emulated. ld.so.conf is
// used as a documented cache-directory approximation, never a basename scan.
func (r *Resolver) Resolve(ctx context.Context, name string) ([]Node, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r.fs == nil {
		return nil, errors.New("target filesystem is required")
	}
	root, err := r.readELF(ctx, r.absolute(name))
	if err != nil {
		return nil, fmt.Errorf("read ELF %q: %w", name, err)
	}
	if root.kind == "application" {
		// The executable's origin is canonical; a loaded DSO's origin is
		// the pathname used to open it, including any directory aliases.
		root.loadPath = root.path
	}
	nodes := []Node{{ID: root.path, Name: path.Base(root.path), Path: root.path, DependsOn: []string{}, Status: "resolved", Kind: root.kind}}
	indices := map[string]int{root.path: 0}
	loaded := make(map[string]*elfInfo)
	if root.soname != "" {
		loaded[root.soname] = root
	}
	musl := strings.HasPrefix(path.Base(root.interp), "ld-musl-")
	environment := r.expandSearchPaths(r.opts.LibraryPath, root.loadPath, musl)
	if musl {
		environment = literalSearchDirectories(r.muslLiteralPaths(r.opts.LibraryPath))
	}
	systemPaths, systemReason := r.systemPaths(ctx, root)
	nodes[0].Reason = systemReason
	queue := []loadFrame{{info: root}}
	for head := 0; head < len(queue); head++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		frame := queue[head]
		ownRPath := []searchDirectory(nil)
		if musl && frame.info.hasRunpath {
			ownRPath = r.expandSearchPaths(frame.info.runpath, frame.info.loadPath, true)
		} else if !frame.info.hasRunpath {
			ownRPath = r.expandSearchPaths(frame.info.rpath, frame.info.loadPath, musl)
		}
		inherited := append(append([]searchDirectory(nil), ownRPath...), frame.inherited...)
		var search []searchDirectory
		if musl {
			// musl searches the environment first and inherits either dynamic
			// path tag through the loader chain; RUNPATH overrides RPATH.
			search = append(search, environment...)
			search = append(search, inherited...)
		} else {
			// A GNU caller with RUNPATH does not consult its loader chain's RPATH.
			if !frame.info.hasRunpath {
				search = append(search, inherited...)
			}
			search = append(search, environment...)
			search = append(search, r.expandPaths(frame.info.runpath, frame.info.loadPath)...)
		}
		if !musl && frame.info.nodefault {
			// NODEFLIB suppresses built-in default directories, not custom
			// directories represented by the target's ld.so.conf.
			defaults := defaultPaths(root)
			for _, directory := range systemPaths {
				if !contains(defaults, directory) {
					search = append(search, searchDirectory{path: directory})
				}
			}
		} else {
			search = append(search, literalSearchDirectories(systemPaths)...)
		}
		search = uniqueSearchDirectories(search)
		for _, needed := range frame.info.needed {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			expanded, tokenOK := expandOrigin(needed, frame.info.loadPath)
			if musl {
				expanded, tokenOK = needed, true // musl treats DT_NEEDED names literally.
			}
			var dependency *elfInfo
			reason := ""
			if !tokenOK {
				reason = "unsupported dynamic string token in DT_NEEDED"
			} else if !strings.Contains(expanded, "/") {
				dependency = loaded[expanded]
			}
			if dependency == nil && tokenOK {
				dependency, reason, err = r.find(ctx, root, expanded, search)
				if err != nil {
					return nil, err
				}
			}
			var id string
			if dependency == nil {
				id = dependencyNodeID(root.path, "missing", frame.info.path, needed)
				if _, exists := indices[id]; !exists {
					indices[id] = len(nodes)
					nodes = append(nodes, Node{ID: id, Name: path.Base(needed), DependsOn: []string{}, Status: "missing", Reason: reason})
				}
			} else {
				index, exists := indices[dependency.path]
				if !exists {
					index = len(nodes)
					indices[dependency.path] = index
					id = dependencyNodeID(root.path, "resolved", dependency.path)
					nodeReason := ""
					if systemReason != "" && contains(systemPaths, path.Dir(dependency.path)) {
						nodeReason = systemReason
					}
					// A DT_NEEDED dependency has the library role even if it is
					// independently executable (for example, glibc's libc.so.6).
					// Keep parsed metadata intact for later root resolutions.
					nodes = append(nodes, Node{ID: id, Name: path.Base(needed), Path: dependency.path, DependsOn: []string{}, Status: "resolved", Reason: nodeReason, Kind: "library"})
					queue = append(queue, loadFrame{info: dependency, index: index, inherited: inherited})
				}
				id = nodes[index].ID
				if !strings.Contains(expanded, "/") {
					loaded[expanded] = dependency
				}
				if dependency.soname != "" && loaded[dependency.soname] == nil {
					loaded[dependency.soname] = dependency
				}
			}
			if !contains(nodes[frame.index].DependsOn, id) {
				nodes[frame.index].DependsOn = append(nodes[frame.index].DependsOn, id)
			}
		}
	}
	return nodes, nil
}

// Root IDs are absolute paths; contextual nodes use a separate namespace and
// an unambiguous tuple. Concatenating paths with "::" collides with valid Linux
// filenames such as the executable /a::/b and /a's dependency /b.
func dependencyNodeID(parts ...string) string {
	payload, _ := json.Marshal(parts) // A slice of strings is always encodable.
	return fmt.Sprintf("urn:bolt:elf:%x", sha256.Sum256(payload))
}

func (r *Resolver) find(ctx context.Context, root *elfInfo, needed string, search []searchDirectory) (*elfInfo, string, error) {
	var candidates []searchDirectory
	if strings.Contains(needed, "/") {
		candidates = []searchDirectory{{path: r.absolute(needed)}}
	} else {
		for _, directory := range search {
			candidates = append(candidates, searchDirectory{path: joinVirtual(directory.path, needed), unsupportedToken: directory.unsupportedToken})
		}
	}
	reason := "not found in target loader search paths"
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		if candidate.unsupportedToken {
			return nil, "unsupported dynamic string token in loader search path prevents determining library search order", nil
		}
		info, err := r.readELF(ctx, candidate.path)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, "", err
			}
			if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, syscall.ENOTDIR) {
				reason = "target library candidate is unreadable or not a supported ELF: " + err.Error()
				if !errors.Is(err, fs.ErrPermission) {
					return nil, reason, nil
				}
			}
			continue
		}
		if info.class != root.class || info.machine != root.machine || info.data != root.data {
			reason = "only incompatible ELF class, machine or byte order found in target search paths"
			continue
		}
		if info.fileType != elf.ET_DYN || info.pie {
			reason = "target library candidate is an executable, not a shared object"
			return nil, reason, nil
		}
		return info, "", nil
	}
	return nil, reason, nil
}

func (r *Resolver) readELF(ctx context.Context, name string) (*elfInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, canonical, err := r.fs.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	r.mu.Lock()
	defer r.mu.Unlock()
	if cached, ok := r.elfs[canonical]; ok {
		return withLoadPath(cached.info, name), cached.err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info, err := parseELF(file, canonical)
	r.elfs[canonical] = parsedELF{info: info, err: err}
	return withLoadPath(info, name), err
}

func withLoadPath(info *elfInfo, name string) *elfInfo {
	if info == nil {
		return nil
	}
	copy := *info
	copy.loadPath = name
	return &copy
}

// Reading PT_DYNAMIC instead of relying on section names also supports ELF
// files whose section table has been removed. All allocations are bounded.
func parseELF(reader io.ReaderAt, canonical string) (*elfInfo, error) {
	var magic [4]byte
	if _, err := reader.ReadAt(magic[:], 0); err != nil || string(magic[:]) != "\x7fELF" {
		return nil, ErrNotELF
	}
	file, err := elf.NewFile(reader)
	if err != nil {
		return nil, err
	}
	if file.Type != elf.ET_EXEC && file.Type != elf.ET_DYN {
		return nil, fmt.Errorf("%w: ELF type %s is not a runtime object", ErrNotELF, file.Type)
	}
	info := &elfInfo{path: canonical, class: file.Class, machine: file.Machine, data: file.Data, fileType: file.Type}
	info.kind = "library"
	if file.Type == elf.ET_EXEC {
		info.kind = "application"
	}
	var dynamic []byte
	for _, program := range file.Progs {
		switch program.Type {
		case elf.PT_INTERP:
			if program.Filesz > 4096 {
				return nil, errors.New("ELF interpreter path exceeds limit")
			}
			data, err := io.ReadAll(program.Open())
			if err != nil {
				return nil, err
			}
			info.interp = strings.TrimRight(string(data), "\x00")
			info.kind = "application"
		case elf.PT_DYNAMIC:
			if program.Filesz > 8<<20 {
				return nil, errors.New("ELF dynamic table exceeds limit")
			}
			dynamic, err = io.ReadAll(program.Open())
			if err != nil {
				return nil, err
			}
		}
	}
	if len(dynamic) == 0 {
		return info, nil
	}
	width := 8
	if file.Class == elf.ELFCLASS64 {
		width = 16
	}
	if len(dynamic)%width != 0 {
		return nil, errors.New("invalid ELF dynamic table size")
	}
	tags := make(map[elf.DynTag][]uint64)
	for offset := 0; offset+width <= len(dynamic); offset += width {
		var tag, value uint64
		if width == 16 {
			tag = file.ByteOrder.Uint64(dynamic[offset:])
			value = file.ByteOrder.Uint64(dynamic[offset+8:])
		} else {
			tag = uint64(file.ByteOrder.Uint32(dynamic[offset:]))
			value = uint64(file.ByteOrder.Uint32(dynamic[offset+4:]))
		}
		if tag == uint64(elf.DT_NULL) {
			break
		}
		tags[elf.DynTag(tag)] = append(tags[elf.DynTag(tag)], value)
	}
	for _, flags := range tags[elf.DT_FLAGS_1] {
		info.nodefault = info.nodefault || flags&uint64(elf.DF_1_NODEFLIB) != 0
		info.pie = info.pie || flags&uint64(elf.DF_1_PIE) != 0
	}
	if len(tags[elf.DT_NEEDED])+len(tags[elf.DT_RPATH])+len(tags[elf.DT_RUNPATH])+len(tags[elf.DT_SONAME]) == 0 {
		return info, nil
	}
	if len(tags[elf.DT_STRTAB]) == 0 || len(tags[elf.DT_STRSZ]) == 0 {
		return nil, errors.New("ELF dynamic string table missing")
	}
	address, size := tags[elf.DT_STRTAB][0], tags[elf.DT_STRSZ][0]
	if size > 64<<20 {
		return nil, errors.New("ELF dynamic string table exceeds limit")
	}
	var stringTable []byte
	for _, program := range file.Progs {
		if program.Type != elf.PT_LOAD || address < program.Vaddr {
			continue
		}
		delta := address - program.Vaddr
		if delta > program.Filesz || size > program.Filesz-delta {
			continue
		}
		stringTable = make([]byte, int(size))
		if _, err := reader.ReadAt(stringTable, int64(program.Off+delta)); err != nil {
			return nil, err
		}
		break
	}
	if stringTable == nil {
		return nil, errors.New("ELF dynamic string table is outside load segments")
	}
	readStrings := func(tag elf.DynTag) ([]string, error) {
		var values []string
		for _, offset := range tags[tag] {
			if offset >= uint64(len(stringTable)) {
				return nil, errors.New("ELF dynamic string offset is out of bounds")
			}
			end := bytes.IndexByte(stringTable[offset:], 0)
			if end < 0 {
				return nil, errors.New("unterminated ELF dynamic string")
			}
			values = append(values, string(stringTable[offset:offset+uint64(end)]))
		}
		return values, nil
	}
	if info.needed, err = readStrings(elf.DT_NEEDED); err != nil {
		return nil, err
	}
	if info.rpath, err = readStrings(elf.DT_RPATH); err != nil {
		return nil, err
	}
	if info.runpath, err = readStrings(elf.DT_RUNPATH); err != nil {
		return nil, err
	}
	info.hasRunpath = len(tags[elf.DT_RUNPATH]) != 0
	sonames, err := readStrings(elf.DT_SONAME)
	if err != nil {
		return nil, err
	}
	if len(sonames) > 0 {
		info.soname = sonames[0]
	}
	return info, nil
}

func (r *Resolver) absolute(name string) string {
	if path.IsAbs(name) {
		return name
	}
	return joinVirtual(r.opts.WorkingDir, name)
}

// Keep symlink/.. traversal ordered. Lexical path.Clean before FS.Open would
// resolve /alias/../library differently from the target's real filesystem.
func joinVirtual(directory, name string) string {
	if path.IsAbs(name) {
		return name
	}
	return strings.TrimRight(directory, "/") + "/" + name
}

var dynamicToken = regexp.MustCompile(`\$\{[^}]*\}|\$[A-Za-z_][A-Za-z_0-9]*`)

func expandOrigin(value, owner string) (string, bool) {
	value = dynamicToken.ReplaceAllStringFunc(value, func(token string) string {
		if token == "$ORIGIN" || token == "${ORIGIN}" {
			// path.Dir cleans symlink/.. components and changes the loader's
			// origin. Retain the successful load pathname up to its last '/'.
			if index := strings.LastIndex(owner, "/"); index > 0 {
				return owner[:index]
			}
			return "/"
		}
		return token
	})
	// LIB and PLATFORM depend on the target loader build/auxiliary vector.
	// Never substitute the scanner host's architecture or environment.
	return value, !strings.Contains(value, "$")
}

func (r *Resolver) expandPaths(values []string, owner string) []searchDirectory {
	return r.expandSearchPaths(values, owner, false)
}

func (r *Resolver) expandSearchPaths(values []string, owner string, musl bool) []searchDirectory {
	var paths []searchDirectory
	for _, value := range values {
		if value == "" {
			continue
		}
		separator := ";"
		if musl {
			separator = "\n"
		}
		for _, part := range strings.Split(strings.ReplaceAll(value, separator, ":"), ":") {
			if musl && part == "" {
				continue
			}
			expanded, ok := expandOrigin(part, owner)
			paths = append(paths, searchDirectory{path: r.absolute(expanded), unsupportedToken: !ok})
		}
	}
	return uniqueSearchDirectories(paths)
}

func literalSearchDirectories(paths []string) []searchDirectory {
	directories := make([]searchDirectory, 0, len(paths))
	for _, directory := range paths {
		directories = append(directories, searchDirectory{path: directory})
	}
	return directories
}

func uniqueSearchDirectories(paths []searchDirectory) []searchDirectory {
	seen := make(map[searchDirectory]bool, len(paths))
	var directories []searchDirectory
	for _, directory := range paths {
		if !seen[directory] {
			seen[directory] = true
			directories = append(directories, directory)
		}
	}
	return directories
}

func (r *Resolver) systemPaths(ctx context.Context, root *elfInfo) ([]string, string) {
	if strings.HasPrefix(path.Base(root.interp), "ld-musl-") {
		prefix := path.Dir(path.Dir(root.interp))
		configuration := joinVirtual(prefix, "etc/"+strings.TrimSuffix(path.Base(root.interp), ".so.1")+".path")
		contents, err := r.readConfig(configuration)
		if err == nil {
			return r.muslLiteralPaths([]string{contents}), "musl declared dependency search; runtime injection and secure-execution state not evaluated"
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, "musl loader path configuration could not be read"
		}
		return []string{"/lib", "/usr/local/lib", "/usr/lib"}, "musl declared dependency search; runtime injection and secure-execution state not evaluated"
	}
	r.mu.Lock()
	if !r.confLoaded {
		r.conf = r.readLDConfig(ctx, "/etc/ld.so.conf", make(map[string]bool), 0)
		r.confLoaded = ctx.Err() == nil
	}
	paths := append([]string(nil), r.conf...)
	r.mu.Unlock()
	paths = append(paths, defaultPaths(root)...)
	return unique(paths), "GNU-style target search paths; ld.so.cache and hardware-capability selection not evaluated"
}

// Unlike its RPATH handling, musl does not expand dynamic tokens in the
// environment or system configuration path; empty entries are ignored.
func (r *Resolver) muslLiteralPaths(values []string) []string {
	var paths []string
	for _, value := range values {
		for _, part := range strings.FieldsFunc(value, func(ch rune) bool { return ch == ':' || ch == '\n' }) {
			paths = append(paths, r.absolute(part))
		}
	}
	return unique(paths)
}

func (r *Resolver) readConfig(name string) (string, error) {
	file, _, err := r.fs.Open(name)
	if err != nil {
		return "", err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if len(data) > 1<<20 {
		return "", errors.New("loader configuration exceeds limit")
	}
	return string(data), err
}

func (r *Resolver) readLDConfig(ctx context.Context, name string, seen map[string]bool, depth int) []string {
	if ctx.Err() != nil || seen[name] || depth >= 32 || len(seen) >= 256 {
		return nil
	}
	seen[name] = true
	contents, err := r.readConfig(name)
	if err != nil {
		return nil
	}
	var paths []string
	scanner := bufio.NewScanner(strings.NewReader(contents))
	for scanner.Scan() {
		line, _, _ := strings.Cut(scanner.Text(), "#")
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "include" {
			for _, pattern := range fields[1:] {
				if !path.IsAbs(pattern) {
					pattern = joinVirtual(path.Dir(name), pattern)
				}
				matches, err := r.fs.Glob(pattern)
				if err != nil {
					continue
				}
				sort.Strings(matches)
				for _, match := range matches {
					paths = append(paths, r.readLDConfig(ctx, match, seen, depth+1)...)
				}
			}
		} else if len(fields) == 1 && path.IsAbs(fields[0]) {
			paths = append(paths, fields[0])
		}
	}
	return paths
}

func defaultPaths(info *elfInfo) []string {
	triplet := ""
	var extra []string
	switch info.machine {
	case elf.EM_X86_64:
		if info.class == elf.ELFCLASS64 {
			triplet, extra = "x86_64-linux-gnu", []string{"/lib64", "/usr/lib64"}
		} else {
			triplet, extra = "x86_64-linux-gnux32", []string{"/libx32", "/usr/libx32"}
		}
	case elf.EM_386:
		triplet, extra = "i386-linux-gnu", []string{"/lib32", "/usr/lib32"}
	case elf.EM_AARCH64:
		triplet = "aarch64-linux-gnu"
	case elf.EM_ARM:
		// The target's ld.so.conf provides its ABI-specific multiarch paths.
	case elf.EM_RISCV:
		if info.class == elf.ELFCLASS64 {
			triplet = "riscv64-linux-gnu"
		}
	case elf.EM_PPC64:
		triplet = "powerpc64-linux-gnu"
		if info.data == elf.ELFDATA2LSB {
			triplet = "powerpc64le-linux-gnu"
		}
	case elf.EM_S390:
		triplet = "s390x-linux-gnu"
	}
	var paths []string
	if triplet != "" {
		paths = append(paths, "/lib/"+triplet, "/usr/lib/"+triplet)
	}
	paths = append(paths, extra...)
	return append(paths, "/lib", "/usr/lib")
}

func unique(values []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
