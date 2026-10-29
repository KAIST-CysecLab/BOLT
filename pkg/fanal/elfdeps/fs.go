package elfdeps

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

type entryKind uint8

const (
	entryDirectory entryKind = iota
	entryRegular
	entrySymlink
	entryHardlink
	entryOther
	entryWhiteout
	entryOpaque
)

type fileData struct {
	backing string
	offset  int64
	size    int64
}

type fsEntry struct {
	kind     entryKind
	target   string
	data     fileData
	hardlink bool
	layer    int // Successful AddLayer ordinal that introduced this path.
}

type entryLookup func(string) (*fsEntry, error)

func validVirtualName(name string) error {
	if name == "" || strings.ContainsAny(name, "\x00\\") || (len(name) >= 2 && name[1] == ':') {
		return fs.ErrInvalid
	}
	return nil
}

// resolveVirtual resolves each component before processing the next '..'. An
// absolute link starts again at the target root, never the host's filesystem.
// mkdir is used only while building a layer's implicit parent directories.
func resolveVirtual(name string, lookup entryLookup, followFinal bool, mkdir func(string)) (string, *fsEntry, error) {
	if err := validVirtualName(name); err != nil {
		return "", nil, err
	}
	parts := strings.Split(name, "/")
	var resolved []string
	links := 0
	var current *fsEntry
	for len(parts) != 0 {
		part := parts[0]
		parts = parts[1:]
		switch part {
		case "", ".":
			continue
		case "..":
			if len(resolved) == 0 {
				return "", nil, fmt.Errorf("path escapes target root: %w", fs.ErrPermission)
			}
			resolved = resolved[:len(resolved)-1]
			continue
		}
		candidate := "/" + strings.Join(append(append([]string(nil), resolved...), part), "/")
		entry, err := lookup(candidate)
		if errors.Is(err, fs.ErrNotExist) && mkdir != nil {
			mkdir(candidate)
			entry, err = lookup(candidate)
		}
		if err != nil {
			return "", nil, err
		}
		if entry.kind == entrySymlink && (followFinal || len(parts) != 0) {
			links++
			if links > 40 {
				return "", nil, fmt.Errorf("too many symbolic links: %w", fs.ErrInvalid)
			}
			if err := validVirtualName(entry.target); err != nil {
				return "", nil, err
			}
			if strings.HasPrefix(entry.target, "/") {
				resolved = nil
			}
			parts = append(strings.Split(entry.target, "/"), parts...)
			continue
		}
		if len(parts) != 0 && entry.kind != entryDirectory {
			return "", nil, fmt.Errorf("%s is not a directory: %w", candidate, fs.ErrInvalid)
		}
		resolved = append(resolved, part)
		current = entry
	}
	canonical := "/" + strings.Join(resolved, "/")
	// A final '.', '..', slash, or link to '/' can change the last entry.
	var err error
	current, err = lookup(canonical)
	return canonical, current, err
}

func fsPathError(op, name string, err error) error {
	return &fs.PathError{Op: op, Path: name, Err: err}
}

type localFS struct{ root string }

// NewLocalFS exposes only root's contents. root must be an existing directory;
// callers scanning a single executable should pass its containing directory.
func NewLocalFS(root string) (FS, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	abs, err = filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fsPathError("new local filesystem", root, fs.ErrInvalid)
	}
	return &localFS{root: abs}, nil
}

func (l *localFS) lookup(name string) (*fsEntry, error) {
	return lookupLocal(l.root, name)
}

func (l *localFS) Open(name string) (File, string, error) {
	canonical, entry, err := resolveVirtual(name, l.lookup, true, nil)
	if err != nil {
		return nil, "", fsPathError("open", name, err)
	}
	if entry.kind != entryRegular {
		return nil, "", fsPathError("open", name, fs.ErrInvalid)
	}
	file, err := openLocal(l.root, canonical)
	if err != nil {
		return nil, "", fsPathError("open", name, err)
	}
	return file, canonical, nil
}

func (l *localFS) readDir(name string) ([]string, error) {
	canonical, entry, err := resolveVirtual(name, l.lookup, true, nil)
	if err != nil {
		return nil, err
	}
	if entry.kind != entryDirectory {
		return nil, fs.ErrInvalid
	}
	file, err := openLocal(l.root, canonical)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return file.Readdirnames(-1)
}

func (l *localFS) Glob(pattern string) ([]string, error) {
	return globVirtual(pattern, l.readDir)
}

// globVirtual deliberately avoids filepath.Glob, which would interpret absolute
// symlinks and glob directories in the host namespace.
func globVirtual(pattern string, readDir func(string) ([]string, error)) ([]string, error) {
	if err := validVirtualName(pattern); err != nil {
		return nil, fsPathError("glob", pattern, err)
	}
	parts := strings.Split(strings.TrimPrefix(pattern, "/"), "/")
	for _, part := range parts {
		if _, err := path.Match(part, ""); err != nil {
			return nil, err
		}
	}
	candidates := []string{"/"}
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			return nil, fsPathError("glob", pattern, fs.ErrPermission)
		}
		var next []string
		for _, parent := range candidates {
			names, err := readDir(parent)
			if err != nil {
				// Match filepath.Glob's treatment of unreadable/missing directories.
				continue
			}
			for _, name := range names {
				if matched, _ := path.Match(part, name); matched {
					next = append(next, strings.TrimSuffix(parent, "/")+"/"+name)
				}
			}
		}
		candidates = next
	}
	sort.Strings(candidates)
	return candidates, nil
}

// LayerFS stores image files in private, flat backing files. Archive paths are
// index keys only; they are never passed to an extraction function. One backing
// file per layer holds regular payloads, including reconstructed sparse files.
// Open/Glob may run concurrently; AddLayer and Close are serialized with them.
// Close removes backing storage; callers should close open readers first.
type LayerFS struct {
	mu       sync.RWMutex
	dir      string
	entries  map[string]*fsEntry
	children map[string][]string
	layers   int
	closed   bool
}

func NewLayerFS(tempDir string) (*LayerFS, error) {
	dir, err := os.MkdirTemp(tempDir, "bolt-elfdeps-")
	if err != nil {
		return nil, err
	}
	return &LayerFS{dir: dir, entries: map[string]*fsEntry{"/": {kind: entryDirectory}}, children: map[string][]string{}}, nil
}

func archiveName(name string) (string, error) {
	if err := validVirtualName(name); err != nil || strings.HasPrefix(name, "/") {
		return "", fs.ErrInvalid
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return "", fmt.Errorf("archive traversal: %w", fs.ErrPermission)
		}
	}
	return path.Clean("/" + name), nil
}

func indexLookup(entries map[string]*fsEntry) entryLookup {
	return func(name string) (*fsEntry, error) {
		if entry := entries[name]; entry != nil {
			return entry, nil
		}
		return nil, fs.ErrNotExist
	}
}

func removeEntries(entries map[string]*fsEntry, name string, childrenOnly bool) {
	if !childrenOnly && name != "/" {
		entry := entries[name]
		if entry == nil {
			return
		}
		// Non-directories cannot have indexed descendants. Replacing thousands
		// of regular files must not scan the whole image for each replacement.
		if entry.kind != entryDirectory {
			delete(entries, name)
			return
		}
	}
	for existing := range entries {
		if (!childrenOnly && existing == name && name != "/") || (existing != name && strings.HasPrefix(existing, strings.TrimSuffix(name, "/")+"/")) {
			delete(entries, existing)
		}
	}
}

type layerEntry struct {
	name  string
	entry *fsEntry
}

func (l *LayerFS) AddLayer(r io.Reader) (err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return fs.ErrClosed
	}
	backing, err := os.CreateTemp(l.dir, "layer-")
	if err != nil {
		return err
	}
	published := false
	defer func() {
		_ = backing.Close()
		if !published {
			_ = os.Remove(backing.Name())
		}
	}()
	var additions []layerEntry
	reader := tar.NewReader(r)
	var offset int64
	for {
		header, nextErr := reader.Next()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			return fmt.Errorf("read image layer: %w", nextErr)
		}
		name, err := archiveName(header.Name)
		if err != nil {
			return fsPathError("index layer", header.Name, err)
		}
		if strings.HasPrefix(path.Base(name), ".wh.") {
			if path.Base(name) == ".wh..wh..opq" {
				additions = append(additions, layerEntry{name, &fsEntry{kind: entryOpaque}})
			} else {
				base := strings.TrimPrefix(path.Base(name), ".wh.")
				if base == "" || base == "." || base == ".." {
					return fsPathError("index whiteout", header.Name, fs.ErrInvalid)
				}
				additions = append(additions, layerEntry{name, &fsEntry{kind: entryWhiteout}})
			}
			continue
		}
		entry := &fsEntry{layer: l.layers}
		switch header.Typeflag {
		case tar.TypeReg, tar.TypeRegA, tar.TypeGNUSparse:
			entry.kind = entryRegular
			entry.data = fileData{backing: backing.Name(), offset: offset, size: header.Size}
			written, err := io.Copy(backing, reader)
			if err != nil {
				return fmt.Errorf("store %s: %w", name, err)
			}
			if written != header.Size {
				return fmt.Errorf("store %s: %w", name, io.ErrUnexpectedEOF)
			}
			offset += written
		case tar.TypeDir:
			entry.kind = entryDirectory
		case tar.TypeSymlink:
			if err := validVirtualName(header.Linkname); err != nil {
				return fsPathError("index symbolic link", name, err)
			}
			entry.kind, entry.target = entrySymlink, header.Linkname
		case tar.TypeLink:
			target, err := archiveName(header.Linkname)
			if err != nil {
				return fsPathError("index hard link", name, err)
			}
			entry.kind, entry.target = entryHardlink, target
		default:
			// Preserve the fact that a special file masks a lower regular file;
			// never create or open host devices, sockets, or FIFOs.
			entry.kind = entryOther
		}
		if name == "/" && entry.kind != entryDirectory {
			return fsPathError("index root", name, fs.ErrInvalid)
		}
		additions = append(additions, layerEntry{name, entry})
	}
	if err := backing.Close(); err != nil {
		return err
	}
	// Build the upper namespace independently. In particular, an implicit
	// upper directory masks a lower symlink; extraction must not traverse a
	// lower-layer symlink to place new files or whiteout markers elsewhere.
	upper := map[string]*fsEntry{"/": {kind: entryDirectory}}
	lookup := indexLookup(upper)
	for _, addition := range additions {
		parent, parentEntry, err := resolveVirtual(path.Dir(addition.name), lookup, true, func(name string) {
			upper[name] = &fsEntry{kind: entryDirectory}
		})
		if err != nil {
			return fsPathError("index parent", addition.name, err)
		}
		if parentEntry.kind != entryDirectory {
			return fsPathError("index parent", addition.name, fs.ErrInvalid)
		}
		name := path.Join(parent, path.Base(addition.name))
		entry := addition.entry
		if entry.kind == entryHardlink {
			_, target, targetErr := resolveVirtual(entry.target, lookup, false, nil)
			if errors.Is(targetErr, fs.ErrNotExist) {
				// Preserve support for archives explicitly linking an unchanged
				// lower object. Copy its identity without redirecting later reads.
				_, target, targetErr = resolveVirtual(entry.target, indexLookup(l.entries), false, nil)
			}
			if targetErr == nil && target.kind != entryHardlink {
				if target.kind != entryRegular && target.kind != entrySymlink {
					return fsPathError("index hard link", name, fs.ErrInvalid)
				}
				copy := *target
				copy.hardlink = true
				copy.layer = entry.layer // Alias provenance differs from its payload.
				entry = &copy
			}
		}
		if old := upper[name]; old != nil && (old.kind != entryDirectory || entry.kind != entryDirectory) {
			removeEntries(upper, name, false)
		}
		upper[name] = entry
	}
	// Tar permits forward hard links. Resolve them only after all target entries
	// exist, then store immutable data identity, not a pathname redirect.
	for name, entry := range upper {
		if entry.kind == entryHardlink {
			resolved, err := resolveHardlink(upper, name, map[string]bool{})
			if err != nil {
				return fsPathError("resolve hard link", name, err)
			}
			upper[name] = resolved
			resolved.hardlink = true
		}
	}
	entries := make(map[string]*fsEntry, len(l.entries)+len(upper))
	for name, entry := range l.entries {
		entries[name] = entry
	}
	// Surviving markers affect only the lower snapshot. Keeping them in the
	// upper namespace until now also handles a parent directory/symlink being
	// replaced later in the same archive, which can remove the marker itself.
	var names []string
	for name, entry := range upper {
		switch entry.kind {
		case entryOpaque:
			removeEntries(entries, path.Dir(name), true)
		case entryWhiteout:
			target := path.Join(path.Dir(name), strings.TrimPrefix(path.Base(name), ".wh."))
			removeEntries(entries, target, false)
		default:
			names = append(names, name)
		}
	}
	sort.Strings(names) // Parent entries precede their children.
	for _, name := range names {
		entry := upper[name]
		if old := entries[name]; old != nil && (old.kind != entryDirectory || entry.kind != entryDirectory) {
			removeEntries(entries, name, false)
		}
		entries[name] = entry
	}
	children := make(map[string][]string)
	for name := range entries {
		if name != "/" {
			parent := path.Dir(name)
			children[parent] = append(children[parent], path.Base(name))
		}
	}
	for parent := range children {
		sort.Strings(children[parent])
	}
	l.entries, l.children = entries, children
	l.layers++
	published = true
	return nil
}

func resolveHardlink(entries map[string]*fsEntry, name string, visiting map[string]bool) (*fsEntry, error) {
	if visiting[name] || len(visiting) >= 40 {
		return nil, fmt.Errorf("hard link cycle: %w", fs.ErrInvalid)
	}
	visiting[name] = true
	entry := entries[name]
	if entry == nil {
		return nil, fs.ErrNotExist
	}
	if entry.kind == entryHardlink {
		canonical, _, err := resolveVirtual(entry.target, indexLookup(entries), false, nil)
		if err != nil {
			return nil, err
		}
		resolved, err := resolveHardlink(entries, canonical, visiting)
		if err != nil {
			return nil, err
		}
		resolved.layer = entry.layer
		return resolved, nil
	}
	if entry.kind != entryRegular && entry.kind != entrySymlink {
		return nil, fs.ErrInvalid
	}
	copy := *entry
	return &copy, nil
}

type sectionFile struct {
	*io.SectionReader
	file *os.File
}

func (f *sectionFile) Close() error { return f.file.Close() }

func (l *LayerFS) Open(name string) (File, string, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed {
		return nil, "", fs.ErrClosed
	}
	canonical, entry, err := resolveVirtual(name, indexLookup(l.entries), true, nil)
	if err != nil {
		return nil, "", fsPathError("open", name, err)
	}
	if entry.kind != entryRegular {
		return nil, "", fsPathError("open", name, fs.ErrInvalid)
	}
	file, err := os.Open(entry.data.backing)
	if err != nil {
		return nil, "", err
	}
	return &sectionFile{SectionReader: io.NewSectionReader(file, entry.data.offset, entry.data.size), file: file}, canonical, nil
}

func (l *LayerFS) Glob(pattern string) ([]string, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed {
		return nil, fs.ErrClosed
	}
	return globVirtual(pattern, func(name string) ([]string, error) {
		canonical, entry, err := resolveVirtual(name, indexLookup(l.entries), true, nil)
		if err != nil {
			return nil, err
		}
		if entry.kind != entryDirectory {
			return nil, fs.ErrInvalid
		}
		return l.children[canonical], nil
	})
}

// HardlinkPaths lists surviving regular-file aliases introduced by hard links.
// A layer walker may skip link headers, so these paths also need ELF resolution
// when their original names have subsequently been deleted or overwritten.
func (l *LayerFS) HardlinkPaths() []string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed {
		return nil
	}
	var names []string
	for name, entry := range l.entries {
		if entry.kind == entryRegular && entry.hardlink {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// RegularPaths lists canonical paths of every surviving regular file in the
// final image. Archive names are not sufficient: a lower layer can write a
// file through a directory symlink that a later layer removes or replaces.
func (l *LayerFS) RegularPaths() []string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed {
		return nil
	}
	var names []string
	for name, entry := range l.entries {
		if entry.kind == entryRegular {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// RegularPathsFromLayers lists surviving canonical regular-file paths last
// introduced or overwritten by the selected successful AddLayer calls (zero
// based). A hard link belongs to its alias's introducing layer, regardless of
// the payload's layer. Nil or empty indices select no files; unsuccessful
// AddLayer calls do not consume an ordinal.
func (l *LayerFS) RegularPathsFromLayers(indices []int) []string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed || len(indices) == 0 {
		return nil
	}
	selected := make(map[int]bool, len(indices))
	for _, index := range indices {
		selected[index] = true
	}
	var names []string
	for name, entry := range l.entries {
		if entry.kind == entryRegular && selected[entry.layer] {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func (l *LayerFS) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	if err := os.RemoveAll(l.dir); err != nil {
		return err
	}
	l.closed = true
	return nil
}
