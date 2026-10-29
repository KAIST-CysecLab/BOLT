//go:build !linux

package elfdeps

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// The portable path is intended for a static scan tree. Linux additionally pins
// handles during traversal and opening, protecting against concurrent renames.
func checkedLocalPath(root, name string) (string, error) {
	host := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(name, "/")))
	rel, err := filepath.Rel(root, host)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fs.ErrPermission
	}
	return host, nil
}

func lookupLocal(root, name string) (*fsEntry, error) {
	host, err := checkedLocalPath(root, name)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(host)
	if err != nil {
		return nil, err
	}
	entry := &fsEntry{kind: entryOther}
	switch {
	case info.IsDir():
		entry.kind = entryDirectory
	case info.Mode().IsRegular():
		entry.kind = entryRegular
	case info.Mode()&os.ModeSymlink != 0:
		entry.kind = entrySymlink
		entry.target, err = os.Readlink(host)
	}
	return entry, err
}

func openLocal(root, name string) (*os.File, error) {
	host, err := checkedLocalPath(root, name)
	if err != nil {
		return nil, err
	}
	resolved, err := filepath.EvalSymlinks(host)
	if err != nil {
		return nil, err
	}
	rel, err := filepath.Rel(root, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, fs.ErrPermission
	}
	before, err := os.Lstat(host)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() && !before.IsDir() {
		return nil, fs.ErrInvalid
	}
	file, err := os.Open(resolved)
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		_ = file.Close()
		return nil, fs.ErrPermission
	}
	return file, nil
}
