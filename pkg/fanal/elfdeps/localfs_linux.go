//go:build linux

package elfdeps

import (
	"io/fs"
	"os"
	"path"

	securejoin "github.com/cyphar/filepath-securejoin"
	"golang.org/x/sys/unix"
)

func lookupLocal(root, name string) (*fsEntry, error) {
	if name == "/" {
		return &fsEntry{kind: entryDirectory}, nil
	}
	parent, err := securejoin.OpenInRoot(root, path.Dir(name))
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	var stat unix.Stat_t
	if err := unix.Fstatat(int(parent.Fd()), path.Base(name), &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, err
	}
	entry := &fsEntry{kind: entryOther}
	switch stat.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		entry.kind = entryDirectory
	case unix.S_IFREG:
		entry.kind = entryRegular
	case unix.S_IFLNK:
		entry.kind = entrySymlink
		for size := 256; size <= 1<<20; size *= 2 {
			buf := make([]byte, size)
			n, err := unix.Readlinkat(int(parent.Fd()), path.Base(name), buf)
			if err != nil {
				return nil, err
			}
			if n < len(buf) {
				entry.target = string(buf[:n])
				return entry, nil
			}
		}
		return nil, fs.ErrInvalid
	}
	return entry, nil
}

func openLocal(root, name string) (*os.File, error) {
	// O_PATH lookup prevents device/FIFO side effects before checking the type.
	handle, err := securejoin.OpenInRoot(root, name)
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	info, err := handle.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() && !info.IsDir() {
		return nil, fs.ErrInvalid
	}
	return securejoin.Reopen(handle, unix.O_RDONLY)
}
