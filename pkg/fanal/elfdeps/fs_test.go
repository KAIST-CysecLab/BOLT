package elfdeps

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

type tarItem struct {
	name, body, link string
	kind             byte
}

func makeLayer(t *testing.T, items ...tarItem) []byte {
	t.Helper()
	var out bytes.Buffer
	w := tar.NewWriter(&out)
	for _, item := range items {
		kind := item.kind
		if kind == 0 {
			kind = tar.TypeReg
		}
		header := &tar.Header{Name: item.name, Typeflag: kind, Mode: 0644, Linkname: item.link}
		if kind == tar.TypeReg {
			header.Size = int64(len(item.body))
		}
		if err := w.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(w, item.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func newTestLayerFS(t *testing.T) *LayerFS {
	t.Helper()
	layers, err := NewLayerFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := layers.Close(); err != nil {
			t.Error(err)
		}
	})
	return layers
}

func addTestLayer(t *testing.T, layers *LayerFS, items ...tarItem) {
	t.Helper()
	if err := layers.AddLayer(bytes.NewReader(makeLayer(t, items...))); err != nil {
		t.Fatal(err)
	}
}

func assertFile(t *testing.T, filesystem FS, name, canonical, content string) {
	t.Helper()
	file, gotPath, err := filesystem.Open(name)
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	defer file.Close()
	got, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != canonical || string(got) != content {
		t.Fatalf("open %s = (%q, %q), want (%q, %q)", name, gotPath, got, canonical, content)
	}
	// ReaderAt must be independent of the sequential reader's position and must
	// stop at this file's boundary even when another file follows in the spool.
	buf := make([]byte, len(content)+3)
	n, err := file.ReadAt(buf, 0)
	if n != len(content) || err != io.EOF || string(buf[:n]) != content {
		t.Fatalf("ReadAt %s = (%q, %d, %v)", name, buf[:n], n, err)
	}
}

func assertMissing(t *testing.T, filesystem FS, names ...string) {
	t.Helper()
	for _, name := range names {
		file, _, err := filesystem.Open(name)
		if file != nil {
			file.Close()
		}
		if !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("open %s = %v, want not-exist", name, err)
		}
	}
}

func TestLayerFSWhiteoutsAffectOnlyLowerEntries(t *testing.T) {
	layers := newTestLayerFS(t)
	addTestLayer(t, layers,
		tarItem{name: "lib/old.so", body: "old"},
		tarItem{name: "lib/replace.so", body: "before"},
		tarItem{name: "etc/ld.so.conf.d/old.conf", body: "old configuration"},
		tarItem{name: "etc/ld.so.conf.d/nested/old.conf", body: "nested old configuration"},
		tarItem{name: "untouched", body: "retained"})
	addTestLayer(t, layers,
		tarItem{name: "lib/replace.so", body: "after"},
		tarItem{name: "lib/.wh.replace.so"}, // After a same-layer replacement.
		tarItem{name: "lib/.wh.old.so"},
		tarItem{name: "etc/ld.so.conf.d/new.conf", body: "new configuration"},
		tarItem{name: "etc/ld.so.conf.d/.wh..wh..opq"}) // After a same-layer child.
	assertFile(t, layers, "/lib/replace.so", "/lib/replace.so", "after")
	assertFile(t, layers, "/etc/ld.so.conf.d/new.conf", "/etc/ld.so.conf.d/new.conf", "new configuration")
	assertFile(t, layers, "/untouched", "/untouched", "retained")
	assertMissing(t, layers, "/lib/old.so", "/etc/ld.so.conf.d/old.conf", "/etc/ld.so.conf.d/nested/old.conf", "/lib/.wh.replace.so")
	got, err := layers.Glob("/etc/ld.so.conf.d/*.conf")
	if err != nil || !reflect.DeepEqual(got, []string{"/etc/ld.so.conf.d/new.conf"}) {
		t.Fatalf("configuration glob = %v, %v", got, err)
	}
	// Removing a lower directory removes its whole subtree; a later directory
	// can be recreated without resurrecting those descendants.
	addTestLayer(t, layers, tarItem{name: "etc/.wh.ld.so.conf.d"})
	assertMissing(t, layers, "/etc/ld.so.conf.d/new.conf")
	addTestLayer(t, layers, tarItem{name: "etc/ld.so.conf.d/final.conf", body: "last"})
	assertMissing(t, layers, "/etc/ld.so.conf.d/old.conf", "/etc/ld.so.conf.d/new.conf")
	assertFile(t, layers, "/etc/ld.so.conf.d/final.conf", "/etc/ld.so.conf.d/final.conf", "last")
}

func TestLayerFSLinksAndLaterModifications(t *testing.T) {
	layers := newTestLayerFS(t)
	addTestLayer(t, layers,
		tarItem{name: "usr/lib/real.so", body: "version one"},
		tarItem{name: "lib", kind: tar.TypeSymlink, link: "/usr/lib"},
		tarItem{name: "usr/lib/relative.so", kind: tar.TypeSymlink, link: "real.so"},
		tarItem{name: "usr/lib/hard.so", kind: tar.TypeLink, link: "usr/lib/real.so"},
		tarItem{name: "usr/lib/forward.so", kind: tar.TypeLink, link: "usr/lib/future.so"},
		tarItem{name: "usr/lib/future.so", body: "forward target"})
	assertFile(t, layers, "/lib/relative.so", "/usr/lib/real.so", "version one")
	assertFile(t, layers, "/lib/hard.so", "/usr/lib/hard.so", "version one")
	assertFile(t, layers, "/lib/forward.so", "/usr/lib/forward.so", "forward target")
	addTestLayer(t, layers,
		tarItem{name: "usr/lib/real.so", body: "version two"},
		// A link traversed while extracting this layer must exist in this
		// layer; otherwise its implicit directory masks a lower symlink.
		tarItem{name: "lib", kind: tar.TypeSymlink, link: "/usr/lib"},
		tarItem{name: "lib/through-link.so", body: "under actual directory"})
	assertFile(t, layers, "/lib/relative.so", "/usr/lib/real.so", "version two")
	assertFile(t, layers, "/lib/hard.so", "/usr/lib/hard.so", "version one")
	assertFile(t, layers, "/usr/lib/through-link.so", "/usr/lib/through-link.so", "under actual directory")
	addTestLayer(t, layers, tarItem{name: "usr/lib/.wh.real.so"})
	assertMissing(t, layers, "/lib/relative.so")
	assertFile(t, layers, "/lib/hard.so", "/usr/lib/hard.so", "version one")
	got, err := layers.Glob("/lib/*hard.so")
	if err != nil || !reflect.DeepEqual(got, []string{"/lib/hard.so"}) {
		t.Fatalf("glob must preserve symlinked path: %v, %v", got, err)
	}
	if got := layers.HardlinkPaths(); !reflect.DeepEqual(got, []string{"/usr/lib/forward.so", "/usr/lib/hard.so"}) {
		t.Fatalf("surviving hard links after original whiteout = %v", got)
	}
	addTestLayer(t, layers,
		tarItem{name: "usr/lib/hard.so", body: "ordinary replacement"},
		tarItem{name: "usr/lib/.wh.forward.so"},
		tarItem{name: "usr/lib/link-alias", kind: tar.TypeLink, link: "usr/lib/relative.so"})
	if got := layers.HardlinkPaths(); len(got) != 0 {
		t.Fatalf("overwritten/deleted aliases or hard links to symlinks retained = %v", got)
	}
	assertFile(t, layers, "/usr/lib/hard.so", "/usr/lib/hard.so", "ordinary replacement")
}

func TestLayerFSRejectsTraversalAndKeepsPriorSnapshotOnError(t *testing.T) {
	for _, badName := range []string{"../escape", "lib/../../escape", "lib/../escape", "/absolute", `C:\escape`, `C:/escape`} {
		t.Run(badName, func(t *testing.T) {
			layers := newTestLayerFS(t)
			addTestLayer(t, layers, tarItem{name: "good", body: "original"})
			err := layers.AddLayer(bytes.NewReader(makeLayer(t, tarItem{name: "good", body: "partial"}, tarItem{name: badName, body: "bad"})))
			if err == nil {
				t.Fatal("malformed layer accepted")
			}
			assertFile(t, layers, "/good", "/good", "original")
			files, err := os.ReadDir(layers.dir)
			if err != nil || len(files) != 1 {
				t.Fatalf("failed layer backing leaked: %v, %v", files, err)
			}
		})
	}
}

func TestLayerFSNeverFallsBackToHost(t *testing.T) {
	hostDir := t.TempDir()
	hostFile := filepath.Join(hostDir, "host-only")
	if err := os.WriteFile(hostFile, []byte("host secret"), 0600); err != nil {
		t.Fatal(err)
	}
	layers := newTestLayerFS(t)
	addTestLayer(t, layers,
		tarItem{name: "host-link", kind: tar.TypeSymlink, link: filepath.ToSlash(hostFile)},
		tarItem{name: "escape-link", kind: tar.TypeSymlink, link: "../../host-only"},
		tarItem{name: "loop-a", kind: tar.TypeSymlink, link: "loop-b"},
		tarItem{name: "loop-b", kind: tar.TypeSymlink, link: "loop-a"},
		tarItem{name: "fifo", kind: tar.TypeFifo})
	assertMissing(t, layers, "/host-link", filepath.ToSlash(hostFile))
	for _, name := range []string{"/escape-link", "/loop-a", "/fifo", "../host-only"} {
		file, _, err := layers.Open(name)
		if file != nil {
			file.Close()
		}
		if err == nil {
			t.Fatalf("unsafe/special path %s opened", name)
		}
	}
	if _, err := layers.Glob("/["); !errors.Is(err, path.ErrBadPattern) {
		t.Fatalf("bad pattern = %v", err)
	}
}

func TestLayerFSRejectsBrokenHardlinksAndTruncatedTar(t *testing.T) {
	layers := newTestLayerFS(t)
	addTestLayer(t, layers, tarItem{name: "good", body: "retained"})
	for _, items := range [][]tarItem{
		{{name: "bad", kind: tar.TypeLink, link: "missing"}},
		{{name: "a", kind: tar.TypeLink, link: "b"}, {name: "b", kind: tar.TypeLink, link: "a"}},
		{{name: "bad", kind: tar.TypeLink, link: "../outside"}},
	} {
		if err := layers.AddLayer(bytes.NewReader(makeLayer(t, items...))); err == nil {
			t.Fatal("invalid hard link accepted")
		}
		assertFile(t, layers, "/good", "/good", "retained")
	}
	raw := makeLayer(t, tarItem{name: "truncated", body: strings.Repeat("x", 1024)})
	if err := layers.AddLayer(bytes.NewReader(raw[:600])); err == nil {
		t.Fatal("truncated payload accepted")
	}
	assertMissing(t, layers, "/truncated")
}

func TestLayerFSSparsePayloadUsesLogicalOffsets(t *testing.T) {
	// Construct a real GNU PAX sparse entry: four archived bytes describe a
	// ten-byte file. Indexing tar-reader byte offsets as ordinary data would
	// otherwise return adjacent headers instead of the six-byte hole.
	var pax strings.Builder
	for _, pair := range [][2]string{{"GNU.sparse.size", "10"}, {"GNU.sparse.numblocks", "2"}, {"GNU.sparse.map", "0,2,8,2"}} {
		body := pair[0] + "=" + pair[1] + "\n"
		size := len(body) + 2
		for {
			line := fmt.Sprintf("%d %s", size, body)
			if len(line) == size {
				pax.WriteString(line)
				break
			}
			size = len(line)
		}
	}
	extended := makeLayer(t, tarItem{name: "PaxHeaders/sparse", body: pax.String()})
	extended[156] = tar.TypeXHeader
	for i := 148; i < 156; i++ {
		extended[i] = ' '
	}
	var checksum int
	for _, b := range extended[:512] {
		checksum += int(b)
	}
	copy(extended[148:156], fmt.Sprintf("%06o\x00 ", checksum))
	raw := append(extended[:len(extended)-1024], makeLayer(t,
		tarItem{name: "sparse", body: "abxy"}, tarItem{name: "after", body: "following file"})...)
	layers := newTestLayerFS(t)
	if err := layers.AddLayer(bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	assertFile(t, layers, "/sparse", "/sparse", "ab\x00\x00\x00\x00\x00\x00xy")
	assertFile(t, layers, "/after", "/after", "following file")
}

func TestLayerFSParallelReadersAndClose(t *testing.T) {
	layers := newTestLayerFS(t)
	addTestLayer(t, layers, tarItem{name: "lib/example.so", body: strings.Repeat("ELF", 300)}, tarItem{name: "etc/ld.so.cache", body: "cache payload"})
	var workers sync.WaitGroup
	for i := 0; i < 24; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			assertFile(t, layers, "/lib/example.so", "/lib/example.so", strings.Repeat("ELF", 300))
		}()
	}
	workers.Wait()
	assertFile(t, layers, "/etc/ld.so.cache", "/etc/ld.so.cache", "cache payload")
	if err := layers.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(layers.dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("temporary storage not removed: %v", err)
	}
	if _, _, err := layers.Open("/lib/example.so"); !errors.Is(err, fs.ErrClosed) {
		t.Fatalf("open after close = %v", err)
	}
	if err := layers.AddLayer(bytes.NewReader(nil)); !errors.Is(err, fs.ErrClosed) {
		t.Fatalf("add after close = %v", err)
	}
}

func TestLocalFSTargetScopedLinksAndGlob(t *testing.T) {
	root := t.TempDir()
	for name, content := range map[string]string{"usr/lib/example.so": "target library", "etc/ld.so.conf.d/b.conf": "b", "etc/ld.so.conf.d/a.conf": "a"} {
		host := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(host), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(host, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range map[string]string{"lib": "/usr/lib", "usr/lib/relative.so": "example.so", "configs": "/etc/ld.so.conf.d", "escape": "../outside"} {
		if err := os.Symlink(target, filepath.Join(root, filepath.FromSlash(name))); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}
	filesystem, err := NewLocalFS(root)
	if err != nil {
		t.Fatal(err)
	}
	assertFile(t, filesystem, "/lib/relative.so", "/usr/lib/example.so", "target library")
	got, err := filesystem.Glob("/configs/*.conf")
	if err != nil || !reflect.DeepEqual(got, []string{"/configs/a.conf", "/configs/b.conf"}) {
		t.Fatalf("target-scoped glob = %v, %v", got, err)
	}
	if _, _, err := filesystem.Open("/escape"); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("relative escape = %v", err)
	}
	outside := filepath.Join(t.TempDir(), "host-only")
	if err := os.WriteFile(outside, []byte("host secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "host-link")); err != nil {
		t.Fatal(err)
	}
	assertMissing(t, filesystem, "/host-link")
	if _, err := NewLocalFS(filepath.Join(root, "usr/lib/example.so")); err == nil {
		t.Fatal("file accepted as filesystem root")
	}
}
