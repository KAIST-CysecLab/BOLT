package elfdeps

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Expected snapshots were independently checked by loading two-layer images
// into Docker 27.5.1 and exporting stopped containers. A directory replacing a
// lower symlink must not delete files from the symlink's former target.
func TestLayerFSDifferentialSymlinkReplacedByDirectory(t *testing.T) {
	for _, marker := range []string{".wh.old.so", ".wh..wh..opq"} {
		t.Run(marker, func(t *testing.T) {
			layers := newTestLayerFS(t)
			addTestLayer(t, layers,
				tarItem{name: "real/old.so", body: "retained old ELF payload"},
				tarItem{name: "obj", kind: tar.TypeSymlink, link: "/real"})
			addTestLayer(t, layers,
				tarItem{name: "obj", kind: tar.TypeDir},
				tarItem{name: "obj/" + marker},
				tarItem{name: "obj/new.so", body: "new ELF payload"})
			assertFile(t, layers, "/real/old.so", "/real/old.so", "retained old ELF payload")
			assertFile(t, layers, "/obj/new.so", "/obj/new.so", "new ELF payload")
			assertMissing(t, layers, "/obj/old.so")
		})
	}
}

// Whiteout path traversal observes a same-layer replacement of its parent
// symlink. The removed contents still belong to a lower layer.
func TestLayerFSDifferentialWhiteoutWithRetargetedSymlink(t *testing.T) {
	layers := newTestLayerFS(t)
	addTestLayer(t, layers,
		tarItem{name: "one/old.so", body: "retained first payload"},
		tarItem{name: "two/old.so", body: "removed second payload"},
		tarItem{name: "obj", kind: tar.TypeSymlink, link: "/one"})
	addTestLayer(t, layers,
		tarItem{name: "obj", kind: tar.TypeSymlink, link: "/two"},
		tarItem{name: "obj/.wh.old.so"})
	assertFile(t, layers, "/one/old.so", "/one/old.so", "retained first payload")
	assertMissing(t, layers, "/two/old.so", "/obj/old.so")
}

func TestLayerFSDifferentialDeletedArchiveAliasRetainsCanonicalRoots(t *testing.T) {
	layers := newTestLayerFS(t)
	addTestLayer(t, layers,
		tarItem{name: "real", kind: tar.TypeDir},
		tarItem{name: "obj", kind: tar.TypeSymlink, link: "/real"},
		tarItem{name: "obj/app.so", body: "surviving ELF payload"},
		tarItem{name: "alias.so", kind: tar.TypeLink, link: "real/app.so"})
	addTestLayer(t, layers, tarItem{name: ".wh.obj"})
	assertMissing(t, layers, "/obj/app.so")
	assertFile(t, layers, "/real/app.so", "/real/app.so", "surviving ELF payload")
	if got := strings.Join(layers.RegularPaths(), ","); got != "/alias.so,/real/app.so" {
		t.Fatalf("final ELF candidates omit surviving canonical paths: %s", got)
	}
}

// Optional differential validation consumes independently generated Docker
// exports, without invoking Docker or executing target files in the Go test.
// The regular tests above retain the discovered regression cases in-tree.
func TestLayerFSDifferentialDockerExports(t *testing.T) {
	root := os.Getenv("BOLT_ELFDEPS_DOCKER_ORACLE_DIR")
	if root == "" {
		t.Skip("set BOLT_ELFDEPS_DOCKER_ORACLE_DIR to the generated audit layer directory")
	}
	data, err := os.ReadFile(filepath.Join(root, "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []string
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			directory := filepath.Join(root, name)
			data, err := os.ReadFile(filepath.Join(directory, "oracle.json"))
			if err != nil {
				t.Fatal(err)
			}
			var oracle struct {
				Error string `json:"error"`
				Files map[string]struct {
					Kind   string `json:"kind"`
					SHA256 string `json:"sha256"`
				} `json:"files"`
			}
			if err := json.Unmarshal(data, &oracle); err != nil {
				t.Fatal(err)
			}
			if oracle.Error != "" {
				t.Skipf("Docker rejected this input: %s", oracle.Error)
			}
			layers := newTestLayerFS(t)
			for _, layer := range []string{"base.tar", "upper.tar"} {
				data, err := os.ReadFile(filepath.Join(directory, layer))
				if err != nil {
					t.Fatal(err)
				}
				if err := layers.AddLayer(bytes.NewReader(data)); err != nil {
					t.Fatal(err)
				}
			}
			for name, entry := range oracle.Files {
				// Docker creates these container runtime mount placeholders;
				// they are absent from the immutable input image layers.
				if name == ".dockerenv" || strings.HasPrefix(name, "etc/") || strings.HasPrefix(name, "dev/") {
					continue
				}
				if entry.Kind != "regular" && entry.Kind != "hardlink" {
					continue
				}
				file, _, err := layers.Open("/" + name)
				if err != nil {
					t.Errorf("Docker retains %s, LayerFS cannot open it: %v", name, err)
					continue
				}
				hash := sha256.New()
				_, err = io.Copy(hash, file)
				_ = file.Close()
				if err != nil || hex.EncodeToString(hash.Sum(nil)) != entry.SHA256 {
					t.Errorf("payload mismatch for %s: %v", name, err)
				}
			}
			for name, entry := range layers.entries {
				if entry.kind != entryRegular {
					continue
				}
				if _, ok := oracle.Files[strings.TrimPrefix(name, "/")]; !ok {
					t.Errorf("LayerFS retains %s, absent from Docker export", name)
				}
			}
		})
	}
}
