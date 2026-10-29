package elfdeps

import (
	"archive/tar"
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRegularPathsFromLayersTracksFinalReplacementsAndWhiteouts(t *testing.T) {
	layers := newTestLayerFS(t)
	addTestLayer(t, layers,
		tarItem{name: "keep", body: "base"},
		tarItem{name: "overwrite", body: "base"},
		tarItem{name: "delete", body: "base"},
		tarItem{name: "mask", body: "base"},
		tarItem{name: "opaque/old", body: "base"},
		tarItem{name: "directory/child", body: "base"})
	addTestLayer(t, layers,
		tarItem{name: "overwrite", body: "upper"},
		tarItem{name: ".wh.delete"},
		tarItem{name: "mask", kind: tar.TypeSymlink, link: "/keep"},
		tarItem{name: "opaque/.wh..wh..opq"},
		tarItem{name: "opaque/new", body: "upper"},
		tarItem{name: "directory", body: "upper"})
	require.Equal(t, []string{"/keep"}, layers.RegularPathsFromLayers([]int{0}))
	require.Equal(t, []string{"/directory", "/opaque/new", "/overwrite"}, layers.RegularPathsFromLayers([]int{1}))
	require.Equal(t, layers.RegularPaths(), layers.RegularPathsFromLayers([]int{1, 0, 1}))
	for _, selection := range [][]int{nil, {}, {-1, 2, 99}} {
		require.Empty(t, layers.RegularPathsFromLayers(selection))
	}
	addTestLayer(t, layers,
		tarItem{name: ".wh.overwrite"},
		// Even identical content is a new upper-layer path introduction.
		tarItem{name: "opaque/new", body: "upper"})
	require.Equal(t, []string{"/directory"}, layers.RegularPathsFromLayers([]int{1}))
	require.Equal(t, []string{"/opaque/new"}, layers.RegularPathsFromLayers([]int{2}))
	require.Equal(t, []string{"/directory", "/keep", "/opaque/new"}, layers.RegularPaths())
	require.NoError(t, layers.Close())
	require.Empty(t, layers.RegularPathsFromLayers([]int{0, 1, 2}))
}

func TestRegularPathsFromLayersUsesHardlinkAliasOrigin(t *testing.T) {
	layers := newTestLayerFS(t)
	addTestLayer(t, layers,
		tarItem{name: "original", body: "version zero"},
		tarItem{name: "other", body: "other payload"})
	addTestLayer(t, layers,
		tarItem{name: "alias", kind: tar.TypeLink, link: "original"},
		tarItem{name: "survivor", kind: tar.TypeLink, link: "original"},
		// A forward link chain ultimately copies a lower-layer payload.
		tarItem{name: "forward", kind: tar.TypeLink, link: "later"},
		tarItem{name: "later", kind: tar.TypeLink, link: "original"},
		tarItem{name: "symbol", kind: tar.TypeSymlink, link: "/original"},
		tarItem{name: "symbol-alias", kind: tar.TypeLink, link: "symbol"})
	require.Equal(t, []string{"/original", "/other"}, layers.RegularPathsFromLayers([]int{0}))
	require.Equal(t, []string{"/alias", "/forward", "/later", "/survivor"}, layers.RegularPathsFromLayers([]int{1}))
	addTestLayer(t, layers,
		tarItem{name: "original", body: "version two"},
		tarItem{name: "alias", kind: tar.TypeLink, link: "other"})
	require.Equal(t, []string{"/other"}, layers.RegularPathsFromLayers([]int{0}))
	require.Equal(t, []string{"/forward", "/later", "/survivor"}, layers.RegularPathsFromLayers([]int{1}))
	require.Equal(t, []string{"/alias", "/original"}, layers.RegularPathsFromLayers([]int{2}))
	assertFile(t, layers, "/alias", "/alias", "other payload")
	assertFile(t, layers, "/forward", "/forward", "version zero")
	assertFile(t, layers, "/survivor", "/survivor", "version zero")
	addTestLayer(t, layers, tarItem{name: ".wh.original"})
	require.Equal(t, []string{"/alias"}, layers.RegularPathsFromLayers([]int{2}))
	require.Empty(t, layers.RegularPathsFromLayers([]int{3}))
	assertFile(t, layers, "/survivor", "/survivor", "version zero")
}

func TestRegularPathsFromLayersRetainsCanonicalWriteOriginAfterAliasRemoval(t *testing.T) {
	layers := newTestLayerFS(t)
	addTestLayer(t, layers,
		tarItem{name: "alias", kind: tar.TypeSymlink, link: "/canonical"},
		tarItem{name: "alias/library.so", body: "written through alias"})
	addTestLayer(t, layers,
		tarItem{name: ".wh.alias"},
		tarItem{name: "user.so", body: "user layer"})
	require.Equal(t, []string{"/canonical/library.so"}, layers.RegularPathsFromLayers([]int{0}))
	require.Equal(t, []string{"/user.so"}, layers.RegularPathsFromLayers([]int{1}))
	assertFile(t, layers, "/canonical/library.so", "/canonical/library.so", "written through alias")
	assertMissing(t, layers, "/alias/library.so")
}

func TestRegularPathsFromLayersFailedAddDoesNotConsumeOrdinal(t *testing.T) {
	layers := newTestLayerFS(t)
	require.Error(t, layers.AddLayer(bytes.NewReader([]byte("invalid tar"))))
	addTestLayer(t, layers, tarItem{name: "base", body: "base"})
	for _, badLayer := range [][]byte{
		makeLayer(t, tarItem{name: "missing-link", kind: tar.TypeLink, link: "not-present"}),
		makeLayer(t, tarItem{name: "regular-parent", body: "file"}, tarItem{name: "regular-parent/child", body: "invalid"}),
		makeLayer(t, tarItem{name: "../escape", body: "invalid"}),
	} {
		require.Error(t, layers.AddLayer(bytes.NewReader(badLayer)))
		require.Equal(t, []string{"/base"}, layers.RegularPathsFromLayers([]int{0}))
		require.Empty(t, layers.RegularPathsFromLayers([]int{1}))
	}
	// A successful empty layer still occupies its place in image layer order.
	addTestLayer(t, layers)
	addTestLayer(t, layers, tarItem{name: "user", body: "user"})
	require.Empty(t, layers.RegularPathsFromLayers([]int{1}))
	require.Equal(t, []string{"/user"}, layers.RegularPathsFromLayers([]int{2}))
	require.Equal(t, []string{"/base", "/user"}, layers.RegularPaths())
}
