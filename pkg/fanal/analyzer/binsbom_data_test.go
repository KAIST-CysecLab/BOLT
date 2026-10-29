package analyzer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeBinSBOMData lays out a minimal component database the way preprocessor.py
// and OSScollector.py leave it under $BIN_SBOM_DB.
func writeBinSBOMData(t *testing.T, root string) {
	t.Helper()
	componentDB := filepath.Join(root, "database", "componentDB")
	for _, entry := range binSBOMComponentDBEntries {
		require.NoError(t, os.MkdirAll(filepath.Join(componentDB, entry), 0o755))
	}
	repoMeta := filepath.Join(root, "osscollector", "repo_meta")
	require.NoError(t, os.MkdirAll(repoMeta, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(repoMeta, "zlib@@zlib.txt"), []byte("meta"), 0o644))
}

func TestCheckBinSBOMData(t *testing.T) {
	t.Run("complete database", func(t *testing.T) {
		root := t.TempDir()
		writeBinSBOMData(t, root)
		assert.NoError(t, checkBinSBOMData(root))
	})

	t.Run("BIN_SBOM_DB not set", func(t *testing.T) {
		assert.ErrorContains(t, checkBinSBOMData(""), "BIN_SBOM_DB is not set")
	})

	t.Run("fresh checkout without a database", func(t *testing.T) {
		err := checkBinSBOMData(t.TempDir())
		require.Error(t, err)
		assert.ErrorContains(t, err, "components.json")
		assert.ErrorContains(t, err, "call_graph")
	})

	t.Run("partially built database", func(t *testing.T) {
		root := t.TempDir()
		writeBinSBOMData(t, root)
		require.NoError(t, os.RemoveAll(filepath.Join(root, "database", "componentDB", "symbols")))
		err := checkBinSBOMData(root)
		require.Error(t, err)
		assert.ErrorContains(t, err, "symbols")
		assert.NotContains(t, err.Error(), "strings")
	})

	t.Run("no component metadata", func(t *testing.T) {
		root := t.TempDir()
		writeBinSBOMData(t, root)
		require.NoError(t, os.Remove(filepath.Join(root, "osscollector", "repo_meta", "zlib@@zlib.txt")))
		assert.ErrorContains(t, checkBinSBOMData(root), "no component metadata")
	})
}

func TestInitBinarySBOMEnginesStopsWithoutBinSBOMData(t *testing.T) {
	t.Cleanup(func() { enabledBinarySBOMEngines = nil })
	// Any existing file passes the executable lookup; it is never run here.
	t.Setenv("BIN_SBOM_PATH", os.Args[0])

	for _, strict := range []bool{false, true} {
		t.Setenv("BIN_SBOM_DB", t.TempDir())
		err := InitBinarySBOMEngines([]string{BinarySBOMBinSBOM}, strict)
		require.Error(t, err, "strict=%v", strict)
		assert.ErrorContains(t, err, "component database unavailable")
	}

	root := t.TempDir()
	writeBinSBOMData(t, root)
	t.Setenv("BIN_SBOM_DB", root)
	require.NoError(t, InitBinarySBOMEngines([]string{BinarySBOMBinSBOM}, false))
	assert.Len(t, enabledBinarySBOMEngines, 1)

	// bom-blint alone does not need the bin-sbom database.
	t.Setenv("BIN_SBOM_DB", "")
	t.Setenv("BOMBLINT_PATH", os.Args[0])
	require.NoError(t, InitBinarySBOMEngines([]string{BinarySBOMBomBlint}, true))
}
