package elfdeps

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestContextIDsCannotCollideWithValidTargetPaths(t *testing.T) {
	root := t.TempDir()
	b := compileLibrary(t, root, "/b", "/b", nil, "", false)
	c := compileLibrary(t, root, "/c", "/c", nil, "", false)
	bc := compileLibrary(t, root, "/b::/c", "/b::/c", nil, "", false)
	compileLibrary(t, root, "/a", "root-a", []string{b, bc}, "", false)
	compileLibrary(t, root, "/a::/b", "root-b", []string{c}, "", false)
	resolver := targetResolver(t, root, Options{})
	a, err := resolver.Resolve(context.Background(), "/a")
	require.NoError(t, err)
	d, err := resolver.Resolve(context.Background(), "/a::/b")
	require.NoError(t, err)
	require.Len(t, a, 3)
	require.Len(t, d, 2)
	seen := make(map[string]string)
	for _, n := range append(a, d...) {
		prior, found := seen[n.ID]
		require.False(t, found, "different target paths %q and %q share ID %q", prior, n.Path, n.ID)
		seen[n.ID] = n.Path
	}
	require.Equal(t, []string{nodeByPath(t, a, "/b").ID, nodeByPath(t, a, "/b::/c").ID}, a[0].DependsOn)
	require.Equal(t, []string{nodeByPath(t, d, "/c").ID}, d[0].DependsOn)
}
