package analyzer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDirectNeededGraph(t *testing.T) {
	tests := []struct {
		name     string
		needed   []string
		filePath string
		want     []libtreeGraphNode
	}{
		{
			name:     "root first, then one childless node per soname",
			needed:   []string{"libselinux.so.1", "libc.so.6"},
			filePath: "/usr/bin/ls",
			want: []libtreeGraphNode{
				{Name: "ls", DependsOn: []string{"libselinux.so.1", "libc.so.6"}},
				{Name: "libselinux.so.1", DependsOn: []string{}},
				{Name: "libc.so.6", DependsOn: []string{}},
			},
		},
		{
			// DT_NEEDED is allowed to hold a path; the ground truth and the CycloneDX
			// refs both key off the bare name.
			name:     "path-valued entries reduce to their base name",
			needed:   []string{"/lib/x86_64-linux-gnu/libm.so.6"},
			filePath: "/usr/bin/nvim",
			want: []libtreeGraphNode{
				{Name: "nvim", DependsOn: []string{"libm.so.6"}},
				{Name: "libm.so.6", DependsOn: []string{}},
			},
		},
		{
			name:     "duplicates collapse and self references drop",
			needed:   []string{"libc.so.6", "libc.so.6", "nvim"},
			filePath: "/usr/bin/nvim",
			want: []libtreeGraphNode{
				{Name: "nvim", DependsOn: []string{"libc.so.6"}},
				{Name: "libc.so.6", DependsOn: []string{}},
			},
		},
		{
			// A static binary would otherwise contribute a component that states no
			// relationship at all, once per file in the effective layer.
			name:     "no entries yields nothing",
			needed:   nil,
			filePath: "/usr/bin/busybox",
			want:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, directNeededGraph(tt.needed, tt.filePath))
		})
	}
}

func TestDirectNeededLibraries_NonELF(t *testing.T) {
	dir := t.TempDir()
	text := filepath.Join(dir, "notes.txt")
	require.NoError(t, os.WriteFile(text, []byte("not an ELF file"), 0o600))

	assert.Nil(t, directNeededLibraries("", text))
	assert.Nil(t, directNeededLibraries("", filepath.Join(dir, "missing")))
}

// The graph is consumed by pkg/report/cyclonedx, which treats element 0 as the root and
// emits a component per element. Pin the encoding those two rely on.
func TestMergeDirectNeeded_WireFormat(t *testing.T) {
	res := NewAnalysisResult()
	mergeDirectNeeded(res, []string{"libc.so.6"}, "/usr/bin/nvim")

	require.Len(t, res.CustomResources, 1)
	cr := res.CustomResources[0]
	assert.Equal(t, "libtree", cr.Type)
	assert.Equal(t, "/usr/bin/nvim", cr.FilePath)

	raw, ok := cr.Data.([]byte)
	require.True(t, ok, "Data must stay []byte for the CycloneDX writer")
	assert.JSONEq(t, `[
		{"name":"nvim","dependsOn":["libc.so.6"]},
		{"name":"libc.so.6","dependsOn":[]}
	]`, string(raw))

	var graph []libtreeGraphNode
	require.NoError(t, json.Unmarshal(raw, &graph))
	assert.Equal(t, "nvim", graph[0].Name)
}

func TestMergeDirectNeeded_RecordsNothingWithoutDependencies(t *testing.T) {
	res := NewAnalysisResult()
	mergeDirectNeeded(res, nil, "/usr/bin/busybox")
	assert.Empty(t, res.CustomResources)
}
