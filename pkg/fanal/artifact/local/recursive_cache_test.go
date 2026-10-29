package local

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/elfdeps"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
)

func ignoredELF(t *testing.T, filePath string, kind elf.Type) {
	t.Helper()
	header := elf.Header64{
		Type: uint16(kind), Machine: uint16(elf.EM_X86_64), Version: uint32(elf.EV_CURRENT),
		Ehsize: 64, Phentsize: 56, Shentsize: 64,
	}
	copy(header.Ident[:], []byte{'\x7f', 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)})
	var raw bytes.Buffer
	require.NoError(t, binary.Write(&raw, binary.LittleEndian, header))
	require.NoError(t, os.WriteFile(filePath, raw.Bytes(), 0755))
}

func TestRecursiveDependenciesRescanIgnoredELFInCleanGitRepository(t *testing.T) {
	root := t.TempDir()
	repository, err := git.PlainInit(root, false)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(root, ".gitignore"), []byte("build/\n"), 0600))
	worktree, err := repository.Worktree()
	require.NoError(t, err)
	_, err = worktree.Add(".gitignore")
	require.NoError(t, err)
	_, err = worktree.Commit("fixture", &git.CommitOptions{Author: &object.Signature{
		Name: "Test", Email: "test@example.invalid", When: time.Unix(1, 0),
	}})
	require.NoError(t, err)
	require.NoError(t, os.Mkdir(filepath.Join(root, "build"), 0700))
	filePath := filepath.Join(root, "build", "program")
	ignoredELF(t, filePath, elf.ET_EXEC)
	commit, err := gitCommitHash(root)
	require.NoError(t, err, "ignored ELF output must not make the repository dirty")

	mockCache := new(cache.MockArtifactCache)
	// A pre-existing result for this commit must not prevent reading new ELF
	// bytes. Ordinary scans can still reuse that same commit cache.
	mockCache.On("MissingBlobs", mock.Anything, mock.Anything).Return(false, []string(nil), nil).Maybe()
	var scanned []types.BlobInfo
	mockCache.On("PutBlob", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		scanned = append(scanned, args.Get(1).(types.BlobInfo))
	}).Return(nil).Twice()
	var refs []artifact.Reference
	for _, kind := range []elf.Type{elf.ET_EXEC, elf.ET_DYN} {
		ignoredELF(t, filePath, kind)
		unchanged, err := gitCommitHash(root)
		require.NoError(t, err)
		require.Equal(t, commit, unchanged)
		a, err := NewArtifact(root, mockCache, walker.NewFS(), artifact.Option{Libtree: true, Parallel: 1, BinarySBOM: []string{"none"}})
		require.NoError(t, err)
		ref, err := a.Inspect(context.Background())
		require.NoError(t, err)
		refs = append(refs, ref)
	}
	mockCache.AssertNotCalled(t, "MissingBlobs", mock.Anything, mock.Anything)
	require.NotEqual(t, refs[0].ID, refs[1].ID)
	require.Len(t, scanned, 2)
	for i, wantKind := range []string{"application", "library"} {
		var graph []elfdeps.Node
		for _, resource := range scanned[i].CustomResources {
			if resource.Type == "libtree" && resource.FilePath == "build/program" {
				require.NoError(t, json.Unmarshal(resource.Data.([]byte), &graph))
			}
		}
		require.Len(t, graph, 1, "each scan must reread the ignored ELF")
		require.Equal(t, "/build/program", graph[0].Path)
		require.Equal(t, wantKind, graph[0].Kind)
	}
	ordinary, err := NewArtifact(root, mockCache, walker.NewFS(), artifact.Option{Parallel: 1, BinarySBOM: []string{"none"}})
	require.NoError(t, err)
	_, err = ordinary.Inspect(context.Background())
	require.NoError(t, err)
	mockCache.AssertNumberOfCalls(t, "MissingBlobs", 1)
	mockCache.AssertExpectations(t)
}
