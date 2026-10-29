package image_test

import (
	"archive/tar"
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/applier"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	imageartifact "github.com/aquasecurity/trivy/pkg/fanal/artifact/image"
	"github.com/aquasecurity/trivy/pkg/fanal/elfdeps"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
)

func TestFinalELFRootsSurviveArchiveAliasDeletionAndPartialCache(t *testing.T) {
	header := elf.Header64{Type: uint16(elf.ET_DYN), Machine: uint16(elf.EM_X86_64), Version: 1, Ehsize: 64, Phentsize: 56, Shentsize: 64}
	copy(header.Ident[:], []byte{'\x7f', 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), 1})
	var elfBytes bytes.Buffer
	require.NoError(t, binary.Write(&elfBytes, binary.LittleEndian, header))
	var base, user, upper bytes.Buffer
	w := tar.NewWriter(&base)
	require.NoError(t, w.WriteHeader(&tar.Header{Name: "base-release", Mode: 0644, Size: 4}))
	_, err := w.Write([]byte("base"))
	require.NoError(t, err)
	require.NoError(t, w.Close())
	w = tar.NewWriter(&user)
	require.NoError(t, w.WriteHeader(&tar.Header{Name: "real", Typeflag: tar.TypeDir, Mode: 0755}))
	require.NoError(t, w.WriteHeader(&tar.Header{Name: "obj", Typeflag: tar.TypeSymlink, Linkname: "/real", Mode: 0777}))
	require.NoError(t, w.WriteHeader(&tar.Header{Name: "obj/app.so", Mode: 0755, Size: int64(elfBytes.Len())}))
	_, err = w.Write(elfBytes.Bytes())
	require.NoError(t, err)
	require.NoError(t, w.Close())
	w = tar.NewWriter(&upper)
	require.NoError(t, w.WriteHeader(&tar.Header{Name: ".wh.obj", Mode: 0644}))
	require.NoError(t, w.Close())
	img, err := mutate.AppendLayers(empty.Image,
		static.NewLayer(base.Bytes(), v1types.OCIUncompressedLayer),
		static.NewLayer(user.Bytes(), v1types.OCIUncompressedLayer),
		static.NewLayer(upper.Bytes(), v1types.OCIUncompressedLayer))
	require.NoError(t, err)
	config, err := img.ConfigFile()
	require.NoError(t, err)
	config.History = []v1.History{
		{CreatedBy: "ADD base /"},
		{CreatedBy: "CMD [\"/bin/sh\"]", EmptyLayer: true},
		{CreatedBy: "COPY app /obj/app.so"},
		{CreatedBy: "/bin/sh -c rm /obj"},
	}
	img, err = mutate.ConfigFile(img, config)
	require.NoError(t, err)
	c := cache.NewMemoryCache()
	inspect := func(skip bool) (artifact.Reference, []types.CustomResource) {
		t.Helper()
		opts := artifact.Option{Libtree: true, Parallel: 1, BinarySBOM: []string{"none"}}
		if skip {
			opts.WalkerOption = walker.Option{SkipFiles: []string{"real/app.so"}}
		}
		a, err := imageartifact.NewArtifact(recursiveRoutingImage{Image: img}, c, opts)
		require.NoError(t, err)
		ref, err := a.Inspect(context.Background())
		require.NoError(t, err)
		var blobs []types.BlobInfo
		for _, id := range ref.BlobIDs {
			blob, err := c.GetBlob(id)
			require.NoError(t, err)
			blobs = append(blobs, blob)
		}
		return ref, applier.ApplyLayers(blobs).CustomResources
	}
	ref, resources := inspect(false)
	check := func(resources []types.CustomResource) {
		t.Helper()
		var graphs []types.CustomResource
		for _, r := range resources {
			if r.Type == "libtree" {
				graphs = append(graphs, r)
			}
		}
		require.Len(t, graphs, 1, "final canonical root must survive deleted tar alias")
		require.Equal(t, "real/app.so", graphs[0].FilePath)
		var nodes []elfdeps.Node
		require.NoError(t, json.Unmarshal(graphs[0].Data.([]byte), &nodes))
		require.Len(t, nodes, 1)
		require.Equal(t, "/real/app.so", nodes[0].Path)
	}
	check(resources)
	for _, id := range ref.BlobIDs {
		require.NoError(t, c.DeleteBlobs([]string{id}))
		_, resources = inspect(false)
		check(resources)
	}
	_, resources = inspect(false)
	check(resources)
	_, resources = inspect(true)
	for _, r := range resources {
		require.NotEqual(t, "libtree", r.Type, "skip-files must also apply to final canonical roots")
	}
}
