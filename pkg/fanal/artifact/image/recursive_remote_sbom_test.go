package image_test

import (
	"context"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	imageartifact "github.com/aquasecurity/trivy/pkg/fanal/artifact/image"
)

type recursiveRoutingImage struct{ v1.Image }

func (recursiveRoutingImage) ID() (string, error)   { return "recursive-routing-fixture", nil }
func (recursiveRoutingImage) Name() string          { return "local archive is not a registry reference" }
func (recursiveRoutingImage) RepoTags() []string    { return nil }
func (recursiveRoutingImage) RepoDigests() []string { return nil }

func TestRecursiveDependenciesBypassRemoteSBOMLookup(t *testing.T) {
	for _, recursive := range []bool{true, false} {
		t.Run(map[bool]string{true: "recursive inspects target", false: "ordinary retains remote lookup"}[recursive], func(t *testing.T) {
			mockCache := new(cache.MockArtifactCache)
			if recursive {
				mockCache.On("MissingBlobs", mock.Anything, mock.Anything).Return(false, []string(nil), nil).Once()
			}
			// This local-image name deliberately fails the registry-only lookup
			// before any network request. Recursive mode must inspect the native
			// image instead, even when a remote SBOM source was requested.
			a, err := imageartifact.NewArtifact(recursiveRoutingImage{Image: empty.Image}, mockCache, artifact.Option{
				Libtree: recursive, SBOMSources: []string{"oci"}, Parallel: 1, BinarySBOM: []string{"none"},
			})
			require.NoError(t, err)
			ref, err := a.Inspect(context.Background())
			if recursive {
				require.NoError(t, err)
				require.Equal(t, artifact.TypeContainerImage, ref.Type)
				mockCache.AssertExpectations(t)
			} else {
				require.ErrorContains(t, err, "remote SBOM fetching error")
				mockCache.AssertNotCalled(t, "MissingBlobs", mock.Anything, mock.Anything)
			}
		})
	}
}
