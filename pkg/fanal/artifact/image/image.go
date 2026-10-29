// Modified by aney666 on 2025-06-26: Add the guessUserLayers function to detect effective user layers.
// Modified by aney666 on 2025-06-26: Modify the Inspect function to use the guessUserLayers function.
// Modified by aney666 on 2025-06-26: Modify the inspect function to set the IsEffectiveLayerKey context value for effective user layers.
// Modified by slyfizz on 2025-09-08: Modify the inspect function and guessUserLayers to fit in custom image.
// Modified by slyfizz on 2026-10-13: collected recursive ELF dependencies from the final image filesystem, starting from effective-user-layer files

package image

import (
	"context"
	"errors"
	"fmt"
	"io"

	//"os/exec"
	"sync"

	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	"github.com/docker/go-units"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/elfdeps"
	"github.com/aquasecurity/trivy/pkg/fanal/handler"
	"github.com/aquasecurity/trivy/pkg/fanal/image"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/parallel"
	"github.com/aquasecurity/trivy/pkg/semaphore"
	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
)

type Artifact struct {
	logger         *log.Logger
	image          types.Image
	cache          cache.ArtifactCache
	walker         walker.LayerTar
	analyzer       analyzer.AnalyzerGroup       // analyzer for files in container image
	configAnalyzer analyzer.ConfigAnalyzerGroup // analyzer for container image config
	handlerManager handler.Manager

	artifactOption artifact.Option

	layerCacheDir string
	elfResolver   *elfdeps.Resolver
	elfRoots      []string
	elfFinalLayer string
}

type LayerInfo struct {
	DiffID    string
	CreatedBy string // can be empty
}

func isCopyOrAddLayer(createdBy string) bool {
	s := strings.TrimSpace(strings.ToLower(createdBy))
	// e.g., "COPY /opt/... /opt/...", "ADD file.tar.gz /app", "copy --chown=..."
	return strings.HasPrefix(s, "copy") || strings.HasPrefix(s, "add")
}

func NewArtifact(img types.Image, c cache.ArtifactCache, opt artifact.Option) (artifact.Artifact, error) {
	// Initialize handlers
	handlerManager, err := handler.NewManager(opt)
	if err != nil {
		return nil, xerrors.Errorf("handler init error: %w", err)
	}

	a, err := analyzer.NewAnalyzerGroup(opt.AnalyzerOptions())
	if err != nil {
		return nil, xerrors.Errorf("analyzer group error: %w", err)
	}

	ca, err := analyzer.NewConfigAnalyzerGroup(opt.ConfigAnalyzerOptions())
	if err != nil {
		return nil, xerrors.Errorf("config analyzer group error: %w", err)
	}

	cacheDir, err := os.MkdirTemp("", "layers")
	if err != nil {
		return nil, xerrors.Errorf("failed to create a cache layers temp dir: %w", err)
	}

	return Artifact{
		logger:         log.WithPrefix("image"),
		image:          img,
		cache:          c,
		walker:         walker.NewLayerTar(opt.WalkerOption),
		analyzer:       a,
		configAnalyzer: ca,
		handlerManager: handlerManager,

		artifactOption: opt,
		layerCacheDir:  cacheDir,
	}, nil
}

func (a Artifact) Inspect(ctx context.Context) (ref artifact.Reference, err error) {
	imageID, err := a.image.ID()
	if err != nil {
		return artifact.Reference{}, xerrors.Errorf("unable to get the image ID: %w", err)
	}
	a.logger.Debug("Detected image ID", log.String("image_id", imageID))

	configFile, err := a.image.ConfigFile()
	if err != nil {
		return artifact.Reference{}, xerrors.Errorf("unable to get the image's config file: %w", err)
	}

	diffIDs := a.diffIDs(configFile)
	a.logger.Debug("Detected diff ID", log.Any("diff_ids", diffIDs))

	defer func() {
		if rerr := os.RemoveAll(a.layerCacheDir); rerr != nil {
			log.Error("Failed to remove layer cache", log.Err(rerr))
		}
	}()
	if err := a.checkImageSize(ctx, diffIDs); err != nil {
		return artifact.Reference{}, err
	}

	// A remote SBOM cannot supply the target bytes needed for recursive ELF
	// resolution. In that mode, inspect the image even if an SBOM is available.
	if !a.artifactOption.Libtree {
		if res, err := a.retrieveRemoteSBOM(ctx); err == nil {
			return res, nil
		} else if !errors.Is(err, errNoSBOMFound) {
			return artifact.Reference{}, xerrors.Errorf("remote SBOM fetching error: %w", err)
		}
	}

	// Try to detect base layers.
	baseDiffIDs := a.guessBaseLayers(diffIDs, configFile)
	userDiffIDs := a.guessUserLayers(diffIDs, configFile)
	a.logger.Debug("Detected base layers", log.Any("diff_ids", baseDiffIDs))
	a.logger.Debug("Detected effective user layers", log.Any("diff_ids", userDiffIDs))

	// Convert image ID and layer IDs to cache keys
	imageKey, layerKeys, err := a.calcCacheKeys(imageID, diffIDs)
	if err != nil {
		return artifact.Reference{}, err
	}

	// Parse histories and extract a list of "created_by"
	layerKeyMap := a.consolidateCreatedBy(diffIDs, layerKeys, configFile)
	effectiveUserDiffIDs := a.effectiveUserLayers(userDiffIDs, layerKeyMap)

	missingImage, missingLayers, err := a.cache.MissingBlobs(imageKey, layerKeys)
	if err != nil {
		return artifact.Reference{}, xerrors.Errorf("unable to get missing layers: %w", err)
	}

	missingImageKey := imageKey
	if missingImage {
		a.logger.Debug("Missing image ID in cache", log.String("image_id", imageID))
	} else {
		missingImageKey = ""
	}

	if a.artifactOption.Libtree && len(missingLayers) > 0 && len(effectiveUserDiffIDs) > 0 {
		rootFS, err := a.dependencyFilesystem(ctx, diffIDs)
		if err != nil {
			return artifact.Reference{}, err
		}
		defer rootFS.Close()
		a.elfResolver = elfdeps.NewResolver(rootFS, dependencyOptions(configFile))
		var rootLayers []int
		for i, diffID := range diffIDs {
			if slices.Contains(effectiveUserDiffIDs, diffID) {
				rootLayers = append(rootLayers, i)
			}
		}
		// Search dependencies across the complete image, but start only from
		// surviving files introduced by the existing effective-user-layer policy.
		a.elfRoots = rootFS.RegularPathsFromLayers(rootLayers)
		if len(diffIDs) > 0 {
			a.elfFinalLayer = diffIDs[len(diffIDs)-1]
		}
	}

	if err = a.inspect(ctx, missingImageKey, missingLayers, baseDiffIDs, userDiffIDs, layerKeyMap, configFile); err != nil {
		return artifact.Reference{}, xerrors.Errorf("analyze error: %w", err)
	}

	return artifact.Reference{
		Name:    a.image.Name(),
		Type:    artifact.TypeContainerImage,
		ID:      imageKey,
		BlobIDs: layerKeys,
		ImageMetadata: artifact.ImageMetadata{
			ID:          imageID,
			DiffIDs:     diffIDs,
			RepoTags:    a.image.RepoTags(),
			RepoDigests: a.image.RepoDigests(),
			ConfigFile:  *configFile,
		},
	}, nil
}

func (a Artifact) Clean(_ artifact.Reference) error {
	return nil
}

func (a Artifact) calcCacheKeys(imageID string, diffIDs []string) (string, []string, error) {
	// Pass an empty config scanner option so that the cache key can be the same, even when policies are updated.
	imageKey, err := cache.CalcKey(imageID, a.configAnalyzer.AnalyzerVersions(), nil, artifact.Option{})
	if err != nil {
		return "", nil, err
	}

	hookVersions := a.handlerManager.Versions()
	var layerKeys []string
	for _, diffID := range diffIDs {
		cacheID := diffID
		if a.artifactOption.Libtree {
			// The same layer can resolve to different libraries in different final
			// images. The config ID covers all layers, ENV and WORKDIR.
			cacheID = imageID + ":" + diffID
		}
		blobKey, err := cache.CalcKey(cacheID, a.analyzer.AnalyzerVersions(), hookVersions, a.artifactOption)
		if err != nil {
			return "", nil, err
		}
		layerKeys = append(layerKeys, blobKey)
	}
	return imageKey, layerKeys, nil
}

func (a Artifact) consolidateCreatedBy(diffIDs, layerKeys []string, configFile *v1.ConfigFile) map[string]LayerInfo {
	// save createdBy fields in order of layers
	var createdBy []string
	for _, h := range configFile.History {
		// skip histories for empty layers
		if h.EmptyLayer {
			continue
		}
		c := strings.TrimPrefix(h.CreatedBy, "/bin/sh -c ")
		c = strings.TrimPrefix(c, "#(nop) ")
		createdBy = append(createdBy, c)
	}

	// If history detected incorrect - use only diffID
	// TODO: our current logic may not detect empty layers correctly in rare cases.
	validCreatedBy := len(diffIDs) == len(createdBy)

	layerKeyMap := make(map[string]LayerInfo)
	for i, diffID := range diffIDs {

		c := ""
		if validCreatedBy {
			c = createdBy[i]
		}

		layerKey := layerKeys[i]
		layerKeyMap[layerKey] = LayerInfo{
			DiffID:    diffID,
			CreatedBy: c,
		}
	}
	return layerKeyMap
}

func (a Artifact) imageSizeError(typ string, size int64) error {
	return &trivyTypes.UserError{
		Message: fmt.Sprintf(
			"%s size %s exceeds maximum allowed size %s", typ,
			units.HumanSizeWithPrecision(float64(size), 3),
			units.HumanSize(float64(a.artifactOption.ImageOption.MaxImageSize)),
		),
	}
}

func (a Artifact) checkImageSize(ctx context.Context, diffIDs []string) error {
	if a.artifactOption.ImageOption.MaxImageSize == 0 {
		return nil
	}

	if err := a.checkCompressedImageSize(diffIDs); err != nil {
		return xerrors.Errorf("failed to get compressed image size: %w", err)
	}

	if err := a.checkUncompressedImageSize(ctx, diffIDs); err != nil {
		return xerrors.Errorf("failed to calculate image size: %w", err)
	}
	return nil
}

func (a Artifact) checkCompressedImageSize(diffIDs []string) error {
	var totalSize int64

	for _, diffID := range diffIDs {
		h, err := v1.NewHash(diffID)
		if err != nil {
			return xerrors.Errorf("invalid layer ID (%s): %w", diffID, err)
		}

		layer, err := a.image.LayerByDiffID(h)
		if err != nil {
			return xerrors.Errorf("failed to get the layer (%s): %w", diffID, err)
		}
		layerSize, err := layer.Size()
		if err != nil {
			return xerrors.Errorf("failed to get layer size: %w", err)
		}
		totalSize += layerSize
	}

	if totalSize > a.artifactOption.ImageOption.MaxImageSize {
		return a.imageSizeError("compressed image", totalSize)
	}

	return nil
}

func (a Artifact) checkUncompressedImageSize(ctx context.Context, diffIDs []string) error {
	var totalSize int64

	p := parallel.NewPipeline(a.artifactOption.Parallel, false, diffIDs,
		func(_ context.Context, diffID string) (int64, error) {
			layerSize, err := a.saveLayer(diffID)
			if err != nil {
				return -1, xerrors.Errorf("failed to save layer: %w", err)
			}
			return layerSize, nil
		},
		func(layerSize int64) error {
			totalSize += layerSize
			if totalSize > a.artifactOption.ImageOption.MaxImageSize {
				return a.imageSizeError("uncompressed layers", totalSize)
			}
			return nil
		},
	)

	if err := p.Do(ctx); err != nil {
		return xerrors.Errorf("pipeline error: %w", err)
	}

	return nil
}

func (a Artifact) saveLayer(diffID string) (int64, error) {
	a.logger.Debug("Pulling the layer to the local cache", log.String("diff_id", diffID))
	_, rc, err := a.uncompressedLayer(diffID)
	if err != nil {
		return -1, xerrors.Errorf("unable to get uncompressed layer %s: %w", diffID, err)
	}
	defer rc.Close()

	f, err := os.Create(filepath.Join(a.layerCacheDir, diffID))
	if err != nil {
		return -1, xerrors.Errorf("failed to create a file: %w", err)
	}
	defer f.Close()

	return io.Copy(f, rc)
}

// Per layer, mark only the COPY/ADD layers among the user layers as effective layers (with fallback), with debug logs
// Per layer, mark only the user layers that "bring in actual content" as effective layers (excluding package-install RUN layers, with fallback)
func (a Artifact) inspect(
	ctx context.Context,
	missingImage string,
	layerKeys, baseDiffIDs []string,
	userDiffIDs []string,
	layerKeyMap map[string]LayerInfo,
	configFile *v1.ConfigFile,
) error {
	var osFound types.OS

	effectiveUserDiffIDs := a.effectiveUserLayers(userDiffIDs, layerKeyMap)

	effSet := make(map[string]struct{}, len(effectiveUserDiffIDs))
	for _, d := range effectiveUserDiffIDs {
		effSet[d] = struct{}{}
	}
	a.logger.Debug("inspect: effective user diffIDs", log.Any("diff_ids", effectiveUserDiffIDs))

	// Layer processing pipeline
	p := parallel.NewPipeline(a.artifactOption.Parallel, false, layerKeys,
		func(_ context.Context, layerKey string) (any, error) {
			layer := layerKeyMap[layerKey]

			// A new context per layer (so values do not leak between layers)
			lctx := ctx

			isUser := slices.Contains(userDiffIDs, layer.DiffID)
			_, isEffective := effSet[layer.DiffID]
			a.logger.Debug("layer gating",
				log.String("diff_id", layer.DiffID),
				log.Bool("is_user_layer", isUser),
				log.Bool("is_effective_user_layer", isEffective),
				log.String("created_by", layer.CreatedBy),
			)

			var disabledAnalyzers []analyzer.Type
			if isEffective {
				// Built-in analyzers to disable follow the existing logic (e.g. Secret)
				disabledAnalyzers = append(disabledAnalyzers, analyzer.TypeSecret)
				lctx = context.WithValue(lctx, analyzer.IsEffectiveLayerKey, true)
			}

			li, err := a.inspectLayer(lctx, layer, disabledAnalyzers)
			if err != nil {
				return nil, xerrors.Errorf("failed to analyze layer (%s): %w", layer.DiffID, err)
			}
			if err = a.cache.PutBlob(layerKey, li); err != nil {
				return nil, xerrors.Errorf("failed to store layer: %s in cache: %w", layerKey, err)
			}
			if lo.IsNotEmpty(li.OS) {
				osFound = li.OS
			}
			return nil, nil
		},
		nil,
	)

	if err := p.Do(ctx); err != nil {
		return xerrors.Errorf("pipeline error: %w", err)
	}

	if missingImage != "" {
		if err := a.inspectConfig(ctx, missingImage, osFound, configFile); err != nil {
			return xerrors.Errorf("unable to analyze config: %w", err)
		}
	}

	return nil
}

func (a Artifact) inspectLayer(ctx context.Context, layerInfo LayerInfo, disabled []analyzer.Type) (types.BlobInfo, error) {
	a.logger.Debug("Missing diff ID in cache", log.String("diff_id", layerInfo.DiffID))

	layerDigest, rc, err := a.uncompressedLayer(layerInfo.DiffID)
	if err != nil {
		return types.BlobInfo{}, xerrors.Errorf("unable to get uncompressed layer %s: %w", layerInfo.DiffID, err)
	}
	defer rc.Close()

	// Prepare variables
	var wg sync.WaitGroup
	opts := analyzer.AnalysisOptions{
		Offline:             a.artifactOption.Offline,
		FileChecksum:        a.artifactOption.FileChecksum,
		SkipELFDependencies: a.artifactOption.Libtree,
	}
	result := analyzer.NewAnalysisResult()
	limit := semaphore.New(a.artifactOption.Parallel)

	// Prepare filesystem for post analysis
	composite, err := a.analyzer.PostAnalyzerFS()
	if err != nil {
		return types.BlobInfo{}, xerrors.Errorf("unable to get post analysis filesystem: %w", err)
	}
	defer composite.Cleanup()

	// Walk a tar layer
	opqDirs, whFiles, err := a.walker.Walk(rc, func(filePath string, info os.FileInfo, opener analyzer.Opener) error {

		if err = a.analyzer.AnalyzeFile(ctx, &wg, limit, result, "", filePath, info, opener, disabled, opts); err != nil {
			return xerrors.Errorf("failed to analyze %s: %w", filePath, err)
		}

		// Skip post analysis if the file is not required
		analyzerTypes := a.analyzer.RequiredPostAnalyzers(filePath, info)
		if len(analyzerTypes) == 0 {
			return nil
		}

		// Build filesystem for post analysis
		tmpFilePath, err := composite.CopyFileToTemp(opener, info)
		if err != nil {
			return xerrors.Errorf("failed to copy file to temp: %w", err)
		}
		if err = composite.CreateLink(analyzerTypes, "", filePath, tmpFilePath); err != nil {
			return xerrors.Errorf("failed to write a file: %w", err)
		}

		return nil
	})
	if err != nil {
		return types.BlobInfo{}, xerrors.Errorf("walk error: %w", err)
	}

	// Wait for all the goroutine to finish.
	wg.Wait()

	// Tar names are not final paths: writing through a directory symlink and
	// later removing that symlink leaves a file under its canonical directory.
	// Collect surviving effective-user-layer ELF roots (including hard links
	// and sparse entries) once from the final snapshot after all whiteouts.
	// The last image-scoped blob keeps later layer merging from deleting them.
	if a.elfResolver != nil && layerInfo.DiffID == a.elfFinalLayer {
		for _, name := range a.elfRoots {
			if a.skipDependencyRoot(name) {
				continue
			}
			if err := analyzer.AnalyzeELFDependencies(ctx, result, a.elfResolver, strings.TrimPrefix(name, "/")); err != nil {
				return types.BlobInfo{}, err
			}
		}
	}

	// Post-analysis
	if err = a.analyzer.PostAnalyze(ctx, composite, result, opts); err != nil {
		return types.BlobInfo{}, xerrors.Errorf("post analysis error: %w", err)
	}

	// Sort the analysis result for consistent results
	result.Sort()

	blobInfo := types.BlobInfo{
		SchemaVersion:     types.BlobJSONSchemaVersion,
		Digest:            layerDigest,
		DiffID:            layerInfo.DiffID,
		CreatedBy:         layerInfo.CreatedBy,
		OpaqueDirs:        opqDirs,
		WhiteoutFiles:     whFiles,
		OS:                result.OS,
		Repository:        result.Repository,
		PackageInfos:      result.PackageInfos,
		Applications:      result.Applications,
		Misconfigurations: result.Misconfigurations,
		Secrets:           result.Secrets,
		Licenses:          result.Licenses,
		CustomResources:   result.CustomResources,

		// For Red Hat
		BuildInfo: result.BuildInfo,
	}

	// Call post handlers to modify blob info
	if err = a.handlerManager.PostHandle(ctx, result, &blobInfo); err != nil {
		return types.BlobInfo{}, xerrors.Errorf("post handler error: %w", err)
	}

	return blobInfo, nil
}

func (a Artifact) diffIDs(configFile *v1.ConfigFile) []string {
	if configFile == nil {
		return nil
	}
	return lo.Map(configFile.RootFS.DiffIDs, func(diffID v1.Hash, _ int) string {
		return diffID.String()
	})
}

func (a Artifact) uncompressedLayer(diffID string) (string, io.ReadCloser, error) {
	// diffID is a hash of the uncompressed layer
	h, err := v1.NewHash(diffID)
	if err != nil {
		return "", nil, xerrors.Errorf("invalid layer ID (%s): %w", diffID, err)
	}

	layer, err := a.image.LayerByDiffID(h)
	if err != nil {
		return "", nil, xerrors.Errorf("failed to get the layer (%s): %w", diffID, err)
	}

	// digest is a hash of the compressed layer
	var digest string
	if a.isCompressed(layer) {
		d, err := layer.Digest()
		if err != nil {
			return "", nil, xerrors.Errorf("failed to get the digest (%s): %w", diffID, err)
		}
		digest = d.String()
	}

	f, err := os.Open(filepath.Join(a.layerCacheDir, diffID))
	if err == nil {
		a.logger.Debug("Loaded the layer from the local cache", log.String("diff_id", diffID))
		return digest, f, nil
	}

	rc, err := layer.Uncompressed()
	if err != nil {
		return "", nil, xerrors.Errorf("failed to get the layer content (%s): %w", diffID, err)
	}
	return digest, rc, nil
}

// ref. https://github.com/google/go-containerregistry/issues/701
func (a Artifact) isCompressed(l v1.Layer) bool {
	_, uncompressed := reflect.TypeOf(l).Elem().FieldByName("UncompressedLayer")
	return !uncompressed
}

func (a Artifact) inspectConfig(ctx context.Context, imageID string, osFound types.OS, config *v1.ConfigFile) error {
	result := lo.FromPtr(a.configAnalyzer.AnalyzeImageConfig(ctx, osFound, config))

	info := types.ArtifactInfo{
		SchemaVersion:    types.ArtifactJSONSchemaVersion,
		Architecture:     config.Architecture,
		Created:          config.Created.Time,
		DockerVersion:    config.DockerVersion,
		OS:               config.OS,
		Misconfiguration: result.Misconfiguration,
		Secret:           result.Secret,
		HistoryPackages:  result.HistoryPackages,
	}

	if err := a.cache.PutArtifact(imageID, info); err != nil {
		return xerrors.Errorf("failed to put image info into the cache: %w", err)
	}

	return nil
}

// guessBaseLayers guesses layers in base image (call base layers).
func (a Artifact) guessBaseLayers(diffIDs []string, configFile *v1.ConfigFile) []string {
	if configFile == nil {
		return nil
	}

	baseImageIndex := image.GuessBaseImageIndex(configFile.History)

	// Diff IDs don't include empty layers, so the index is different from histories
	var diffIDIndex int
	var baseDiffIDs []string
	for i, h := range configFile.History {
		// It is no longer base layer.
		if i > baseImageIndex {
			break
		}
		// Empty layers are not included in diff IDs.
		if h.EmptyLayer {
			continue
		}

		if diffIDIndex >= len(diffIDs) {
			// something wrong...
			return nil
		}
		baseDiffIDs = append(baseDiffIDs, diffIDs[diffIDIndex])
		diffIDIndex++
	}
	return baseDiffIDs
}

// User layers = all diffIDs - base diffIDs (avoids overlaps and misdetection; with debug logs)
func (a Artifact) guessUserLayers(diffIDs []string, configFile *v1.ConfigFile) []string {
	if configFile == nil {
		return nil
	}

	// 1) Reuse the base-layer detection
	baseDiffIDs := a.guessBaseLayers(diffIDs, configFile)
	a.logger.Debug("guessUserLayers: base diffIDs", log.Any("diff_ids", baseDiffIDs))

	if len(baseDiffIDs) == 0 {
		// Rare case where no base layer is detected: return no user layers either, to avoid over-scanning
		a.logger.Debug("guessUserLayers: no base layers detected; returning empty user set")
		return nil
	}

	// 2) Determine the user layers by set difference
	baseSet := make(map[string]struct{}, len(baseDiffIDs))
	for _, id := range baseDiffIDs {
		baseSet[id] = struct{}{}
	}

	var user []string
	for _, id := range diffIDs {
		if _, isBase := baseSet[id]; !isBase {
			user = append(user, id)
		}
	}
	a.logger.Debug("guessUserLayers: user diffIDs", log.Any("diff_ids", user))
	return user
}
