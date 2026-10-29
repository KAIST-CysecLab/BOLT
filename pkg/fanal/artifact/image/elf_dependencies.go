package image

import (
	"context"
	"fmt"
	"io"
	"path"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/aquasecurity/trivy/pkg/fanal/elfdeps"
	"github.com/aquasecurity/trivy/pkg/fanal/utils"
	"github.com/aquasecurity/trivy/pkg/log"
)

// dependencyFilesystem applies every image layer in order, including base
// layers. Library lookup never uses the filesystem of the scanner process.
func (a Artifact) dependencyFilesystem(ctx context.Context, diffIDs []string) (*elfdeps.LayerFS, error) {
	a.logger.Info("Indexing target image filesystem for recursive ELF dependencies")
	rootFS, err := elfdeps.NewLayerFS(a.layerCacheDir)
	if err != nil {
		return nil, err
	}
	for _, diffID := range diffIDs {
		if err := ctx.Err(); err != nil {
			_ = rootFS.Close()
			return nil, err
		}
		_, reader, err := a.uncompressedLayer(diffID)
		if err != nil {
			_ = rootFS.Close()
			return nil, err
		}
		err = rootFS.AddLayer(dependencyLayerReader{Context: ctx, Reader: reader})
		closeErr := reader.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			_ = rootFS.Close()
			return nil, fmt.Errorf("index ELF dependency filesystem layer %s: %w", diffID, err)
		}
	}
	a.logger.Debug("Target image filesystem ready", log.Any("layers", len(diffIDs)))
	return rootFS, nil
}

func (a Artifact) skipDependencyRoot(name string) bool {
	if utils.SkipPath(name, utils.CleanSkipPaths(a.artifactOption.WalkerOption.SkipFiles)) {
		return true
	}
	dirs := utils.CleanSkipPaths(a.artifactOption.WalkerOption.SkipDirs)
	for dir := path.Dir(name); dir != "/" && dir != "."; dir = path.Dir(dir) {
		if utils.SkipPath(dir, dirs) {
			return true
		}
	}
	return false
}

type dependencyLayerReader struct {
	context.Context
	io.Reader
}

func (r dependencyLayerReader) Read(p []byte) (int, error) {
	if err := r.Context.Err(); err != nil {
		return 0, err
	}
	return r.Reader.Read(p)
}

func dependencyOptions(config *v1.ConfigFile) elfdeps.Options {
	opts := elfdeps.Options{WorkingDir: config.Config.WorkingDir}
	for _, env := range config.Config.Env {
		if value, ok := strings.CutPrefix(env, "LD_LIBRARY_PATH="); ok {
			opts.LibraryPath = nil
			if value != "" {
				// Let the target loader rules split the original value. Splitting
				// here loses empty GNU entries (WORKDIR) and treats musl's literal
				// semicolons as GNU separators.
				opts.LibraryPath = []string{value}
			}
		}
	}
	return opts
}
