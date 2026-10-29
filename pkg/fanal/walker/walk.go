// Modified by aney666 on 2025-07-04: set the temporary-file size threshold to 0 so every analyzed file has a path on disk

package walker

import (
	"os"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
)

const defaultSizeThreshold = 0 //int64(100) << 20 // 200MB

var defaultSkipDirs = []string{
	"**/.git",
	"proc",
	"sys",
	"dev",
}

type Option struct {
	SkipFiles []string
	SkipDirs  []string
}

type WalkFunc func(filePath string, info os.FileInfo, opener analyzer.Opener) error
