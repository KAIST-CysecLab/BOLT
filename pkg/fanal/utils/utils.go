// Modified by slyfizz on 2025-05-14: upgraded file type checker

package utils

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
	"github.com/h2non/filetype"
	"github.com/h2non/filetype/types"
)

var (
	PathSeparator = fmt.Sprintf("%c", os.PathSeparator)
)

func CacheDir() string {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		cacheDir = os.TempDir()
	}
	return cacheDir
}

func IsCommandAvailable(name string) bool {
	if _, err := exec.LookPath(name); err != nil {
		return false
	}
	return true
}

func IsGzip(f *bufio.Reader) bool {
	buf, err := f.Peek(261)
	if err != nil {
		return false
	}
	return filetype.IsType(buf, types.Get("gz"))
}

func IsExecutable(fileInfo os.FileInfo) bool {
	if filepath.Ext(fileInfo.Name()) == ".exe" {
		return true
	}

	mode := fileInfo.Mode()
	if !mode.IsRegular() {
		return false
	}

	if mode.Perm()&0111 != 0 {
		return true
	}

	ext := strings.ToLower(filepath.Ext(fileInfo.Name()))
	switch ext {
	case ".elf", ".exe", ".macho":
		return true
	}

	return false
}

func IsBinary(content xio.ReadSeekerAt, fileSize int64) (bool, error) {
	headSize := int(math.Min(float64(fileSize), 261)) // filetype uses up to 261 bytes
	head := make([]byte, headSize)
	if _, err := content.Read(head); err != nil {
		return false, err
	}
	if _, err := content.Seek(0, io.SeekStart); err != nil {
		return false, err
	}

	kind, err := filetype.Match(head)
	if err != nil {
		return false, err
	}
	if kind == filetype.Unknown {
		return false, nil
	}
	log.Debug("utils.IsBinary matched ELF",
		log.String("kind", kind.Extension))

	switch kind.Extension {
	case "exe", "elf", "macho", "so", "dll":
		return true, nil
	default:
		return false, nil
	}
}

func CleanSkipPaths(skipPaths []string) []string {
	return lo.Map(skipPaths, func(skipPath string, index int) string {
		skipPath = filepath.ToSlash(filepath.Clean(skipPath))
		return strings.TrimLeft(skipPath, "/")
	})
}

func SkipPath(path string, skipPaths []string) bool {
	path = strings.TrimLeft(path, "/")

	// skip files
	for _, pattern := range skipPaths {
		match, err := doublestar.Match(pattern, path)
		if err != nil {
			return false // return early if bad pattern
		} else if match {
			log.Debug("Skipping path", log.String("path", path))
			return true
		}
	}
	return false
}

func ExtractPrintableBytes(content xio.ReadSeekerAt) ([]byte, error) {
	const minLength = 4 // Minimum length of strings to extract
	var result []byte
	currentPrintableLine := new(bytes.Buffer)

	current := make([]byte, 1) // buffer for 1 byte reading

	for {
		if n, err := content.Read(current); err == io.EOF {
			break
		} else if n != 1 {
			continue
		} else if err != nil {
			return nil, xerrors.Errorf("failed to read a byte: %w", err)
		}
		if unicode.IsPrint(rune(current[0])) {
			_ = currentPrintableLine.WriteByte(current[0])
			continue
		}
		if currentPrintableLine.Len() > minLength {
			// add a newline between printable lines to separate them
			_ = currentPrintableLine.WriteByte('\n')
			result = append(result, currentPrintableLine.Bytes()...)
		}
		currentPrintableLine.Reset()
	}
	if currentPrintableLine.Len() > minLength {
		// add a newline between printable lines to separate them
		_ = currentPrintableLine.WriteByte('\n')
		result = append(result, currentPrintableLine.Bytes()...)
	}
	return result, nil
}
