// Modified by aney666 on 2025-07-04: returned the temporary file path from Open

package walker

import (
	"bytes"
	"io"
	"os"
	"sync"

	"golang.org/x/xerrors"

	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

// cachedFile represents a file cached in memory or storage according to the file size.
type cachedFile struct {
	once sync.Once
	err  error

	size   int64
	reader io.Reader

	content  []byte // It will be populated if this file is small
	filePath string // It will be populated if this file is large
}

func newCachedFile(size int64, r io.Reader) *cachedFile {
	return &cachedFile{
		size:   size,
		reader: r,
	}
}

// Open opens a file and cache the file.
// If the file size is greater than or equal to threshold, it copies the content to a temp file and opens it next time.
// If the file size is less than threshold, it opens the file once and the content will be shared so that others analyzers can use the same data.
func (o *cachedFile) Open() (xio.ReadSeekCloserAt, string, error) { 
	// The path of the temp file holding an image file must be available when Open() is called,
	// so Open also returns it as a string; the signatures of related functions changed accordingly.
	o.once.Do(func() {
		// When the file is large, it will be written down to a temp file.
		if o.size >= defaultSizeThreshold {
			// defaultSizeThreshold was originally 200MB, and files smaller than that
			// are read whole into a memory buffer.
			// That does not work for us, since we need a path on disk,
			// so the threshold was lowered to 0 (a temp file is created for every file).
			f, err := os.CreateTemp("", "fanal-*")
			if err != nil {
				o.err = xerrors.Errorf("failed to create the temp file: %w", err)
				return
			}

			if _, err = io.Copy(f, o.reader); err != nil {
				o.err = xerrors.Errorf("failed to copy: %w", err)
				return
			}

			o.filePath = f.Name()
		} else {
			b, err := io.ReadAll(o.reader)
			if err != nil {
				o.err = xerrors.Errorf("unable to read the file: %w", err)
				return
			}
			o.content = b
		}
	})
	if o.err != nil {
		return nil, "", xerrors.Errorf("failed to open: %w", o.err)
	}

	return o.open()
}

func (o *cachedFile) open() (xio.ReadSeekCloserAt, string, error) {
	if o.filePath != "" {
		f, err := os.Open(o.filePath)
		if err != nil {
			return nil, "", xerrors.Errorf("failed to open the temp file: %w", err)
		}
		return f, o.filePath, nil
		// The temp file path is o.filePath.
	}

	return xio.NopCloser(bytes.NewReader(o.content)), "", nil
}

func (o *cachedFile) Clean() error {
	return os.Remove(o.filePath)
}
