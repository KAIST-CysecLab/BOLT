// Modified by KimSeoYe on 2026-08-07: tested --binary-sbom parsing and explicit generator selection
// Modified by KimSeoYe on 2026-10-13: updated tests for bin-sbom as the default generator
// Modified by KimSeoYe on 2026-10-29: updated tests for bom-blint as the default generator

package flag_test

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestScanFlagGroup_ToOptions(t *testing.T) {
	type fields struct {
		skipDirs    []string
		skipFiles   []string
		offlineScan bool
		scanners    string
		distro      string
	}
	tests := []struct {
		name      string
		args      []string
		fields    fields
		want      flag.ScanOptions
		assertion require.ErrorAssertionFunc
	}{
		{
			name:   "happy path",
			args:   []string{"alpine:latest"},
			fields: fields{},
			want: flag.ScanOptions{
				Target: "alpine:latest",
			},
			assertion: require.NoError,
		},
		{
			name: "happy path for configs",
			args: []string{"alpine:latest"},
			fields: fields{
				scanners: "misconfig",
			},
			want: flag.ScanOptions{
				Target:   "alpine:latest",
				Scanners: types.Scanners{types.MisconfigScanner},
			},
			assertion: require.NoError,
		},
		{
			name:      "without target (args)",
			args:      []string{},
			fields:    fields{},
			want:      flag.ScanOptions{},
			assertion: require.NoError,
		},
		{
			name: "with two or more targets (args)",
			args: []string{
				"alpine:latest",
				"nginx:latest",
			},
			fields:    fields{},
			want:      flag.ScanOptions{},
			assertion: require.NoError,
		},
		{
			name: "skip two files",
			fields: fields{
				skipFiles: []string{
					"file1",
					"file2",
				},
			},
			want: flag.ScanOptions{
				SkipFiles: []string{
					"file1",
					"file2",
				},
			},
			assertion: require.NoError,
		},
		{
			name: "skip two folders",
			fields: fields{
				skipDirs: []string{
					"dir1",
					"dir2",
				},
			},
			want: flag.ScanOptions{
				SkipDirs: []string{
					"dir1",
					"dir2",
				},
			},
			assertion: require.NoError,
		},
		{
			name: "offline scan",
			fields: fields{
				offlineScan: true,
			},
			want: flag.ScanOptions{
				OfflineScan: true,
			},
			assertion: require.NoError,
		},
		{
			name: "happy path `distro` flag",
			fields: fields{
				distro: "alpine/3.20",
			},
			want: flag.ScanOptions{
				Distro: ftypes.OS{
					Family: "alpine",
					Name:   "3.20",
				},
			},
			assertion: require.NoError,
		},
		{
			name: "sad distro flag",
			fields: fields{
				distro: "sad",
			},
			assertion: require.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(viper.Reset)
			setSliceValue(flag.SkipDirsFlag.ConfigName, tt.fields.skipDirs)
			setSliceValue(flag.SkipFilesFlag.ConfigName, tt.fields.skipFiles)
			setValue(flag.OfflineScanFlag.ConfigName, tt.fields.offlineScan)
			setValue(flag.ScannersFlag.ConfigName, tt.fields.scanners)
			setValue(flag.DistroFlag.ConfigName, tt.fields.distro)

			// Assert options
			f := &flag.ScanFlagGroup{
				SkipDirs:    flag.SkipDirsFlag.Clone(),
				SkipFiles:   flag.SkipFilesFlag.Clone(),
				OfflineScan: flag.OfflineScanFlag.Clone(),
				Scanners:    flag.ScannersFlag.Clone(),
				DistroFlag:  flag.DistroFlag.Clone(),
			}

			got, err := f.ToOptions(tt.args)
			tt.assertion(t, err)
			assert.Equalf(t, tt.want, got, "ToOptions()")
		})
	}
}

func TestScanFlagGroup_ToOptions_binarySBOM(t *testing.T) {
	// A generator named by the user must be available; one inherited from the default
	// may be skipped with a warning. "explicit" is derived by comparing against the
	// default, so naming exactly the default value counts as non-explicit.
	tests := []struct {
		name         string
		binarySBOM   []string
		want         []string
		wantExplicit bool
		assertion    require.ErrorAssertionFunc
	}{
		{
			name:       "default selection is not explicit",
			binarySBOM: []string{analyzer.BinarySBOMBomBlint},
			want:       []string{analyzer.BinarySBOMBomBlint},
			assertion:  require.NoError,
		},
		{
			name:         "a different generator is explicit",
			binarySBOM:   []string{analyzer.BinarySBOMBinSBOM},
			want:         []string{analyzer.BinarySBOMBinSBOM},
			wantExplicit: true,
			assertion:    require.NoError,
		},
		{
			name:         "both generators are explicit",
			binarySBOM:   []string{analyzer.BinarySBOMBomBlint, analyzer.BinarySBOMBinSBOM},
			want:         []string{analyzer.BinarySBOMBomBlint, analyzer.BinarySBOMBinSBOM},
			wantExplicit: true,
			assertion:    require.NoError,
		},
		{
			name:         "none disables generation",
			binarySBOM:   []string{flag.BinarySBOMNone},
			want:         nil,
			wantExplicit: true,
			assertion:    require.NoError,
		},
		{
			name:         "duplicates are collapsed",
			binarySBOM:   []string{analyzer.BinarySBOMBinSBOM, analyzer.BinarySBOMBinSBOM},
			want:         []string{analyzer.BinarySBOMBinSBOM},
			wantExplicit: true,
			assertion:    require.NoError,
		},
		{
			name:       "none cannot be combined with a generator",
			binarySBOM: []string{flag.BinarySBOMNone, analyzer.BinarySBOMBinSBOM},
			assertion:  require.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(viper.Reset)
			setSliceValue(flag.BinarySBOMFlag.ConfigName, tt.binarySBOM)

			f := &flag.ScanFlagGroup{BinarySBOM: flag.BinarySBOMFlag.Clone()}

			got, err := f.ToOptions(nil)
			tt.assertion(t, err)
			if err != nil {
				return
			}
			assert.Equal(t, tt.want, got.BinarySBOM)
			assert.Equal(t, tt.wantExplicit, got.BinarySBOMExplicit)
		})
	}
}
