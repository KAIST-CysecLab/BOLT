// Modified by KimSeoYe on 2026-08-06: added the --binary-sbom flag
// Modified by KimSeoYe on 2026-08-07: added --binary-sbom-timeout and recorded whether generators were named explicitly
// Modified by KimSeoYe on 2026-10-13: made bin-sbom the default binary SBOM generator
// Modified by KimSeoYe on 2026-10-29: made bom-blint the default again, since bin-sbom needs a user-built database

package flag

import (
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
	xstrings "github.com/aquasecurity/trivy/pkg/x/strings"
)

var (
	SkipDirsFlag = Flag[[]string]{
		Name:       "skip-dirs",
		ConfigName: "scan.skip-dirs",
		Usage:      "specify the directories or glob patterns to skip",
	}
	SkipFilesFlag = Flag[[]string]{
		Name:       "skip-files",
		ConfigName: "scan.skip-files",
		Default:    []string{},
		Usage:      "specify the files or glob patterns to skip",
	}
	OfflineScanFlag = Flag[bool]{
		Name:       "offline-scan",
		ConfigName: "scan.offline",
		Usage:      "do not issue API requests to identify dependencies",
	}
	ScannersFlag = Flag[[]string]{
		Name:       "scanners",
		ConfigName: "scan.scanners",
		Default: xstrings.ToStringSlice(types.Scanners{
			types.VulnerabilityScanner,
			types.SecretScanner,
		}),
		Values: xstrings.ToStringSlice(types.Scanners{
			types.VulnerabilityScanner,
			types.MisconfigScanner,
			types.SecretScanner,
			types.LicenseScanner,
		}),
		ValueNormalize: func(ss []string) []string {
			return lo.Map(ss, func(s string, _ int) string {
				switch s {
				case "vulnerability":
					return string(types.VulnerabilityScanner)
				case "misconf", "misconfiguration":
					return string(types.MisconfigScanner)
				case "config":
					log.Warn("'--scanners config' is deprecated. Use '--scanners misconfig' instead. See https://github.com/aquasecurity/trivy/discussions/5586 for the detail.")
					return string(types.MisconfigScanner)
				}
				return s
			})
		},
		Aliases: []Alias{
			{
				Name:       "security-checks",
				ConfigName: "scan.security-checks",
				Deprecated: true, // --security-checks was renamed to --scanners
			},
		},
		Usage: "comma-separated list of what security issues to detect",
	}
	FilePatternsFlag = Flag[[]string]{
		Name:       "file-patterns",
		ConfigName: "scan.file-patterns",
		Usage:      "specify config file patterns",
	}
	SlowFlag = Flag[bool]{
		Name:       "slow",
		ConfigName: "scan.slow",
		Default:    false,
		Usage:      "scan over time with lower CPU and memory utilization",
		Deprecated: `Use "--parallel 1" instead.`,
	}
	ParallelFlag = Flag[int]{
		Name:       "parallel",
		ConfigName: "scan.parallel",
		Default:    5,
		Usage:      "number of goroutines enabled for parallel scanning, set 0 to auto-detect parallelism",
	}
	SBOMSourcesFlag = Flag[[]string]{
		Name:       "sbom-sources",
		ConfigName: "scan.sbom-sources",
		Values: []string{
			"oci",
			"rekor",
		},
		Usage: "[EXPERIMENTAL] try to retrieve SBOM from the specified sources",
	}
	RekorURLFlag = Flag[string]{
		Name:       "rekor-url",
		ConfigName: "scan.rekor-url",
		Default:    "https://rekor.sigstore.dev",
		Usage:      "[EXPERIMENTAL] address of rekor STL server",
	}
	DetectionPriority = Flag[string]{
		Name:       "detection-priority",
		ConfigName: "scan.detection-priority",
		Default:    string(ftypes.PriorityPrecise),
		Values: xstrings.ToStringSlice([]ftypes.DetectionPriority{
			ftypes.PriorityPrecise,
			ftypes.PriorityComprehensive,
		}),
		Usage: `specify the detection priority:
  - "precise": Prioritizes precise by minimizing false positives.
  - "comprehensive": Aims to detect more security findings at the cost of potential false positives.
`,
	}
	DistroFlag = Flag[string]{
		Name:       "distro",
		ConfigName: "scan.distro",
		Usage:      "[EXPERIMENTAL] specify a distribution, <family>/<version>",
	}
	BinarySBOMFlag = Flag[[]string]{
		Name:       "binary-sbom",
		ConfigName: "scan.binary-sbom",
		// bom-blint needs nothing beyond the image. bin-sbom needs a component database
		// that users build themselves, so it is opt-in.
		Default: []string{analyzer.BinarySBOMBomBlint},
		Values: []string{
			analyzer.BinarySBOMBomBlint,
			analyzer.BinarySBOMBinSBOM,
			BinarySBOMNone,
		},
		Usage: `[EXPERIMENTAL] comma-separated SBOM generators to run against detected binaries:
  - "bom-blint" (default): fast static analysis of the binary itself
  - "bin-sbom": OSS component detection via decompilation; requires a component database you build first ($BIN_SBOM_DB)
  - "none": skip binary SBOM generation
`,
	}
	BinarySBOMTimeoutFlag = Flag[time.Duration]{
		Name:       "binary-sbom-timeout",
		ConfigName: "scan.binary-sbom-timeout",
		Usage: "[EXPERIMENTAL] per-binary time limit for a binary SBOM generator; " +
			"a file that exceeds it is skipped with a warning (0 disables the limit)",
	}
)

// BinarySBOMNone disables binary SBOM generation. The generator names themselves are
// defined by the analyzer package, which owns the implementations.
const BinarySBOMNone = "none"

type ScanFlagGroup struct {
	SkipDirs          *Flag[[]string]
	SkipFiles         *Flag[[]string]
	OfflineScan       *Flag[bool]
	Scanners          *Flag[[]string]
	FilePatterns      *Flag[[]string]
	Slow              *Flag[bool] // deprecated
	Parallel          *Flag[int]
	SBOMSources       *Flag[[]string]
	RekorURL          *Flag[string]
	DetectionPriority *Flag[string]
	DistroFlag        *Flag[string]
	BinarySBOM        *Flag[[]string]
	BinarySBOMTimeout *Flag[time.Duration]
}

type ScanOptions struct {
	Target            string
	SkipDirs          []string
	SkipFiles         []string
	OfflineScan       bool
	Scanners          types.Scanners
	FilePatterns      []string
	Parallel          int
	SBOMSources       []string
	RekorURL          string
	DetectionPriority ftypes.DetectionPriority
	Distro            ftypes.OS
	// BinarySBOM lists the binary SBOM generators to run. Empty means none.
	BinarySBOM []string
	// BinarySBOMExplicit records that the user named the generators, in which case an
	// unavailable one is an error rather than something to skip.
	BinarySBOMExplicit bool
	// BinarySBOMTimeout caps how long a generator may spend on one binary. Zero means
	// the only limit is the scan's own deadline.
	BinarySBOMTimeout time.Duration
}

func NewScanFlagGroup() *ScanFlagGroup {
	return &ScanFlagGroup{
		SkipDirs:          SkipDirsFlag.Clone(),
		SkipFiles:         SkipFilesFlag.Clone(),
		OfflineScan:       OfflineScanFlag.Clone(),
		Scanners:          ScannersFlag.Clone(),
		FilePatterns:      FilePatternsFlag.Clone(),
		Parallel:          ParallelFlag.Clone(),
		SBOMSources:       SBOMSourcesFlag.Clone(),
		RekorURL:          RekorURLFlag.Clone(),
		Slow:              SlowFlag.Clone(),
		DetectionPriority: DetectionPriority.Clone(),
		DistroFlag:        DistroFlag.Clone(),
		BinarySBOM:        BinarySBOMFlag.Clone(),
		BinarySBOMTimeout: BinarySBOMTimeoutFlag.Clone(),
	}
}

func (f *ScanFlagGroup) Name() string {
	return "Scan"
}

func (f *ScanFlagGroup) Flags() []Flagger {
	return []Flagger{
		f.SkipDirs,
		f.SkipFiles,
		f.OfflineScan,
		f.Scanners,
		f.FilePatterns,
		f.Slow,
		f.Parallel,
		f.SBOMSources,
		f.RekorURL,
		f.DetectionPriority,
		f.DistroFlag,
		f.BinarySBOM,
		f.BinarySBOMTimeout,
	}
}

func (f *ScanFlagGroup) ToOptions(args []string) (ScanOptions, error) {
	if err := parseFlags(f); err != nil {
		return ScanOptions{}, err
	}

	var target string
	if len(args) == 1 {
		target = args[0]
	}

	parallel := f.Parallel.Value()
	if f.Parallel != nil && parallel == 0 {
		log.Info("Set '--parallel' to the number of CPUs", log.Int("parallel", runtime.NumCPU()))
		parallel = runtime.NumCPU()
	}

	binarySBOM, binarySBOMExplicit, err := parseBinarySBOM(f.BinarySBOM)
	if err != nil {
		return ScanOptions{}, err
	}

	var distro ftypes.OS
	if f.DistroFlag != nil && f.DistroFlag.Value() != "" {
		family, version, _ := strings.Cut(f.DistroFlag.Value(), "/")
		if !slices.Contains(ftypes.OSTypes, ftypes.OSType(family)) {
			return ScanOptions{}, xerrors.Errorf("unknown OS family: %s, must be %q", family, ftypes.OSTypes)
		}
		distro = ftypes.OS{
			Family: ftypes.OSType(family),
			Name:   version,
		}
	}

	return ScanOptions{
		Target:            target,
		SkipDirs:          f.SkipDirs.Value(),
		SkipFiles:         f.SkipFiles.Value(),
		OfflineScan:       f.OfflineScan.Value(),
		Scanners:          xstrings.ToTSlice[types.Scanner](f.Scanners.Value()),
		FilePatterns:      f.FilePatterns.Value(),
		Parallel:          parallel,
		SBOMSources:       f.SBOMSources.Value(),
		RekorURL:          f.RekorURL.Value(),
		DetectionPriority: ftypes.DetectionPriority(f.DetectionPriority.Value()),
		Distro:            distro,

		BinarySBOM:         binarySBOM,
		BinarySBOMExplicit: binarySBOMExplicit,
		BinarySBOMTimeout:  f.BinarySBOMTimeout.Value(),
	}, nil
}

// parseBinarySBOM normalizes --binary-sbom into the list of generators to run and
// reports whether the selection came from the user rather than the default.
// "none" disables binary SBOM generation and cannot be combined with a generator.
func parseBinarySBOM(f *Flag[[]string]) ([]string, bool, error) {
	if f == nil {
		return nil, false, nil
	}
	values := lo.Uniq(f.Value())

	// A generator the user asked for by name must not be skipped silently, whereas
	// the default selection stays tolerant of a generator that is not installed.
	explicit := !slices.Equal(values, lo.Uniq(f.Default))

	if len(values) == 0 {
		return nil, explicit, nil
	}
	if slices.Contains(values, BinarySBOMNone) {
		if len(values) > 1 {
			return nil, false, xerrors.Errorf(
				`invalid argument for "--%s" flag: %q cannot be combined with other generators`,
				BinarySBOMFlag.Name, BinarySBOMNone)
		}
		return nil, explicit, nil
	}
	return values, explicit, nil
}
