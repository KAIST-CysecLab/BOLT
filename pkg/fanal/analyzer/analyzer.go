// Modified by slyfizz on 2025-05-29: added BLint output to SBOM results
// Modified by KimSeoYe on 2025-06-25: implemented BLint executable initialization
// Modified by aney666 on 2025-06-26: Modify AnalyzeFile function to check 'IsEffectiveLayerKey' context value and call IsBinary function if it is effective layer.
// Modified by aney666 on 2025-07-01: Modify AnalyzeFile function to handle filesystem with effective layers.
// Modified by slyfizz on 2025-07-04: replaced temporary paths and basenames in BLint output
// Modified by slyfizz on 2025-09-29: recovered JSON output after BLint diagnostic messages
// Modified by slyfizz on 2026-04-09: added libtree binary dependency analysis
// Modified by slyfizz on 2026-04-28: stored libtree output as an ordered dependency graph
// Modified by slyfizz on 2026-04-30: retained nonempty libtree output after command errors
// Modified by KimSeoYe on 2026-08-06: added bin-sbom as a selectable binary SBOM generator alongside bom-blint
// Modified by KimSeoYe on 2026-08-07: added per-binary generator timeouts and cancellation, and failed on unavailable generators the user named
// Modified by KimSeoYe on 2026-08-07: Record only the direct DT_NEEDED entries read from each
// binary's own ELF header, replacing the libtree subprocess and its resolved dependency tree.
// Modified by slyfizz on 2026-10-13: resolved ELF dependencies recursively within the target filesystem
// Modified by KimSeoYe on 2026-10-26: stopped before scanning when bin-sbom has no component database

package analyzer

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"

	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/samber/lo"
	"golang.org/x/sync/semaphore"
	"golang.org/x/xerrors"

	fos "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os"
	"github.com/aquasecurity/trivy/pkg/fanal/elfdeps"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/utils"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/misconf"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

func mergeBinarySBOMFromJSON(res *AnalysisResult, resourceType, jsonStr, filePath string) {
	// A generator that failed returns no document; recording an empty resource would
	// only make the report writer warn about a malformed fragment.
	if strings.TrimSpace(jsonStr) == "" {
		return
	}
	res.CustomResources = append(res.CustomResources, types.CustomResource{
		Type:     resourceType,
		FilePath: filePath,
		Data:     []byte(jsonStr),
	})
}

var (
	analyzers     = make(map[Type]analyzer)
	postAnalyzers = make(map[Type]postAnalyzerInitialize)

	// ErrUnknownOS occurs when unknown OS is analyzed.
	ErrUnknownOS = xerrors.New("unknown OS")
	// ErrPkgAnalysis occurs when the analysis of packages is failed.
	ErrPkgAnalysis = xerrors.New("failed to analyze packages")
	// ErrNoPkgsDetected occurs when the required files for an OS package manager are not detected
	ErrNoPkgsDetected = xerrors.New("no packages detected")
)

//////////////////////
// Analyzer options //
//////////////////////

// AnalyzerOptions is used to initialize analyzers
type AnalyzerOptions struct {
	Group                Group
	Parallel             int
	FilePatterns         []string
	DisabledAnalyzers    []Type
	DetectionPriority    types.DetectionPriority
	MisconfScannerOption misconf.ScannerOption
	SecretScannerOption  SecretScannerOption
	LicenseScannerOption LicenseScannerOption
}

type SecretScannerOption struct {
	ConfigPath string
}

type LicenseScannerOption struct {
	// Use license classifier to get better results though the classification is expensive.
	Full                      bool
	ClassifierConfidenceLevel float64
}

////////////////
// Interfaces //
////////////////

// Initializer represents analyzers that need to take parameters from users
type Initializer interface {
	Init(AnalyzerOptions) error
}

type analyzer interface {
	Type() Type
	Version() int
	Analyze(ctx context.Context, input AnalysisInput) (*AnalysisResult, error)
	Required(filePath string, info os.FileInfo) bool
}

type PostAnalyzer interface {
	Type() Type
	Version() int
	PostAnalyze(ctx context.Context, input PostAnalysisInput) (*AnalysisResult, error)
	Required(filePath string, info os.FileInfo) bool
}

////////////////////
// Analyzer group //
////////////////////

type Group string

const GroupBuiltin Group = "builtin"

func RegisterAnalyzer(analyzer analyzer) {
	if _, ok := analyzers[analyzer.Type()]; ok {
		log.Fatal("Analyzer is registered twice", log.String("type", string(analyzer.Type())))
	}
	analyzers[analyzer.Type()] = analyzer
}

type postAnalyzerInitialize func(options AnalyzerOptions) (PostAnalyzer, error)

func RegisterPostAnalyzer(t Type, initializer postAnalyzerInitialize) {
	if _, ok := postAnalyzers[t]; ok {
		log.Fatal("Analyzer is registered twice", log.String("type", string(t)))
	}
	postAnalyzers[t] = initializer
}

// DeregisterAnalyzer is mainly for testing
func DeregisterAnalyzer(t Type) {
	delete(analyzers, t)
}

// CustomGroup returns a group name for custom analyzers
// This is mainly intended to be used in Aqua products.
type CustomGroup interface {
	Group() Group
}

type Opener func() (xio.ReadSeekCloserAt, string, error)

type AnalyzerGroup struct {
	logger            *log.Logger
	analyzers         []analyzer
	postAnalyzers     []PostAnalyzer
	filePatterns      map[Type][]*regexp.Regexp
	detectionPriority types.DetectionPriority
}

///////////////////////////
// Analyzer input/output //
///////////////////////////

type AnalysisInput struct {
	Dir      string
	FilePath string
	Info     os.FileInfo
	Content  xio.ReadSeekerAt

	Options AnalysisOptions
}

type PostAnalysisInput struct {
	FS      fs.FS
	Options AnalysisOptions
}

type AnalysisOptions struct {
	Offline      bool
	FileChecksum bool
	ELFResolver  *elfdeps.Resolver
	// Image dependencies are collected once from the final target filesystem.
	SkipELFDependencies bool
}

type AnalysisResult struct {
	m                    sync.Mutex
	OS                   types.OS
	Repository           *types.Repository
	PackageInfos         []types.PackageInfo
	Applications         []types.Application
	Misconfigurations    []types.Misconfiguration
	Secrets              []types.Secret
	Licenses             []types.LicenseFile
	SystemInstalledFiles []string // A list of files installed by OS package manager

	// Digests contains SHA-256 digests of unpackaged files
	// used to search for SBOM attestation.
	Digests map[string]string

	// For Red Hat
	BuildInfo *types.BuildInfo

	// CustomResources hold analysis results from custom analyzers.
	// It is for extensibility and not used in OSS.
	CustomResources []types.CustomResource
}

func NewAnalysisResult() *AnalysisResult {
	result := new(AnalysisResult)
	return result
}

func (r *AnalysisResult) isEmpty() bool {
	return lo.IsEmpty(r.OS) && r.Repository == nil && len(r.PackageInfos) == 0 && len(r.Applications) == 0 &&
		len(r.Misconfigurations) == 0 && len(r.Secrets) == 0 && len(r.Licenses) == 0 && len(r.SystemInstalledFiles) == 0 &&
		r.BuildInfo == nil && len(r.Digests) == 0 && len(r.CustomResources) == 0
}

func (r *AnalysisResult) Sort() {
	// OS packages
	sort.Slice(r.PackageInfos, func(i, j int) bool {
		return r.PackageInfos[i].FilePath < r.PackageInfos[j].FilePath
	})

	for _, pi := range r.PackageInfos {
		sort.Sort(pi.Packages)
	}

	// Language-specific packages
	sort.Slice(r.Applications, func(i, j int) bool {
		if r.Applications[i].FilePath != r.Applications[j].FilePath {
			return r.Applications[i].FilePath < r.Applications[j].FilePath
		}
		return r.Applications[i].Type < r.Applications[j].Type
	})

	for _, app := range r.Applications {
		sort.Sort(app.Packages)
	}

	// Custom resources
	sort.Slice(r.CustomResources, func(i, j int) bool {
		return r.CustomResources[i].FilePath < r.CustomResources[j].FilePath
	})

	// Misconfigurations
	sort.Slice(r.Misconfigurations, func(i, j int) bool {
		if r.Misconfigurations[i].FileType != r.Misconfigurations[j].FileType {
			return r.Misconfigurations[i].FileType < r.Misconfigurations[j].FileType
		} else {
			return r.Misconfigurations[i].FilePath < r.Misconfigurations[j].FilePath
		}
	})

	// Secrets
	sort.Slice(r.Secrets, func(i, j int) bool {
		return r.Secrets[i].FilePath < r.Secrets[j].FilePath
	})
	for _, sec := range r.Secrets {
		sort.Slice(sec.Findings, func(i, j int) bool {
			if sec.Findings[i].RuleID != sec.Findings[j].RuleID {
				return sec.Findings[i].RuleID < sec.Findings[j].RuleID
			}
			return sec.Findings[i].StartLine < sec.Findings[j].StartLine
		})
	}

	// License files
	sort.Slice(r.Licenses, func(i, j int) bool {
		if r.Licenses[i].Type == r.Licenses[j].Type {
			if r.Licenses[i].FilePath == r.Licenses[j].FilePath {
				return r.Licenses[i].Layer.DiffID < r.Licenses[j].Layer.DiffID
			} else {
				return r.Licenses[i].FilePath < r.Licenses[j].FilePath
			}
		}

		return r.Licenses[i].Type < r.Licenses[j].Type
	})
}

func (r *AnalysisResult) Merge(newResult *AnalysisResult) {
	if newResult == nil || newResult.isEmpty() {
		return
	}

	// this struct is accessed by multiple goroutines
	r.m.Lock()
	defer r.m.Unlock()

	r.OS.Merge(newResult.OS)

	if newResult.Repository != nil {
		r.Repository = newResult.Repository
	}

	if len(newResult.PackageInfos) > 0 {
		r.PackageInfos = append(r.PackageInfos, newResult.PackageInfos...)
	}

	if len(newResult.Applications) > 0 {
		r.Applications = append(r.Applications, newResult.Applications...)
	}

	// Merge SHA-256 digests of unpackaged files
	if newResult.Digests != nil {
		r.Digests = lo.Assign(r.Digests, newResult.Digests)
	}

	r.Misconfigurations = append(r.Misconfigurations, newResult.Misconfigurations...)
	r.Secrets = append(r.Secrets, newResult.Secrets...)
	r.Licenses = append(r.Licenses, newResult.Licenses...)
	r.SystemInstalledFiles = append(r.SystemInstalledFiles, newResult.SystemInstalledFiles...)

	if newResult.BuildInfo != nil {
		if r.BuildInfo == nil {
			r.BuildInfo = newResult.BuildInfo
		} else {
			// We don't need to merge build info here
			// because there is theoretically only one file about build info in each layer.
			if newResult.BuildInfo.Nvr != "" || newResult.BuildInfo.Arch != "" {
				r.BuildInfo.Nvr = newResult.BuildInfo.Nvr
				r.BuildInfo.Arch = newResult.BuildInfo.Arch
			}
			if len(newResult.BuildInfo.ContentSets) > 0 {
				r.BuildInfo.ContentSets = newResult.BuildInfo.ContentSets
			}
		}
	}

	r.CustomResources = append(r.CustomResources, newResult.CustomResources...)
}

func belongToGroup(groupName Group, analyzerType Type, disabledAnalyzers []Type, analyzer any) bool {
	if slices.Contains(disabledAnalyzers, analyzerType) {
		return false
	}

	analyzerGroupName := GroupBuiltin
	if cg, ok := analyzer.(CustomGroup); ok {
		analyzerGroupName = cg.Group()
	}
	if analyzerGroupName != groupName {
		return false
	}

	return true
}

const separator = ":"

func NewAnalyzerGroup(opts AnalyzerOptions) (AnalyzerGroup, error) {
	groupName := opts.Group
	if groupName == "" {
		groupName = GroupBuiltin
	}

	group := AnalyzerGroup{
		logger:            log.WithPrefix("analyzer"),
		filePatterns:      make(map[Type][]*regexp.Regexp),
		detectionPriority: opts.DetectionPriority,
	}
	for _, p := range opts.FilePatterns {
		// e.g. "dockerfile:my_dockerfile_*"
		s := strings.SplitN(p, separator, 2)
		if len(s) != 2 {
			return group, xerrors.Errorf("invalid file pattern (%s) expected format: \"fileType:regexPattern\" e.g. \"dockerfile:my_dockerfile_*\"", p)
		}

		fileType, pattern := s[0], s[1]
		r, err := regexp.Compile(pattern)
		if err != nil {
			return group, xerrors.Errorf("invalid file regexp (%s): %w", p, err)
		}

		if _, ok := group.filePatterns[Type(fileType)]; !ok {
			group.filePatterns[Type(fileType)] = []*regexp.Regexp{}
		}

		group.filePatterns[Type(fileType)] = append(group.filePatterns[Type(fileType)], r)
	}

	for analyzerType, a := range analyzers {
		if !belongToGroup(groupName, analyzerType, opts.DisabledAnalyzers, a) {
			continue
		}
		// Initialize only scanners that have Init()
		if ini, ok := a.(Initializer); ok {
			if err := ini.Init(opts); err != nil {
				return AnalyzerGroup{}, xerrors.Errorf("analyzer initialization error: %w", err)
			}
		}
		group.analyzers = append(group.analyzers, a)
	}

	for analyzerType, init := range postAnalyzers {
		a, err := init(opts)
		if err != nil {
			return AnalyzerGroup{}, xerrors.Errorf("post-analyzer init error: %w", err)
		}
		if !belongToGroup(groupName, analyzerType, opts.DisabledAnalyzers, a) {
			continue
		}
		group.postAnalyzers = append(group.postAnalyzers, a)
	}

	return group, nil
}

type Versions struct {
	Analyzers     map[string]int
	PostAnalyzers map[string]int
}

// AnalyzerVersions returns analyzer version identifier used for cache keys.
func (ag AnalyzerGroup) AnalyzerVersions() Versions {
	analyzerVersions := make(map[string]int)
	for _, a := range ag.analyzers {
		analyzerVersions[string(a.Type())] = a.Version()
	}
	postAnalyzerVersions := make(map[string]int)
	for _, a := range ag.postAnalyzers {
		postAnalyzerVersions[string(a.Type())] = a.Version()
	}
	return Versions{
		Analyzers:     analyzerVersions,
		PostAnalyzers: postAnalyzerVersions,
	}
}

// Binary SBOM generators run against files detected as binaries.
// Which ones run is selected with --binary-sbom.
const (
	BinarySBOMBomBlint = "bom-blint"
	BinarySBOMBinSBOM  = "bin-sbom"
)

// binarySBOMWaitDelay bounds how long cmd.Wait may block after the context is
// cancelled. Without it, a helper process that survived cancellation and still holds
// the output pipes would keep the scan waiting indefinitely.
const binarySBOMWaitDelay = 10 * time.Second

type binarySBOMEngine struct {
	name string
	// resourceType tags the emitted CustomResource so the report writer knows which
	// generator produced the fragment.
	resourceType string
	path         string
	// args builds the command line. target is the path actually analyzed; display is
	// where the file lives in the scanned artifact, which differs from target when the
	// file was extracted from an image layer.
	args func(target, display string) []string
	// combineOutput folds stderr into the parsed output. bom-blint writes diagnostics
	// there that postProcess strips, while bin-sbom keeps a progress log on stderr
	// that must not be mixed into the JSON.
	combineOutput bool
	postProcess   func(out string) string
}

var (
	enabledBinarySBOMEngines []binarySBOMEngine
	// binarySBOMTimeout caps one generator run against one binary. Zero leaves the
	// scan's own deadline as the only limit.
	binarySBOMTimeout time.Duration
)

// SetBinarySBOMTimeout sets the per-binary limit from --binary-sbom-timeout.
func SetBinarySBOMTimeout(d time.Duration) {
	binarySBOMTimeout = d
}

// InitBinarySBOMEngines resolves the executables for the selected generators.
//
// When strict is false a generator that cannot be found is reported and skipped, so a
// missing optional tool does not block the rest of the analysis. When the user named
// the generators (strict), an unavailable one is an error instead: silently producing
// an SBOM without the requested data looks identical to a successful scan.
func InitBinarySBOMEngines(selected []string, strict bool) error {
	enabledBinarySBOMEngines = nil

	unavailable := func(name string, err error) error {
		if strict {
			return xerrors.Errorf(
				"%s was requested but is unavailable; install it or pass --binary-sbom to"+
					" select a different generator: %w", name, err)
		}
		log.Warn(name+" not found; skipping it", log.Err(err))
		return nil
	}

	for _, name := range selected {
		var engine binarySBOMEngine

		switch name {
		case BinarySBOMBomBlint:
			path, err := lookupBinarySBOMTool("BOMBLINT_PATH", "bom_blint", "bom-blint")
			if err != nil {
				if err := unavailable(BinarySBOMBomBlint, err); err != nil {
					return err
				}
				continue
			}
			engine = binarySBOMEngine{
				name:         BinarySBOMBomBlint,
				resourceType: types.CustomResourceCycloneDXBomBlint,
				path:         path,
				args: func(target, _ string) []string {
					return []string{"--no-banner", "--no-reviews", "sbom", "--stdout", "-i", target}
				},
				combineOutput: true,
				postProcess:   stripBomBlintDiagnostics,
			}
		case BinarySBOMBinSBOM:
			path, err := lookupBinarySBOMTool("BIN_SBOM_PATH", "bin-sbom")
			if err != nil {
				if err := unavailable(BinarySBOMBinSBOM, err); err != nil {
					return err
				}
				continue
			}
			// No component database is distributed with BOLT. Without one, bin-sbom
			// fails on every binary and the scan would finish with no binary SBOM data
			// at all, so stop before scanning.
			if err := checkBinSBOMData(os.Getenv("BIN_SBOM_DB")); err != nil {
				log.Warn("bin-sbom has no component database; build one as described in the README, " +
					"or pass --binary-sbom bom-blint to scan without bin-sbom")
				return xerrors.Errorf("bin-sbom component database unavailable: %w", err)
			}
			engine = binarySBOMEngine{
				name:         BinarySBOMBinSBOM,
				resourceType: types.CustomResourceCycloneDXBinSBOM,
				path:         path,
				args: func(target, display string) []string {
					return []string{
						"--no-banner", "sbom", "--stdout", "-i", target,
						"--display-path", display,
					}
				},
			}
		default:
			return fmt.Errorf("unknown binary SBOM generator: %s", name)
		}

		log.Debug("binary SBOM generator enabled",
			log.String("generator", engine.name), log.String("path", engine.path))
		enabledBinarySBOMEngines = append(enabledBinarySBOMEngines, engine)
	}
	return nil
}

// binSBOMComponentDBEntries are the parts of database/componentDB that bin-sbom
// requires; keep in sync with COMPONENT_DB_ENTRIES in Binary_SBOM_Generator/src/cli.py.
var binSBOMComponentDBEntries = []string{
	"components.json", "functions.json", "strings", "symbols", "control_blocks", "call_graph",
}

// checkBinSBOMData reports whether root (the $BIN_SBOM_DB directory) holds a
// component database bin-sbom can use. It mirrors bin-sbom's own validation, which
// otherwise only runs per binary, once the scan is already under way.
func checkBinSBOMData(root string) error {
	if root == "" {
		return xerrors.New("BIN_SBOM_DB is not set")
	}
	componentDB := filepath.Join(root, "database", "componentDB")
	var missing []string
	for _, entry := range binSBOMComponentDBEntries {
		if _, err := os.Stat(filepath.Join(componentDB, entry)); err != nil {
			missing = append(missing, entry)
		}
	}
	if len(missing) > 0 {
		return xerrors.Errorf("%s is missing %s", componentDB, strings.Join(missing, ", "))
	}
	repoMeta := filepath.Join(root, "osscollector", "repo_meta")
	if matches, _ := filepath.Glob(filepath.Join(repoMeta, "*.txt")); len(matches) == 0 {
		return xerrors.Errorf("%s has no component metadata", repoMeta)
	}
	return nil
}

// lookupBinarySBOMTool resolves a generator executable: an explicit path from envVar
// first, then $PATH, then alongside the bolt executable.
func lookupBinarySBOMTool(envVar string, names ...string) (string, error) {
	if p := os.Getenv(envVar); p != "" {
		return p, nil
	}

	for _, name := range names {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}

	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("cannot find executable (bolt): %w", err)
	}
	for _, name := range names {
		cand := filepath.Join(filepath.Dir(exe), name)
		if info, err := os.Stat(cand); err == nil && info.Mode().IsRegular() {
			return cand, nil
		}
	}
	return "", fmt.Errorf("cannot find %s; set %s or put it on PATH", names[0], envVar)
}

// getBinarySBOMInfo runs one generator against one binary. A generator that cannot
// handle the file is not a scan failure, so this returns an empty document rather than
// an error; the caller records nothing for that binary and moves on.
func getBinarySBOMInfo(ctx context.Context, engine binarySBOMEngine, tempPath string, filePath string) string {
	target := filePath // fs
	if tempPath != "" {
		target = tempPath // image: analyze the copy extracted from the layer
	}

	// Cap this run so one large binary cannot spend the whole scan's budget; without a
	// cap a single 15MB library can starve every file after it.
	if binarySBOMTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, binarySBOMTimeout)
		defer cancel()
	}

	// CommandContext so a cancelled or timed-out scan takes the generator down with
	// it. Decompilation-based generators can run for minutes, and with exec.Command
	// they would keep going after the scan gave up.
	cmd := exec.CommandContext(ctx, engine.path, engine.args(target, filePath)...)
	isolateProcessGroup(cmd)
	cmd.WaitDelay = binarySBOMWaitDelay
	log.Debug("[analyzer] binary SBOM command", log.String("generator", engine.name),
		log.String("cmd", cmd.String()), log.FilePath(filePath))
	cmd.Env = os.Environ()

	var stderr bytes.Buffer
	var output []byte
	var err error
	if engine.combineOutput {
		output, err = cmd.CombinedOutput()
	} else {
		cmd.Stderr = &stderr
		output, err = cmd.Output()
	}
	if err != nil {
		// Warn rather than Debug: the scan still succeeds, and without this the only
		// sign that a generator produced nothing is its absence from the SBOM.
		msg := "Binary SBOM generator failed; no data recorded for this file"
		if binarySBOMTimeout > 0 && errors.Is(ctx.Err(), context.DeadlineExceeded) {
			msg = "Binary SBOM generator exceeded --binary-sbom-timeout; skipping this file"
		}
		log.Warn(msg,
			log.String("generator", engine.name), log.FilePath(filePath),
			log.Err(err), log.String("stderr", strings.TrimSpace(stderr.String())))
		return ""
	}

	outputStr := string(output)
	if engine.postProcess != nil {
		outputStr = engine.postProcess(outputStr)
	}
	return replaceTempPath(outputStr, tempPath, filePath)
}

// stripBomBlintDiagnostics drops the diagnostics bom-blint prints ahead of the
// document when it hits a recoverable error.
func stripBomBlintDiagnostics(out string) string {
	firstNL := strings.IndexByte(out, '\n')
	if firstNL == -1 {
		firstNL = len(out)
	}

	firstLine := strings.TrimSpace(out[:firstNL])
	if !strings.Contains(firstLine, "ERROR") && !strings.HasPrefix(firstLine, "[ERROR") {
		return out
	}

	// Skip to the start of the JSON document: '{' if present, otherwise '['.
	start := strings.IndexByte(out, '{')
	if start < 0 {
		start = strings.IndexByte(out, '[')
	}
	if start < 0 {
		return out
	}
	return strings.TrimSpace(out[start:])
}

// replaceTempPath rewrites references to the extraction path so the fragment names
// the file by its location in the scanned artifact.
func replaceTempPath(out, tempPath, filePath string) string {
	// filepath.Base("") is ".", so without this guard an fs scan would replace every
	// "." in the document and splice filePath between every character.
	if tempPath == "" {
		return out
	}
	baseTempPath := filepath.Base(tempPath)
	if !strings.Contains(out, baseTempPath) {
		return out
	}
	out = strings.ReplaceAll(out, tempPath, filePath)
	return strings.ReplaceAll(out, baseTempPath, filepath.Base(filePath))
}

// directNeededLibraries returns the DT_NEEDED entries of one ELF binary: the sonames
// the file itself declares it links against.
//
// Only the direct entries are reported, and they are deliberately not resolved to files
// on disk. Resolving a soname means searching a root filesystem, and the only copy of
// the file available here is one extracted out of the scanned artifact into BOLT's own
// container. A search would therefore run against BOLT's libraries and attribute BOLT's
// dependency tree to the scanned image -- silently wrong data, and wrong in a way that
// grows with depth. DT_NEEDED is stored inside the binary, so reading it needs no
// filesystem context and is correct wherever the file happens to sit.
//
// A file this cannot parse is not a scan failure: the caller records nothing for it.
func directNeededLibraries(tempPath, filePath string) []string {
	targetPath := filePath
	if tempPath != "" {
		targetPath = tempPath
	}

	f, err := elf.Open(targetPath)
	if err != nil {
		// IsBinary passes anything non-text through, so non-ELF files reach this and
		// are expected; Debug rather than Warn.
		log.Debug("not a readable ELF file; no runtime dependencies recorded",
			log.FilePath(filePath), log.Err(err))
		return nil
	}
	defer f.Close()

	libs, err := f.ImportedLibraries()
	if err != nil {
		log.Debug("failed to read DT_NEEDED entries", log.FilePath(filePath), log.Err(err))
		return nil
	}
	return libs
}

type libtreeGraphNode struct {
	Name      string   `json:"name"`
	DependsOn []string `json:"dependsOn"`
}

// mergeDirectNeeded records one binary's direct dependencies as a CustomResource.
//
// The resource type stays "libtree" and the graph keeps its previous shape -- root node
// first, then one node per dependency -- because pkg/report/cyclonedx reads graph[0] as
// the root and emits a component per node. Only the contents changed: the dependency
// nodes now have no children of their own, since each edge is one the binary declares.
func mergeDirectNeeded(res *AnalysisResult, needed []string, filePath string) {
	graph := directNeededGraph(needed, filePath)
	if len(graph) == 0 {
		return
	}

	raw, err := json.Marshal(graph)
	if err != nil {
		log.Debug("failed to marshal dependency graph", log.Err(err), log.FilePath(filePath))
		return
	}

	res.CustomResources = append(res.CustomResources, types.CustomResource{
		Type:     "libtree",
		FilePath: filePath,
		Data:     raw,
	})
}

// directNeededGraph builds the node list for one binary and the sonames it needs.
//
// Nothing is emitted for a binary with no DT_NEEDED entries -- a static one, typically.
// A lone root with no edges would add a component to the SBOM without stating any
// relationship, and every file in an effective layer would contribute one.
func directNeededGraph(needed []string, filePath string) []libtreeGraphNode {
	root := filepath.Base(filePath)
	if root == "" || root == "." || root == string(filepath.Separator) {
		return nil
	}

	// DT_NEEDED usually holds a bare soname but is allowed to hold a path, so reduce
	// both to the name the ground truth and the CycloneDX refs use.
	deps := make([]string, 0, len(needed))
	seen := map[string]struct{}{}
	for _, name := range needed {
		name = filepath.Base(strings.TrimSpace(name))
		if name == "" || name == "." || name == root {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		deps = append(deps, name)
	}
	if len(deps) == 0 {
		return nil
	}

	graph := make([]libtreeGraphNode, 0, len(deps)+1)
	graph = append(graph, libtreeGraphNode{Name: root, DependsOn: deps})
	for _, name := range deps {
		graph = append(graph, libtreeGraphNode{Name: name, DependsOn: []string{}})
	}
	return graph
}

// binarySBOMTargetPath returns the path to hand the binary SBOM generators, or ""
// when the file should not be analyzed. For image scans the extracted copy lives at
// tmpPath and filePath names it; for filesystem scans the opener must be backed by a
// real file, since the generators take a path rather than a stream.
func binarySBOMTargetPath(rc xio.ReadSeekCloserAt, isBin bool, tmpPath, filePath string) string {
	if !isBin {
		return ""
	}
	if tmpPath != "" {
		return filePath
	}
	f, ok := rc.(*os.File)
	if !ok {
		return ""
	}
	absPath, err := filepath.Abs(f.Name())
	if err != nil {
		return ""
	}
	return absPath
}

// AnalyzeFile determines which files are required by the analyzers based on the file name and attributes,
// and passes only those files to the analyzer for analysis.
// This function may be called concurrently and must be thread-safe.
func (ag AnalyzerGroup) AnalyzeFile(ctx context.Context, wg *sync.WaitGroup, limit *semaphore.Weighted, result *AnalysisResult,
	dir, filePath string, info os.FileInfo, opener Opener, disabled []Type, opts AnalysisOptions) error {
	if info.IsDir() {
		log.Debug("Is Directory!!", log.String("path", "nope"))
		return nil
	}

	// The error must be checked before deferring Close: a failed opener returns a nil
	// reader, and deferring on it panics.
	rc, tmp_path, err := opener()
	if errors.Is(err, fs.ErrPermission) {
		ag.logger.Debug("Permission error", log.FilePath(filePath))
		return nil
	}
	if err != nil {
		return xerrors.Errorf("unable to open %s: %w", filePath, err)
	}
	defer rc.Close()

	fileSize := info.Size()
	if fileSize <= 0 {
		return nil
	}

	var isBin bool

	val := ctx.Value(IsEffectiveLayerKey)
	isEffectiveLayer, _ := val.(bool)

	if tmp_path != "" && !isEffectiveLayer {
		log.Debug("[SEOYE] Not Effective layer: pass the binary analysis")
		isBin = false
	} else if tmp_path == "" || (tmp_path != "" && isEffectiveLayer) {
		// fs or effective layer in image
		isBin, err = utils.IsBinary(rc, fileSize)
		if err != nil {
			return xerrors.Errorf("failed to check if file is binary %s: %w", filePath, err)
		}
	}

	if binPath := binarySBOMTargetPath(rc, isBin, tmp_path, filePath); binPath != "" {
		log.Debug("opened path", log.String("path", binPath))

		// A generator failing on one file must not fail the scan: these are auxiliary
		// enrichment, and a decompiler giving up on an unusual binary is expected.
		// Availability is enforced once up front instead (InitBinarySBOMEngines).
		for _, engine := range enabledBinarySBOMEngines {
			sbomJSON := getBinarySBOMInfo(ctx, engine, tmp_path, binPath)
			mergeBinarySBOMFromJSON(result, engine.resourceType, sbomJSON, filePath)
		}

		if opts.ELFResolver == nil && !opts.SkipELFDependencies {
			mergeDirectNeeded(result, directNeededLibraries(tmp_path, binPath), filePath)
		}
	}

	// Filesystem scans resolve from their explicitly selected root. Image scans
	// collect roots separately under the effective-user-layer policy, while
	// using the complete image filesystem to find those roots' dependencies.
	var elfMagic [4]byte
	if opts.ELFResolver != nil && !opts.SkipELFDependencies {
		_, _ = rc.ReadAt(elfMagic[:], 0)
	}
	if opts.ELFResolver != nil && !opts.SkipELFDependencies && string(elfMagic[:]) == "\x7fELF" {
		if err := AnalyzeELFDependencies(ctx, result, opts.ELFResolver, filePath); err != nil {
			return err
		}
	}

	// filepath extracted from tar file doesn't have the prefix "/"
	cleanPath := strings.TrimLeft(filePath, "/")

	for _, a := range ag.analyzers {
		// Skip disabled analyzers
		if slices.Contains(disabled, a.Type()) {
			continue
		}

		if !ag.filePatternMatch(a.Type(), cleanPath) && !a.Required(cleanPath, info) {
			continue
		}
		rc, _, err := opener()
		if errors.Is(err, fs.ErrPermission) {
			ag.logger.Debug("Permission error", log.FilePath(filePath))
			break
		} else if err != nil {
			return xerrors.Errorf("unable to open %s: %w", filePath, err)
		}

		if err = limit.Acquire(ctx, 1); err != nil {
			return xerrors.Errorf("semaphore acquire: %w", err)
		}
		wg.Add(1)

		go func(a analyzer, rc xio.ReadSeekCloserAt) {
			defer limit.Release(1)
			defer wg.Done()
			defer rc.Close()

			ret, err := a.Analyze(ctx, AnalysisInput{
				Dir:      dir,
				FilePath: filePath,
				Info:     info,
				Content:  rc,
				Options:  opts,
			})
			if err != nil && !errors.Is(err, fos.AnalyzeOSError) {
				ag.logger.Debug("Analysis error", log.Err(err))
				return
			}
			result.Merge(ret)
		}(a, rc)
	}

	return nil
}

// RequiredPostAnalyzers returns a list of analyzer types that require the given file.
func (ag AnalyzerGroup) RequiredPostAnalyzers(filePath string, info os.FileInfo) []Type {
	if info.IsDir() {
		return nil
	}
	var postAnalyzerTypes []Type
	for _, a := range ag.postAnalyzers {
		if ag.filePatternMatch(a.Type(), filePath) || a.Required(filePath, info) {
			postAnalyzerTypes = append(postAnalyzerTypes, a.Type())
		}
	}
	return postAnalyzerTypes
}

// PostAnalyze passes a virtual filesystem containing only required files
// and passes it to the respective post-analyzer.
// The obtained results are merged into the "result".
// This function may be called concurrently and must be thread-safe.
func (ag AnalyzerGroup) PostAnalyze(ctx context.Context, compositeFS *CompositeFS, result *AnalysisResult, opts AnalysisOptions) error {
	for _, a := range ag.postAnalyzers {
		fsys, ok := compositeFS.Get(a.Type())
		if !ok {
			continue
		}

		skippedFiles := result.SystemInstalledFiles
		if ag.detectionPriority == types.PriorityComprehensive {
			// If the detection priority is comprehensive, system files installed by the OS package manager will not be skipped.
			// It can lead to false positives and duplicates, but it may be necessary to detect all possible vulnerabilities.
			skippedFiles = nil
		}
		for _, app := range result.Applications {
			skippedFiles = append(skippedFiles, app.FilePath)
			for _, pkg := range app.Packages {
				// The analysis result could contain packages listed in SBOM.
				// The files of those packages don't have to be analyzed.
				// This is especially helpful for expensive post-analyzers such as the JAR analyzer.
				if pkg.FilePath != "" {
					skippedFiles = append(skippedFiles, pkg.FilePath)
				}
			}
		}

		filteredFS, err := fsys.Filter(skippedFiles)
		if err != nil {
			return xerrors.Errorf("unable to filter filesystem: %w", err)
		}

		res, err := a.PostAnalyze(ctx, PostAnalysisInput{
			FS:      filteredFS,
			Options: opts,
		})
		if err != nil {
			return xerrors.Errorf("post analysis error: %w", err)
		}
		result.Merge(res)
	}
	return nil
}

// PostAnalyzerFS returns a composite filesystem that contains multiple filesystems for each post-analyzer
func (ag AnalyzerGroup) PostAnalyzerFS() (*CompositeFS, error) {
	return NewCompositeFS()
}

func (ag AnalyzerGroup) filePatternMatch(analyzerType Type, filePath string) bool {
	for _, pattern := range ag.filePatterns[analyzerType] {
		if pattern.MatchString(filePath) {
			return true
		}
	}
	return false
}
