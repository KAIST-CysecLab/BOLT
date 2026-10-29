package opam

import (
    "bufio"
    "bytes"
    "context"
    "os"
    "os/exec"
    "strings"
    "fmt"

    "github.com/aquasecurity/trivy/pkg/fanal/analyzer"
    ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
    analyzer.RegisterAnalyzer(&opamAnalyzer{})
}

type opamAnalyzer struct{}

// Analyze runs `opam list` and packs the result into AnalysisResult.PackageInfos.
func (a opamAnalyzer) Analyze(ctx context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
    // 1. Run opam list
    fmt.Println("🛠️  opamAnalyzer running...")
    cmd := exec.Command("opam", "list", "--installed", "--columns=name,version", "--short")
    output, err := cmd.Output()
    if err != nil {
        return nil, err
    }

    // 2. Parse the output
    scanner := bufio.NewScanner(bytes.NewReader(output))
    var pkgs []ftypes.Package
    for scanner.Scan() {
        parts := strings.Fields(scanner.Text())
        if len(parts) >= 2 {
            pkgs = append(pkgs, ftypes.Package{
                Name:    parts[0],
                Version: parts[1],
            })
        }
    }

    // 3. Wrap the packages as ftypes.PackageInfo in the AnalysisResult
    res := analyzer.AnalysisResult{}
    res.PackageInfos = []ftypes.PackageInfo{
        {
            FilePath: input.FilePath,
            Packages: pkgs,
        },
    }
    return &res, nil
}

// Required always returns true, so Analyze is called whether or not any file matches.
func (a opamAnalyzer) Required(_ string, fileInfo os.FileInfo) bool {
    return fileInfo.Name() == ".opam" || fileInfo.Name() == "dune-project"
}
func (a opamAnalyzer) Type() analyzer.Type {
    return analyzer.Type("opam")
}

func (a opamAnalyzer) Version() int {
    return 1
}
