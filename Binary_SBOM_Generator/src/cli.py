"""bin-sbom: generate a CycloneDX SBOM for a single binary.

The upstream pipeline (``bin_preprocessor.py`` -> ``detector.py`` ->
``cyclonedx_sbom_gen.py``) is driven by module-level constants anchored at
``os.getcwd()`` and expects its targets to live in ``testset/bin``.  Rather than
rewrite those scripts, this CLI builds a throwaway staging directory that has the
layout they expect, drops the single requested binary into it, and runs them there
with ``cwd`` set to the staging root.  The resulting CycloneDX document is written
to stdout so that callers such as bolt can consume it directly.

The component database is *not* built here; it must be prepared beforehand with
``OSScollector.py`` and ``preprocessor.py`` and pointed at via ``--db`` or the
``BIN_SBOM_DB`` environment variable.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Optional

# Directory holding the pipeline scripts. In the repo this is ``src``; in an
# installed wheel it is the ``bin_sbom`` package directory.
PKG_DIR = Path(__file__).resolve().parent

GHIDRA_DIRNAME = "ghidra_11.2.1_PUBLIC"

# Mirrors detector.has_componentdb_layout(); checked up front so a missing
# database fails with a clear message instead of an empty SBOM.
COMPONENT_DB_ENTRIES = [
    "components.json",
    "functions.json",
    "strings",
    "symbols",
    "control_blocks",
    "call_graph",
]

EXIT_BAD_USAGE = 2
EXIT_MISSING_DB = 3
EXIT_PIPELINE_FAILED = 4


class BinSbomError(Exception):
    """Fatal condition that should be reported to the caller on stderr."""

    def __init__(self, message: str, code: int = EXIT_PIPELINE_FAILED):
        super().__init__(message)
        self.code = code


def log(message: str) -> None:
    print(message, file=sys.stderr)


# --------------------------- input resolution ---------------------------


def resolve_data_dirs(args: argparse.Namespace) -> tuple[Path, Path]:
    """Locate the prebuilt ``database`` and ``repo_meta`` directories.

    Precedence: explicit per-directory flags > --db / $BIN_SBOM_DB root > error.
    """
    root: Optional[Path] = None
    if args.db:
        root = Path(args.db).expanduser()
    elif os.environ.get("BIN_SBOM_DB"):
        root = Path(os.environ["BIN_SBOM_DB"]).expanduser()

    if args.database:
        database = Path(args.database).expanduser()
    elif root is not None:
        database = root / "database"
    else:
        raise BinSbomError(
            "no component database configured; pass --db/--database or set BIN_SBOM_DB",
            EXIT_MISSING_DB,
        )

    if args.repo_meta:
        repo_meta = Path(args.repo_meta).expanduser()
    elif root is not None:
        repo_meta = root / "osscollector" / "repo_meta"
    else:
        raise BinSbomError(
            "no repo_meta directory configured; pass --db/--repo-meta or set BIN_SBOM_DB",
            EXIT_MISSING_DB,
        )

    return database.resolve(), repo_meta.resolve()


def validate_data_dirs(database: Path, repo_meta: Path) -> None:
    component_db = database / "componentDB"
    missing = [
        str(component_db / entry)
        for entry in COMPONENT_DB_ENTRIES
        if not (component_db / entry).exists()
    ]
    if missing:
        raise BinSbomError(
            "incomplete component database under {}; missing: {}\n"
            "    build it with: uv run python src/preprocessor.py".format(
                component_db, ", ".join(Path(p).name for p in missing)
            ),
            EXIT_MISSING_DB,
        )

    # A missing repo_meta is not fatal to detection, but detector.py silently drops
    # every component that has no release metadata, yielding an empty SBOM. Fail
    # loudly instead.
    if not repo_meta.is_dir():
        raise BinSbomError(
            "repo_meta directory not found: {}\n"
            "    collect it with: uv run python src/OSScollector.py osscollector".format(repo_meta),
            EXIT_MISSING_DB,
        )
    if not any(repo_meta.glob("*.txt")):
        raise BinSbomError(
            "repo_meta directory contains no component metadata: {}".format(repo_meta),
            EXIT_MISSING_DB,
        )


def resolve_ghidra(args: argparse.Namespace) -> Path:
    if args.ghidra:
        ghidra = Path(args.ghidra).expanduser()
    elif os.environ.get("BIN_SBOM_GHIDRA"):
        ghidra = Path(os.environ["BIN_SBOM_GHIDRA"]).expanduser()
    else:
        # Repo layout: <root>/tools/ghidra/<GHIDRA_DIRNAME>, with PKG_DIR == <root>/src
        ghidra = PKG_DIR.parent / "tools" / "ghidra" / GHIDRA_DIRNAME

    ghidra = ghidra.resolve()
    if not (ghidra / "support" / "analyzeHeadless").exists():
        raise BinSbomError(
            "Ghidra headless not found under {}\n"
            "    install it with: bash tools/external_tools_install.sh, "
            "or point at it with --ghidra/$BIN_SBOM_GHIDRA".format(ghidra),
            EXIT_MISSING_DB,
        )
    return ghidra


def target_name(binary: Path, display_path: Optional[str]) -> str:
    """Name the binary is known by in the SBOM.

    bolt hands us a temporary extraction path for image scans, so the caller can
    pass the real in-image path via --display-path. Using it as the staged
    filename means the pipeline produces correct names natively, with no
    after-the-fact string substitution.
    """
    raw = Path(display_path).name if display_path else binary.name
    name = raw.strip().strip("/")
    if not name or name in {".", ".."} or "/" in name or "\\" in name:
        raise BinSbomError("invalid target name derived from {!r}".format(raw), EXIT_BAD_USAGE)
    return name


# --------------------------- staging ---------------------------


def build_workdir(
    workdir: Path,
    binary: Path,
    name: str,
    database: Path,
    repo_meta: Path,
    ghidra: Path,
) -> None:
    """Lay out the directory tree the pipeline scripts expect at ``cwd``."""
    # The scripts are copied rather than symlinked: cyclonedx_sbom_gen resolves
    # __file__ to pick its output directory, and a symlink would resolve back to
    # the installed package. Copying also keeps __pycache__ out of the install.
    shutil.copytree(PKG_DIR, workdir / "src", ignore=shutil.ignore_patterns("__pycache__"))

    # Read-only inputs are large; link them instead of copying.
    (workdir / "database").symlink_to(database, target_is_directory=True)
    (workdir / "osscollector").mkdir()
    (workdir / "osscollector" / "repo_meta").symlink_to(repo_meta, target_is_directory=True)

    # Only the Ghidra install is shared. ghidra_project must be a real per-run
    # directory: bin_preprocessor.clean_ghidra_project() wipes it, so sharing it
    # across concurrent runs would have them delete each other's projects.
    ghidra_root = workdir / "tools" / "ghidra"
    ghidra_root.mkdir(parents=True)
    (ghidra_root / GHIDRA_DIRNAME).symlink_to(ghidra, target_is_directory=True)
    (ghidra_root / "ghidra_project").mkdir()

    staged_bin = workdir / "testset" / "bin" / name
    staged_bin.parent.mkdir(parents=True)
    shutil.copy2(binary, staged_bin)

    (workdir / "output").mkdir()

    # utils/decomplie_ghidra.py runs inside Ghidra's interpreter and takes its output
    # root from this file, which is gitignored and therefore absent from a fresh
    # checkout. It holds one path, so upstream's multi-binary run needs it rewritten
    # per binary; here there is exactly one target per invocation.
    features_dir = workdir / "testset" / name
    features_dir.mkdir(parents=True, exist_ok=True)
    (workdir / "src" / "utils" / "config.json").write_text(
        json.dumps({"input_path": str(features_dir)}, indent=2), encoding="utf-8"
    )


def run_step(label: str, argv: List[str], workdir: Path) -> None:
    """Run a pipeline script with cwd at the staging root.

    Their progress output goes to stdout, which is reserved for the SBOM, so it is
    redirected to stderr.
    """
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONUNBUFFERED"] = "1"

    # Give each invocation its own HOME. Ghidra stores the JDK it discovers under
    # $HOME/.config/ghidra/<version>/, and a caller that analyzes several binaries at
    # once (bolt scans an image's binaries concurrently) races on creating that
    # directory: the loser reports "Failed to create directory" and then "Unable to
    # prompt user for JDK path, no TTY detected", and its binary silently yields no
    # SBOM. The staging workdir is already per-invocation, so it is the natural home.
    home = workdir / "home"
    home.mkdir(exist_ok=True)
    env["HOME"] = str(home)

    log("[bin-sbom] {}".format(label))
    completed = subprocess.run(argv, cwd=str(workdir), env=env, stdout=sys.stderr.fileno())
    if completed.returncode != 0:
        raise BinSbomError("{} failed (exit {})".format(label, completed.returncode))


def generate(
    binary: Path,
    name: str,
    database: Path,
    repo_meta: Path,
    ghidra: Path,
    workdir: Path,
    display_path: Optional[str] = None,
) -> str:
    build_workdir(workdir, binary, name, database, repo_meta, ghidra)

    py = sys.executable
    staged_bin = workdir / "testset" / "bin" / name

    # 1. Decompile with Ghidra and extract features. bin_preprocessor processes
    #    every file under testset/bin, which here is exactly our one target.
    run_step("preprocess: {}".format(name), [py, "src/bin_preprocessor.py"], workdir)

    # 2. Detect OSS components. detector.py already accepts binary names.
    run_step("detect: {}".format(name), [py, "src/detector.py", name], workdir)

    components = workdir / "output" / name / "{}.components.json".format(name)
    if not components.is_file():
        raise BinSbomError("detector produced no component list at {}".format(components))

    # 3. Build the CycloneDX document. --ldd is deliberately omitted: it emits
    #    dependsOn refs without matching components, and for image scans it would
    #    resolve host libraries rather than the image's.
    sbom_argv = [py, "src/cyclonedx_sbom_gen.py", str(staged_bin), str(components)]
    if display_path:
        sbom_argv += ["--display-path", display_path]
    run_step("sbom: {}".format(name), sbom_argv, workdir)

    # cyclonedx_sbom_gen names its output after Path(binary).stem.
    sbom = workdir / "output" / "{}-sbom.json".format(staged_bin.stem)
    if not sbom.is_file():
        raise BinSbomError("SBOM not generated at {}".format(sbom))
    return sbom.read_text(encoding="utf-8")


# --------------------------- entry point ---------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bin-sbom",
        description="Generate a CycloneDX SBOM for a single binary.",
    )
    # Accepted for symmetry with bom-blint's invocation; both are no-ops here.
    parser.add_argument("--no-banner", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--no-reviews", action="store_true", help=argparse.SUPPRESS)

    sub = parser.add_subparsers(dest="command", required=True)
    sbom = sub.add_parser("sbom", help="generate an SBOM for one binary")
    sbom.add_argument("-i", "--input", required=True, help="path to the target binary")
    sbom.add_argument(
        "--stdout", action="store_true", help="write the SBOM to stdout (default)"
    )
    sbom.add_argument("-o", "--output", help="write the SBOM to this file instead of stdout")
    sbom.add_argument(
        "--display-path",
        help="path to report for the binary; its basename names the component "
        "(use when --input is a temporary extraction)",
    )
    sbom.add_argument(
        "--db",
        help="root holding database/ and osscollector/repo_meta/ (default: $BIN_SBOM_DB)",
    )
    sbom.add_argument("--database", help="the database/ directory, if not under --db")
    sbom.add_argument("--repo-meta", help="the repo_meta/ directory, if not under --db")
    sbom.add_argument(
        "--ghidra", help="Ghidra install directory (default: $BIN_SBOM_GHIDRA)"
    )
    sbom.add_argument(
        "--keep-workdir", action="store_true", help="leave the staging directory for debugging"
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        binary = Path(args.input).expanduser().resolve()
        if not binary.is_file():
            raise BinSbomError("binary not found: {}".format(binary), EXIT_BAD_USAGE)

        # Without this the staging path would be reported as the binary's location.
        # bolt always passes --display-path, so only direct invocations need the default.
        display_path = args.display_path or str(binary)
        name = target_name(binary, display_path)
        database, repo_meta = resolve_data_dirs(args)
        validate_data_dirs(database, repo_meta)
        ghidra = resolve_ghidra(args)

        workdir = Path(tempfile.mkdtemp(prefix="bin-sbom-"))
        try:
            document = generate(
                binary, name, database, repo_meta, ghidra, workdir, display_path
            )
        finally:
            if args.keep_workdir:
                log("[bin-sbom] staging directory kept at {}".format(workdir))
            else:
                shutil.rmtree(workdir, ignore_errors=True)
    except BinSbomError as err:
        log("[bin-sbom] error: {}".format(err))
        return err.code
    except KeyboardInterrupt:
        return 130

    if args.output:
        Path(args.output).write_text(document, encoding="utf-8")
        log("[bin-sbom] wrote {}".format(args.output))
    else:
        sys.stdout.write(document)
        if not document.endswith("\n"):
            sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
