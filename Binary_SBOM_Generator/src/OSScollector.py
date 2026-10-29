"""
Dataset Collection Tool.
Original Author: Seunghoon Woo (seunghoonwoo@korea.ac.kr)
Modified Author: Heedong Yang (heedongy@korea.ac.kr)
"""

import os
import git
import shutil
import subprocess
import re
import tlsh
import json
import glob
import concurrent.futures
from pathlib import Path
from urllib.parse import urlparse
import preprocess_clang as preClang

"""GLOBALS"""
currentPath = os.getcwd() + "/osscollector"
gitCloneURLS = currentPath + "/repolist.txt"
funcCodePath = currentPath + "/repo_funcCode/"
clonePath = currentPath + "/repo_src/"  # Default path
tagDatePath = currentPath + "/repo_date/"  # Default path
resultPath = currentPath + "/repo_functions/"  # Default path
metaPath = currentPath + "/repo_meta/"  # Path for SBOM metadata (license, purl)
funcMetaPath = currentPath + "/repo_funcMeta/"
repoSidecarPath = currentPath + "/repo_repoMeta/"
ctagsPath = shutil.which("ctags") or "/bin/ctags"  # Prefer PATH discovery; fallback for legacy setups

# License file patterns
LICENSE_PATTERNS = ["LICENSE", "LICENSE.txt", "LICENSE.md", "LICENCE", "COPYING", "COPYING.*"]
MANIFEST_PATTERNS = [
    "CMakeLists.txt",
    "configure.ac",
    "configure.in",
    "meson.build",
    "Makefile.am",
    "vcpkg.json",
    "conanfile.txt",
    "conanfile.py",
    "*.pc",
    "*.pc.in",
    "README*",
]

VENDORED_DIR_NAMES = {
    "third_party",
    "thirdparty",
    "3rdparty",
    "third-party",
    "vendor",
    "external",
    "externals",
    "external_libs",
    "components",
    "deps",
    "contrib",
    "dependencies",
    "extern",
}
EXCLUDED_DIR_NAMES = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".cache",
    "build",
    "cmake-build-debug",
    "cmake-build-release",
}

BLACKLIST_TOKENS = {
    "src",
    "source",
    "sources",
    "lib",
    "libs",
    "common",
    "test",
    "tests",
    "testing",
    "module",
    "modules",
    "components",
    "extra",
}

# Generate directories
shouldMake = [clonePath, tagDatePath, resultPath, metaPath, funcMetaPath, repoSidecarPath]
for eachRepo in shouldMake:
    if not os.path.isdir(eachRepo):
        os.mkdir(eachRepo)


# Generate TLSH
def computeTlsh(string):
    string = str.encode(string)
    hs = tlsh.forcehash(string)
    return hs


def removeComment(string):
    # Code for removing C/C++ style comments. (Imported from VUDDY and ReDeBug.)
    # ref: https://github.com/squizz617/vuddy
    c_regex = re.compile(
        r'(?P<comment>//.*?$|[{}]+)|(?P<multilinecomment>/\*.*?\*/)|(?P<noncomment>\'(\\.|[^\\\'])*\'|"(\\.|[^\\"])*"|.[^/\'"]*)',
        re.DOTALL | re.MULTILINE)
    return ''.join([c.group('noncomment') for c in c_regex.finditer(string) if c.group('noncomment')])


def normalize(string):
    # Code for normalizing the input string.
    # LF and TAB literals, curly braces, and spaces are removed,
    # and all characters are lowercased.
    # ref: https://github.com/squizz617/vuddy
    return ''.join(string.replace('\n', '').replace('\r', '').replace('\t', '').replace('{', '').replace('}', '').split(
        ' ')).lower()

def decode_output(output):
    try:
        return output.decode('utf-8')
    except UnicodeDecodeError:
        return output.decode('latin-1', 'ignore')


def should_skip_dir(dirname):
    return dirname.lower() in EXCLUDED_DIR_NAMES


def filtered_walk(root):
    for path, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if not should_skip_dir(d)]
        yield path, dirs, files


def sanitize_version_tag(tag_name):
    return str(tag_name).replace('/', '_').replace('\\', '_')


def normalize_submodule_component_name(submodule_url):
    try:
        repo_path = normalize_repo_url_path(str(submodule_url))
        return repo_path.replace("/", "@@")
    except Exception:
        cleaned = str(submodule_url).strip().strip("/")
        if cleaned.endswith(".git"):
            cleaned = cleaned[:-4]
        return cleaned.replace("/", "@@").replace(":", "@@")


def get_submodule_commit(repo, submodule_path):
    try:
        return repo.git.ls_tree("HEAD", submodule_path).split()[2]
    except Exception:
        return ""


def collect_git_submodules(repo):
    submodules = []
    try:
        for submodule in repo.submodules:
            path = str(submodule.path).replace("\\", "/").strip("/")
            url = str(submodule.url)
            commit = get_submodule_commit(repo, path)
            submodules.append({
                "path": path,
                "url": url,
                "commit": commit,
                "component": normalize_submodule_component_name(url),
            })
    except Exception:
        return []
    return sorted(submodules, key=lambda item: item["path"])


def update_git_submodules(repo):
    if os.environ.get("BCA_SKIP_SUBMODULE_UPDATE") == "1":
        return []
    try:
        repo.git.submodule("sync", "--recursive")
        repo.git.submodule("update", "--init", "--recursive")
    except Exception as e:
        print(f"[!] Submodule update failed: {e}")
    return collect_git_submodules(repo)


def refresh_repo_sidecar_and_submodules(repo, repo_dir, repo_name):
    submodules = update_git_submodules(repo)
    write_repo_sidecar(repo_dir, repo_name, repo)
    return submodules


def find_submodule_for_path(stored_path, submodules):
    normalized = str(stored_path).replace("\\", "/").lstrip("/")
    best = None
    for submodule in submodules or []:
        sub_path = submodule.get("path", "").strip("/")
        if not sub_path:
            continue
        if normalized == sub_path or normalized.startswith(sub_path + "/"):
            if best is None or len(sub_path) > len(best.get("path", "")):
                best = submodule
    return best


def collect_hint_tokens(raw):
    cleaned = (
        str(raw)
        .strip()
        .strip("\"'<>(),;")
        .replace("\\", "/")
        .lower()
    )
    if not cleaned:
        return set()

    tokens = set()
    parts = [part.strip() for part in cleaned.split('/') if part.strip()]
    if parts:
        first = parts[0].split('.')[0].strip()
        last = parts[-1].split('.')[0].strip()
        if first and first not in BLACKLIST_TOKENS:
            tokens.add(first)
        if last and last not in BLACKLIST_TOKENS:
            tokens.add(last)
    for part in parts:
        piece = part.split('.')[0].strip()
        if piece and piece not in BLACKLIST_TOKENS:
            tokens.add(piece)
    return tokens


def extract_include_tokens(content):
    tokens = set()
    for match in re.finditer(r'(?m)^\s*#\s*include\s*[<"]([^">]+)[">]', content):
        tokens.update(collect_hint_tokens(match.group(1)))
    return tokens


def extract_manifest_tokens(content):
    tokens = set()
    patterns = [
        r'(?i)find_package\s*\(\s*([A-Za-z0-9_.+\-]+)',
        r'(?i)dependency\s*\(\s*[\'"]([^\'"]+)[\'"]',
        r'(?i)pkg_check_modules\s*\(\s*[A-Za-z0-9_]+\s+([A-Za-z0-9_.+\-]+)',
        r'(?i)-l([A-Za-z0-9_.+\-]+)',
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, content):
            tokens.update(collect_hint_tokens(match.group(1)))
    return tokens


def collect_license_text(repo_dir):
    for pattern in LICENSE_PATTERNS:
        matches = glob.glob(os.path.join(repo_dir, pattern))
        for match in matches:
            if os.path.isfile(match):
                try:
                    with open(match, 'r', encoding='utf-8', errors='ignore') as f:
                        return f.read().lower()
                except Exception:
                    continue
    return ""


def collect_repo_sidecar_metadata(repo_dir, repo_name, repo=None):
    manifest_tokens = set()
    for path, _, files in filtered_walk(repo_dir):
        for filename in files:
            candidate = os.path.join(path, filename)
            matched = False
            for pattern in MANIFEST_PATTERNS:
                if Path(filename).match(pattern):
                    matched = True
                    break
            if not matched:
                continue
            try:
                with open(candidate, 'r', encoding='utf-8', errors='ignore') as f:
                    manifest_tokens.update(extract_manifest_tokens(f.read()))
            except Exception:
                continue

    return {
        "repo_name": repo_name,
        "license_id": detect_license_id(repo_dir),
        "license_text": collect_license_text(repo_dir),
        "build_manifest_tokens": sorted(manifest_tokens),
        "sbom_dependency_tokens": sorted(manifest_tokens),
        "git_submodules": collect_git_submodules(repo) if repo is not None else [],
    }


def write_repo_sidecar(repo_dir, repo_name, repo=None):
    repo_sidecar_file = os.path.join(repoSidecarPath, f"{repo_name}.json")
    sidecar = collect_repo_sidecar_metadata(repo_dir, repo_name, repo)
    with open(repo_sidecar_file, 'w', encoding='utf-8') as f:
        json.dump(sidecar, f, indent=2, ensure_ascii=False)


def write_function_meta_sidecar(repo_name, version_name, func_meta):
    repo_dir = os.path.join(funcMetaPath, repo_name)
    os.makedirs(repo_dir, exist_ok=True)
    sidecar_path = os.path.join(repo_dir, f"fuzzy_{sanitize_version_tag(version_name)}.json")
    serializable = {}
    for func_hash, entry in func_meta.items():
        serializable[func_hash] = {
            "paths": sorted(entry["paths"]),
            "include_tokens": sorted(entry["include_tokens"]),
            "occurrences": sorted(
                entry.get("occurrences", []),
                key=lambda item: (
                    item.get("repo", ""),
                    item.get("version", ""),
                    item.get("path", ""),
                    item.get("function_name", ""),
                ),
            ),
            "path_birth_dates": {
                path: entry["path_birth_dates"][path]
                for path in sorted(entry.get("path_birth_dates", {}))
            },
        }
    with open(sidecar_path, 'w', encoding='utf-8') as f:
        json.dump(serializable, f, indent=2, ensure_ascii=False)


def detect_license_id(repo_dir):
    for pattern in LICENSE_PATTERNS:
        matches = glob.glob(os.path.join(repo_dir, pattern))
        for match in matches:
            if os.path.isfile(match):
                try:
                    with open(match, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read().lower()

                    # 0) SPDX-License-Identifier가 있으면 최우선 (가장 정확)
                    #    예: "spdx-license-identifier: mit"
                    m = re.search(r"spdx-license-identifier:\s*([a-z0-9\.\-+ ]+)", content)
                    if m:
                        spdx = m.group(1).strip()
                        # 흔한 끝문자 제거
                        spdx = re.sub(r"[;)\].,]+$", "", spdx)
                        # 공백 제거 + 대문자 정규화(단, -or-later 같은건 대문자여도 문제없음)
                        return spdx.replace(" ", "").upper()

                    # 1) SSPL / RSALv2는 GPL/AGPL보다 먼저 (문구가 겹쳐 오탐 방지)
                    if "server side public license" in content or ("sspl" in content and "license" in content):
                        return "SSPL-1.0"
                    elif "redis source available license" in content or "rsalv2" in content or "redis source available license 2.0" in content:
                        # SPDX 표준 ID로 단정하기 애매 → LicenseRef로
                        return "LicenseRef-RSALv2"

                    # 2) MIT (강한 시그니처)
                    if ("permission is hereby granted, free of charge, to any person obtaining a copy" in content
                        and ("the software is provided \"as is\"" in content or "the software is provided 'as is'" in content)
                        and "without warranty of any kind" in content):
                        return "MIT"
                    elif "mit license" in content and "permission is hereby granted" in content:
                        return "MIT"

                    # 3) Apache-2.0 (정형 문구/URL)
                    elif ("apache license" in content and "version 2.0" in content
                          and ("http://www.apache.org/licenses/license-2.0" in content
                               or "you may not use this file except in compliance with the license" in content)):
                        return "Apache-2.0"

                    # 4) MPL-2.0
                    elif "mozilla public license" in content and ("version 2.0" in content or "mpl 2.0" in content):
                        return "MPL-2.0"

                    # 5) Boost
                    elif "boost software license" in content and ("version 1.0" in content or "boost software license - version 1.0" in content):
                        return "BSL-1.0"

                    # 6) ISC (짧지만 강한 시그니처)
                    elif ("permission to use, copy, modify, and/or distribute this software for any purpose" in content
                          and "provided that the above copyright notice" in content
                          and ("the software is provided \"as is\"" in content or "the software is provided 'as is'" in content)):
                        return "ISC"
                    elif "isc license" in content:
                        return "ISC"

                    # 7) BSD 2/3-clause (endorsement 문구로 구분)
                    elif "redistribution and use in source and binary forms" in content:
                        if "neither the name of" in content and "nor the names of its contributors" in content:
                            return "BSD-3-Clause"
                        # 2-clause는 보통 endorsement 문구가 없다.
                        # 애매하면 단정하지 말고 UNKNOWN
                        elif "this list of conditions and the following disclaimer" in content:
                            return "BSD-2-Clause"
                        else:
                            return "UNKNOWN"
                    elif "bsd 3-clause" in content:
                        return "BSD-3-Clause"
                    elif "bsd 2-clause" in content:
                        return "BSD-2-Clause"

                    # 8) AGPL / LGPL / GPL (버전 + only/or-later)
                    elif "gnu affero general public license" in content:
                        if "version 3" in content:
                            if "or (at your option) any later version" in content or "or later" in content:
                                return "AGPL-3.0-or-later"
                            return "AGPL-3.0-only"
                        return "UNKNOWN"
                    elif "gnu lesser general public license" in content:
                        if "version 3" in content:
                            if "or (at your option) any later version" in content or "or later" in content:
                                return "LGPL-3.0-or-later"
                            return "LGPL-3.0-only"
                        elif "version 2.1" in content:
                            if "or (at your option) any later version" in content or "or later" in content:
                                return "LGPL-2.1-or-later"
                            return "LGPL-2.1-only"
                        elif "version 2" in content:
                            if "or (at your option) any later version" in content or "or later" in content:
                                return "LGPL-2.0-or-later"
                            return "LGPL-2.0-only"
                        return "UNKNOWN"
                    elif "gnu general public license" in content:
                        if "version 3" in content:
                            if "or (at your option) any later version" in content or "or later" in content:
                                return "GPL-3.0-or-later"
                            return "GPL-3.0-only"
                        elif "version 2" in content:
                            if "or (at your option) any later version" in content or "or later" in content:
                                return "GPL-2.0-or-later"
                            return "GPL-2.0-only"
                        return "UNKNOWN"

                except:
                    pass
    return "UNKNOWN"



def checkout_ref(repo, ref):
    """Check out a tag, commit SHA, or branch.

    Only annotated/lightweight tag *names* resolve under "tags/", so pinning a repo to a
    commit SHA or to a branch such as "master" used to raise here. The caller treats that
    as a fatal error for the repository and skips metadata collection and hashing
    entirely, which silently dropped every SHA- or branch-pinned entry from the database.
    """
    last_error = None
    for candidate in (f'tags/{ref}', ref, f'origin/{ref}'):
        try:
            repo.git.checkout(candidate, force=True)
            return candidate
        except Exception as e:
            last_error = e
    raise last_error


def collect_and_save_metadata(repo_dir, repo_name, version, component_type):
    name = repo_name.split("@@")[-1] if "@@" in repo_name else repo_name
    # Remove a leading "v" / "v." version prefix, but only where it actually prefixes a
    # number. Stripping it unconditionally mangled any tag that merely begins with "v":
    # "version-1.900.1" became "ersion-1.900.1", and that string reached the SBOM as the
    # component version. Tags like "release-2.0.12" or "jpeg-9a" are kept verbatim,
    # because the ground truth records the raw tag for those.
    clean_version = version
    if version and version != "default":
        clean_version = re.sub(r'^[vV]\.?(?=\d)', '', version)

    # Generate PURL (pkg:generic/name@version)
    purl = f"pkg:generic/{name}@{clean_version}" if clean_version and clean_version != "default" else f"pkg:generic/{name}"

    license_id = detect_license_id(repo_dir)

    line = f"{version}, {purl}, {license_id}, {component_type}\n"

    meta_file_path = os.path.join(metaPath, f"{repo_name}.txt")
    try:
        with open(meta_file_path, 'a', encoding='utf-8') as f:
            f.write(line)
    except Exception as e:
        print(f"Error saving metadata: {e}")

def extract_functions(filePath):
    try:
        _, file_extension = os.path.splitext(filePath)
        file_extension = file_extension.lower()
        # An argument list, not a shell string: file names come from the collected
        # repositories, and a name containing shell syntax must not run as a command.
        ctags_command = [ctagsPath, '-f', '-', '--kinds-C=*', '--fields=neKSt', filePath]
        # for .i extension
        if file_extension == '.i':
            base_file_name = os.path.splitext(filePath)[0]
            _, new_file_extension = os.path.splitext(base_file_name)
            new_file_extension = new_file_extension.lower()
            language_map = {
                '.c': 'C',
                '.cc': 'C++',
                '.cpp': 'C++',
            }
            language_option = language_map.get(new_file_extension, None)
            # Apply language force only when detectable
            if language_option:
                ctags_command = [ctagsPath, f'--language-force={language_option}', '-f', '-',
                                 '--kinds-C=*', '--fields=neKSt', filePath]

        functionList = subprocess.check_output(
            ctags_command, stderr=subprocess.STDOUT
        ).decode()

        with open(filePath, 'r', encoding="UTF-8", errors='ignore') as f:
            lines = f.readlines()
        allFuncs = str(functionList).split('\n')
        func = re.compile(r'(function)')
        number = re.compile(r'(\d+)')
        funcSearch = re.compile(r'{([\S\s]*)}')
        paramSearch = re.compile(r'\(([^)]*)\)')

        functions = {}
        for i in allFuncs:
            elemList = re.sub(r'[\t\s ]{2,}', '', i).split('\t')
            if i and len(elemList) >= 8 and func.fullmatch(elemList[3]):
                funcName = elemList[0]
                funcStartLine = int(number.search(elemList[4]).group(0))
                funcEndLine = int(number.search(elemList[7]).group(0))
                funcFullBody = ''.join(lines[funcStartLine - 1: funcEndLine])
                funcBody = ''.join(lines[funcStartLine - 1: funcEndLine])

                if funcSearch.search(funcBody):
                    funcBody = funcSearch.search(funcBody).group(1)
                else:
                    funcBody = " "
                funcBody = removeComment(funcBody)

                if paramSearch.search(funcFullBody):
                    params = paramSearch.search(funcFullBody).group(1)
                    paramCount = len([param.strip() for param in params.split(',') if param.strip()])
                else:
                    paramCount = 0

                functions[funcName] = (funcFullBody, funcBody, paramCount)
        return functions
    except subprocess.CalledProcessError as e:
        print("Parser Error:", e)
    except Exception as e:
        print("Subprocess failed", e)
    return {}

def cleanup_preprocessed_files(root):
    """Remove all .i files from previous preprocessing runs."""
    for path, _, files in filtered_walk(root):
        for f in files:
            if f.endswith('.i'):
                try:
                    os.remove(os.path.join(path, f))
                except Exception as e:
                    print(f"Failed to remove {os.path.join(path, f)}: {e}")


def get_file_birth_date(repoPath, storedPath, cache):
    if storedPath in cache:
        return cache[storedPath]

    rel_path = storedPath.lstrip("/\\")
    if not rel_path:
        cache[storedPath] = None
        return None

    try:
        output = subprocess.check_output(
            [
                "git",
                "-C",
                repoPath,
                "log",
                "--follow",
                "--diff-filter=A",
                "--format=%ai",
                "--",
                rel_path,
            ],
            stderr=subprocess.DEVNULL,
        )
        decoded = decode_output(output).strip().splitlines()
        cache[storedPath] = decoded[-1][:10] if decoded else None
    except Exception:
        cache[storedPath] = None
    return cache[storedPath]

def hashing(repoPath, saveCodePath, repoName="", versionName="", submodules=None):
    possible = (".c", ".cc", ".cpp")
    fileCnt = 0
    funcCnt = 0
    lineCnt = 0
    resDict = {}
    funcMeta = {}
    path_birth_cache = {}

    # Clean up old .i files before preprocessing
    cleanup_preprocessed_files(repoPath)

    # Clang Preprocessing
    preClang.process_files_in_directory(repoPath)

    for path, _, files in filtered_walk(repoPath):
        for file in files:
            filePath = os.path.join(path, file)
            if file.endswith(possible):
                i_filePath = filePath + '.i'
                i_functions = {}
                if os.path.exists(i_filePath):
                    i_functions = extract_functions(i_filePath)

                functions = extract_functions(filePath)
                if not functions:
                    continue

                fileCnt += 1
                with open(filePath, 'r', encoding="UTF-8", errors='ignore') as f:
                    file_content = f.read()
                lines = file_content.splitlines(True)
                include_tokens = extract_include_tokens(file_content)

                for funcName, (funcFullBody, funcBody, paramCount) in functions.items():
                    if funcName in i_functions:
                        funcFullBody, funcBody, paramCount = i_functions[funcName]

                    funcBody = removeComment(funcBody)
                    normalizedFuncBody = normalize(funcBody)
                    funcHash = computeTlsh(normalizedFuncBody)

                    if len(funcHash) == 72 and funcHash.startswith("T1"):
                        funcHash = funcHash[2:]
                    elif funcHash in ["TNULL", "", "NULL"]:
                        continue

                    storedPath = filePath.replace(repoPath, "")
                    if funcHash not in resDict:
                        resDict[funcHash] = []

                    resDict[funcHash].append((storedPath, funcName, paramCount))
                    funcMeta.setdefault(
                        funcHash,
                        {
                            "paths": set(),
                            "include_tokens": set(),
                            "path_birth_dates": {},
                            "occurrences": [],
                        },
                    )
                    funcMeta[funcHash]["paths"].add(storedPath)
                    funcMeta[funcHash]["include_tokens"].update(include_tokens)
                    birth_date = get_file_birth_date(repoPath, storedPath, path_birth_cache)
                    if birth_date:
                        funcMeta[funcHash]["path_birth_dates"][storedPath] = birth_date
                    occurrence = {
                        "repo": repoName,
                        "version": str(versionName),
                        "path": storedPath,
                        "function_name": funcName,
                        "param_count": paramCount,
                        "tlsh": funcHash,
                        "include_tokens": sorted(include_tokens),
                        "path_birth_date": birth_date,
                    }
                    submodule = find_submodule_for_path(storedPath, submodules)
                    if submodule:
                        occurrence["submodule_path"] = submodule.get("path", "")
                        occurrence["submodule_url"] = submodule.get("url", "")
                        occurrence["submodule_commit"] = submodule.get("commit", "")
                        occurrence["submodule_component"] = submodule.get("component", "")
                    funcMeta[funcHash]["occurrences"].append(occurrence)

                    file_ext = os.path.splitext(filePath)[1]  # .c, .cpp, .cc 등 원본 확장자
                    hash_file_path = os.path.join(saveCodePath, f'{funcHash}{file_ext}')
                    if not os.path.exists(hash_file_path):
                        if not os.path.exists(saveCodePath):
                            os.makedirs(saveCodePath)
                        with open(hash_file_path, 'w', encoding='utf-8') as funcFile:
                            funcFile.write(removeComment(funcFullBody))

                    lineCnt += len(lines)
                    funcCnt += 1

    return resDict, funcMeta, fileCnt, funcCnt, lineCnt

def indexing(resDict, title, filePath):
    # For indexing each OSS
    with open(filePath, 'w') as fres:
        fres.write(title + '\n')

        for hashval in resDict:
            if hashval == '' or hashval == ' ':
                continue

            fres.write(hashval)

            for funcPath, funcName, paramCount in resDict[hashval]:
                fres.write(f', {funcName}, {paramCount}, {funcPath}')
            fres.write('\n')


def is_repo_completed(repoName):
    repo_result_dir = os.path.join(resultPath, repoName)
    if not os.path.isdir(repo_result_dir):
        return False
    hidx_files = glob.glob(os.path.join(repo_result_dir, "*.hidx"))
    return len(hidx_files) > 0


def is_valid_version_tag(tag_name: str) -> bool:
    tag_str = str(tag_name)
    
    # beta, alpha, pre, rc, dev, snapshot 등 프리릴리즈 버전 제외
    prerelease_patterns = ['alpha', 'beta', 'pre', 'rc', 'dev', 'snapshot', 'nightly', 'canary', 'test']
    tag_lower = tag_str.lower()
    for pattern in prerelease_patterns:
        if pattern in tag_lower:
            return False
    
    # Strip a leading "v" / "v." prefix for parsing, but only where a digit follows.
    # Stripping unconditionally turns "version-1.900.1" into "ersion-1.900.1"; the
    # project_version_pattern below happens to salvage that, but only by accident.
    cleaned = re.sub(r'^[vV]\.?(?=\d)', '', tag_str)
    
    # 패턴 2
    project_version_pattern = re.compile(r'^[a-zA-Z][a-zA-Z0-9]*[._-](.+)$')
    match = project_version_pattern.match(cleaned)
    if match:
        cleaned = match.group(1)
    
    # 버전 3
    version_pattern = re.compile(r'^(\d+[a-zA-Z]?)[._-](\d+[a-zA-Z]?)(?:[._-](\d+[a-zA-Z]?))?(?:[._-].*)?$')
    return version_pattern.match(cleaned) is not None


def filter_version_tags(tags) -> list:
    valid_tags = []
    for tag in tags:
        tag_name = str(tag)
        if is_valid_version_tag(tag_name):
            valid_tags.append(tag_name)
    return valid_tags


def get_tag_commit_date(repo, tag_name):
    try:
        return repo.git.log(f"refs/tags/{tag_name}", n=1, format="%ai").strip()
    except Exception:
        return ""


def select_latest_valid_tag(repo, tags):
    filtered_tags = filter_version_tags(tags)
    if not filtered_tags:
        return []
    dated_tags = []
    for tag_name in filtered_tags:
        tag_date = get_tag_commit_date(repo, tag_name)
        if tag_date:
            dated_tags.append((tag_date, tag_name))
    if not dated_tags:
        return [filtered_tags[-1]]
    dated_tags.sort(reverse=True)
    return [dated_tags[0][1]]


def parse_sample_line(line):
    raw = line.strip()
    if not raw:
        return None

    parts = [part.strip() for part in raw.split(',', 2)]
    url = parts[0]
    component_type = parts[1] if len(parts) > 1 and parts[1] else "library"
    requested_tags = None
    if len(parts) > 2 and parts[2]:
        try:
            parsed = json.loads(parts[2])
            if isinstance(parsed, list):
                requested_tags = [str(tag).strip() for tag in parsed if str(tag).strip()]
        except json.JSONDecodeError:
            requested_tags = None
    return url, component_type, requested_tags


def normalize_repo_url_path(repo_url):
    raw = repo_url.strip()
    if not raw:
        raise ValueError("empty repository URL")

    if "://" in raw:
        parsed = urlparse(raw)
        repo_path = parsed.path
    elif raw.startswith("git@") and ":" in raw:
        repo_path = raw.split(":", 1)[1]
    else:
        repo_path = raw

    repo_path = repo_path.strip().strip("/")
    if repo_path.endswith(".git"):
        repo_path = repo_path[:-4]
    if not repo_path:
        raise ValueError(f"invalid repository URL: {repo_url}")
    return repo_path


def get_repo_name_from_url(repo_url):
    repo_path = normalize_repo_url_path(repo_url)
    return repo_path.replace("/", "@@")


def write_tag_dates(repo, repo_name, target_tags=None):
    with open(os.path.join(tagDatePath, repo_name), 'w', encoding='utf-8') as tag_date_file:
        if target_tags:
            for tag_name in target_tags:
                tag_date = get_tag_commit_date(repo, tag_name)
                if tag_date:
                    tag_date_file.write(f"{tag_date} (tag: {tag_name})\n")
            return

        tags = repo.tags
        branches = [branch.name for branch in repo.remote().refs]
        for tag in tags:
            tag_date = repo.git.log(f"refs/tags/{tag}", n=1, format="%ai")
            tag_date_file.write(f"{tag_date} (tag: {tag})\n")
        if 'origin/master' in branches:
            branch_date = repo.git.log('origin/master', n=1, format="%ai")
            tag_date_file.write(f"{branch_date} (tag: master)\n")
        if 'origin/main' in branches:
            branch_date = repo.git.log('origin/main', n=1, format="%ai")
            tag_date_file.write(f"{branch_date} (tag: main)\n")

def _clone_repo(url: str, dest: str):
    """Clone with credential prompts disabled. Raises on auth failure or 404."""
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_ASKPASS"] = "echo"
    return git.Repo.clone_from(url, dest, env=env)


def process_repo(eachUrl, component_type, requested_tags=None):
    os.chdir(currentPath)
    repoName = get_repo_name_from_url(eachUrl)

    # Skip if already completed
    if is_repo_completed(repoName):
        print(f"[*] {repoName} is already completed")
        return

    print("[+] Processing", repoName)

    # Define specific tags for each repository
    repo_tag_mapping = {
        'redis@@redis': ['4.0.0', '6.0.0', '7.2.0', '8.4.0'],
        'redis@@hiredis': ['v0.13.0', 'v1.0.0', 'v1.2.0'],
        'fastfloat@@fast_float': ['v3.0.0', 'v5.0.0', 'v6.1.1'],
        'HdrHistogram@@HdrHistogram_c': ['0.9.1', '0.11.0', '0.11.8'],
        'jemalloc@@jemalloc': ['3.6.0', '4.5.0', '5.3.0'],
        'antirez@@linenoise': ['1.0'],
        'zlib@@zlib': ['1.2.8', '1.2.11', '1.3.1'],
        'Cyan4973@@xxHash': ['v0.7.4', 'v0.8.2', 'v0.8.3']
    }

    try:
        repo_dir = os.path.join(clonePath, repoName)
        # Clone the repository (credential prompts disabled — fails fast on 404 / private repos).
        #
        # Reuse an existing clone rather than cloning over it. git refuses to clone into a
        # non-empty directory with a "fatal: destination path already exists" message, which
        # the handler below matches on "fatal" and treats as an inaccessible repository --
        # deleting the perfectly good checkout. Combined with a run that clones but fails
        # later, that made every other run fail for the same repositories.
        try:
            if os.path.isdir(os.path.join(repo_dir, ".git")):
                repo = git.Repo(repo_dir)
                try:
                    repo.git.fetch("--all", "--tags", "--force")
                except Exception as fetch_err:
                    print(f"[!] Fetch failed for {repoName}, using existing checkout: {fetch_err}")
            else:
                if os.path.isdir(repo_dir):
                    shutil.rmtree(repo_dir, ignore_errors=True)
                repo = _clone_repo(eachUrl, repo_dir)
        except git.exc.GitCommandError as clone_err:
            err_msg = str(clone_err).lower()
            if any(kw in err_msg for kw in ("authentication", "could not read", "repository not found",
                                             "not found", "403", "404", "fatal")):
                print(f"[!] Skipping {repoName}: inaccessible or deleted ({clone_err})")
            else:
                print(f"[!] Clone failed for {repoName}: {clone_err}")
            if os.path.isdir(repo_dir):
                shutil.rmtree(repo_dir, ignore_errors=True)
            return
        write_repo_sidecar(repo_dir, repoName, repo)

        tags = repo.tags
        write_tag_dates(repo, repoName)

        resDict = {}
        funcMeta = {}
        fileCnt = 0
        funcCnt = 0
        lineCnt = 0

        # Check if this repository has a specific tag mapping
        if requested_tags:
            target_tags = requested_tags
            write_tag_dates(repo, repoName, target_tags)
            for target_tag in target_tags:
                print(f"Using requested tag {target_tag} for {repoName}")
                try:
                    checkout_ref(repo, target_tag)
                    submodules = refresh_repo_sidecar_and_submodules(repo, repo_dir, repoName)
                    collect_and_save_metadata(repo_dir, repoName, target_tag, component_type)
                    resDict, funcMeta, fileCnt, funcCnt, lineCnt = hashing(repo_dir, os.path.join(funcCodePath, repoName), repoName, target_tag, submodules)
                    if len(resDict) > 0:
                        if not os.path.isdir(resultPath + repoName):
                            os.mkdir(resultPath + repoName)
                        title = '\t'.join([repoName, str(fileCnt), str(funcCnt), str(lineCnt)])
                        resultFilePath = resultPath + repoName + f'/fuzzy_{sanitize_version_tag(target_tag)}.hidx'
                        indexing(resDict, title, resultFilePath)
                        write_function_meta_sidecar(repoName, target_tag, funcMeta)
                except Exception as e:
                    print(f"Error checking out tag {target_tag} for {repoName}: {e}")
        elif repoName in repo_tag_mapping:
            target_tags = repo_tag_mapping[repoName]
            write_tag_dates(repo, repoName, target_tags)
            for target_tag in target_tags:
                print(f"Using specific tag {target_tag} for {repoName}")

                try:
                    # Checkout the specific tag
                    checkout_ref(repo, target_tag)
                    submodules = refresh_repo_sidecar_and_submodules(repo, repo_dir, repoName)

                    # Collect and save metadata (version, purl, license id, type) for SBOM
                    collect_and_save_metadata(repo_dir, repoName, target_tag, component_type)

                    resDict, funcMeta, fileCnt, funcCnt, lineCnt = hashing(repo_dir, os.path.join(funcCodePath, repoName), repoName, target_tag, submodules)

                    if len(resDict) > 0:
                        if not os.path.isdir(resultPath + repoName):
                            os.mkdir(resultPath + repoName)
                        title = '\t'.join([repoName, str(fileCnt), str(funcCnt), str(lineCnt)])
                        resultFilePath = resultPath + repoName + f'/fuzzy_{target_tag}.hidx'
                        indexing(resDict, title, resultFilePath)
                        write_function_meta_sidecar(repoName, target_tag, funcMeta)
                except Exception as e:
                    print(f"Error checking out tag {target_tag} for {repoName}: {e}")

        elif len(tags) > 0:
            filtered_tags = select_latest_valid_tag(repo, tags)
            
            if len(filtered_tags) > 0:
                print(f"Found {len(filtered_tags)} valid version tags for {repoName}")
                
                write_tag_dates(repo, repoName, filtered_tags)

                for target_tag in filtered_tags:
                    print(f"Processing tag {target_tag} for {repoName}")

                    try:
                        checkout_ref(repo, target_tag)
                        submodules = refresh_repo_sidecar_and_submodules(repo, repo_dir, repoName)
                        collect_and_save_metadata(repo_dir, repoName, target_tag, component_type)
                        resDict, funcMeta, fileCnt, funcCnt, lineCnt = hashing(repo_dir, os.path.join(funcCodePath, repoName), repoName, target_tag, submodules)

                        if len(resDict) > 0:
                            if not os.path.isdir(resultPath + repoName):
                                os.mkdir(resultPath + repoName)
                            title = '\t'.join([repoName, str(fileCnt), str(funcCnt), str(lineCnt)])
                            safe_tag = sanitize_version_tag(target_tag)
                            resultFilePath = resultPath + repoName + f'/fuzzy_{safe_tag}.hidx'
                            indexing(resDict, title, resultFilePath)
                            write_function_meta_sidecar(repoName, target_tag, funcMeta)
                    except Exception as e:
                        print(f"Error checking out tag {target_tag} for {repoName}: {e}")
            else:
                # 필터링 결과 유효한 버전 태그가 없으면 HEAD 사용
                print(f"No valid version tags found for {repoName}, using HEAD commit")
                head_sha = repo.head.commit.hexsha
                head_date = repo.git.log('HEAD', n=1, format="%ai")
                version = f"git+{head_sha}"

                with open(os.path.join(tagDatePath, repoName), 'w') as tag_date_file:
                    tag_date_file.write(f"{head_date} (commit: {head_sha})\n")

                collect_and_save_metadata(repo_dir, repoName, version, component_type)
                submodules = refresh_repo_sidecar_and_submodules(repo, repo_dir, repoName)
                resDict, funcMeta, fileCnt, funcCnt, lineCnt = hashing(repo_dir, os.path.join(funcCodePath, repoName), repoName, head_sha[:8], submodules)
                
                if len(resDict) > 0:
                    if not os.path.isdir(resultPath + repoName):
                        os.mkdir(resultPath + repoName)
                    title = '\t'.join([repoName, str(fileCnt), str(funcCnt), str(lineCnt)])
                    resultFilePath = resultPath + repoName + f'/fuzzy_{head_sha[:8]}.hidx'
                    indexing(resDict, title, resultFilePath)
                    write_function_meta_sidecar(repoName, head_sha[:8], funcMeta)

        else:
            # 태그가 아예 없는 경우: HEAD 커밋 사용
            head_sha = repo.head.commit.hexsha
            head_date = repo.git.log('HEAD', n=1, format="%ai")
            version = f"git+{head_sha}"
            print(f"No tags found for {repoName}, using HEAD commit: {version}")

            # 태그 날짜 대신 HEAD 커밋 날짜 기록
            with open(os.path.join(tagDatePath, repoName), 'w') as tag_date_file:
                tag_date_file.write(f"{head_date} (commit: {head_sha})\n")

            collect_and_save_metadata(repo_dir, repoName, version, component_type)

            submodules = refresh_repo_sidecar_and_submodules(repo, repo_dir, repoName)
            resDict, funcMeta, fileCnt, funcCnt, lineCnt = hashing(repo_dir, os.path.join(funcCodePath, repoName), repoName, head_sha[:8], submodules)
            if len(resDict) > 0:
                if not os.path.isdir(resultPath + repoName):
                    os.mkdir(resultPath + repoName)
                title = '\t'.join([repoName, str(fileCnt), str(funcCnt), str(lineCnt)])
                resultFilePath = resultPath + repoName + f'/fuzzy_{head_sha[:8]}.hidx'
                indexing(resDict, title, resultFilePath)
                write_function_meta_sidecar(repoName, head_sha[:8], funcMeta)

        # Remove the cloned repository from repo_src
        #shutil.rmtree(repo_dir)
        print(f"{repoName} is finished")

    except git.exc.GitCommandError as e:
        print(f"[!] Git error for {repoName}: {e}")
        repo_dir = os.path.join(clonePath, repoName)
        if os.path.isdir(repo_dir):
            shutil.rmtree(repo_dir, ignore_errors=True)
    except Exception as e:
        print(f"[!] Unexpected error for {repoName}: {e}")

def main():
    with open(gitCloneURLS, 'r', encoding="UTF-8", errors='ignore') as fp:
        funcDateDict = {}
        lines = [l.strip('\n\r') for l in fp.readlines()]

    repo_entries = []
    for line in lines:
        parsed = parse_sample_line(line)
        if not parsed:
            continue
        repo_entries.append(parsed)

    # Use ThreadPoolExecutor to process repositories in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(process_repo, url, component_type, requested_tags)
            for url, component_type, requested_tags in repo_entries
        ]
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"An error occurred: {e}")


""" EXECUTE """
if __name__ == "__main__":
    main()
