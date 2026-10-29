import argparse
import os
import subprocess
import sys
import shutil
import glob
import json
import io
import signal
import re
from pathlib import Path


# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))

from utils.function_preprocessing import CBMaker

currentPath	= os.getcwd()
TargetBinaryPath = currentPath + "/testset/bin"
TargetOutputPath = currentPath + "/testset"
GHIDRA_PATH = currentPath + "/tools/ghidra/ghidra_11.2.1_PUBLIC"
PROJECT_DIR = currentPath + "/tools/ghidra/ghidra_project"
PROJECT_NAME = "temp_proj"
SCRIPT_PATH = currentPath + "/src/utils/decomplie_ghidra.py"

FORMAT_PATTERN = re.compile(r"^%[-+0 #]*(\d+|\*)?(\.(\d+|\*))?[hlLzjt]*[diouxXeEfFgGaAcspn%]$")
FORMAT_ONLY_PATTERN = re.compile(r"^[\s%\-+0-9.#hlLzjtdiouxXeEfFgGaAcspn\[\]\(\)\{\}:,'\"\ntr]*$")
PATH_PATTERN = re.compile(r"^([a-zA-Z]:)?[\\/][^\s]+")
GENERATED_SYMBOL_PATTERN = re.compile(r"^(FUN|SUB|sub|func|Func|loc|LAB|LAB_|unk|UNK)_[0-9A-Fa-f]+$")
UNSUPPORTED_SYMBOLS = {"", "entry", "_start", "__libc_start_main", "main", "usage"}


def normalize_binary_function_name(func_name, thunk_name_map=None):
    if not isinstance(func_name, str):
        return func_name
    normalized = func_name.strip()
    if thunk_name_map:
        if normalized in thunk_name_map:
            return thunk_name_map[normalized]
        while normalized.startswith("thunk_"):
            normalized = normalized[len("thunk_") :]
            if normalized in thunk_name_map:
                return thunk_name_map[normalized]
        return normalized
    while normalized.startswith("thunk_"):
        normalized = normalized[len("thunk_") :]
    return normalized


def normalize_function_name_mapping(hash_to_name, thunk_name_map=None):
    return {
        func_hash: normalize_binary_function_name(func_name, thunk_name_map)
        for func_hash, func_name in hash_to_name.items()
    }


def normalize_function_name_list(func_names, thunk_name_map=None):
    normalized = []
    seen = set()
    for func_name in func_names:
        normalized_name = normalize_binary_function_name(func_name, thunk_name_map)
        if not normalized_name or normalized_name in seen:
            continue
        seen.add(normalized_name)
        normalized.append(normalized_name)
    return normalized


def normalize_control_blocks(blocks, thunk_name_map=None):
    changed = False
    if not isinstance(blocks, list):
        return blocks, changed

    for block in blocks:
        if not isinstance(block, dict):
            continue
        for field_name in ("key_feature_dvector", "block_content_dvector"):
            dvector = block.get(field_name)
            if not isinstance(dvector, dict):
                continue
            raw_values = dvector.get("function_values")
            if not isinstance(raw_values, list):
                continue
            normalized_values = []
            for raw_name in raw_values:
                normalized_name = normalize_binary_function_name(raw_name, thunk_name_map)
                if normalized_name != raw_name:
                    changed = True
                normalized_values.append(normalized_name)
            dvector["function_values"] = normalized_values
    return blocks, changed


def load_thunk_name_map(binary_name):
    thunk_map_path = Path(TargetOutputPath) / binary_name / "thunk_map.json"
    if not thunk_map_path.exists():
        return {}
    try:
        with open(thunk_map_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except Exception:
        return {}
    return {}


def normalize_text(text):
    return (
        text.replace("\\n", "")
        .replace("\\r", "")
        .replace("\\t", "")
        .replace("\n", "")
        .replace("\r", "")
        .replace("\t", "")
        .replace("{", "")
        .replace("}", "")
        .replace(" ", "")
        .replace("\\", "")
        .replace("'", "")
        .lower()
    )


def is_discriminative_string(s):
    if not s or len(s) < 4:
        return False
    if PATH_PATTERN.match(s):
        return False
    if FORMAT_PATTERN.match(s):
        return False
    if FORMAT_ONLY_PATTERN.match(s) and "%" in s:
        return False
    return True


def classify_symbol_kind(func_name, thunk_name_map=None):
    if not isinstance(func_name, str):
        return "unsupported"
    normalized = normalize_binary_function_name(func_name, thunk_name_map)
    if normalized in UNSUPPORTED_SYMBOLS:
        return "unsupported"
    if GENERATED_SYMBOL_PATTERN.match(normalized):
        return "generated"
    if thunk_name_map and func_name in thunk_name_map and thunk_name_map[func_name] != func_name:
        return "thunk_normalized"
    return "real"


def extract_callstr_tokens_from_blocks(blocks, filter_discriminative=False):
    tokens = set()
    for block in blocks:
        if not isinstance(block, dict):
            continue
        if block.get("block_type", "") != "String":
            continue

        raw_strings = block.get("key_feature_dvector", {}).get("literal_values", [])
        caller = (
            block.get("block_content_dvector", {})
            .get("function_values", ["assign"])[0]
            if isinstance(block.get("block_content_dvector", {}), dict)
            else "assign"
        )
        caller = normalize_binary_function_name(caller)

        for lit_text in raw_strings:
            if not isinstance(lit_text, str):
                continue
            if filter_discriminative and not is_discriminative_string(lit_text):
                continue
            norm = normalize_text(lit_text)
            if not norm:
                continue

            if caller == "assign":
                tokens.add(f"ASSIGNSTR:{norm}")
            elif caller == "callfunc":
                tokens.add(f"CALLSTR:{norm}")
            else:
                tokens.add(f"LIBCALLSTR:{caller}:{norm}")
    return tokens


def build_headless_command(ghidra_install_dir, project_dir, project_name, binary_path, script_path):
    analyze_headless = os.path.join(ghidra_install_dir, "support", "analyzeHeadless")
    if not os.path.exists(analyze_headless):
        raise FileNotFoundError("analyzeHeadless not found under {}".format(ghidra_install_dir))

    # Ensure paths are absolute
    project_dir = os.path.abspath(project_dir)
    binary_path = os.path.abspath(binary_path)
    script_path = os.path.abspath(script_path)

    cmd = [
        analyze_headless,
        project_dir,
        project_name,
        "-import", binary_path,
        "-scriptPath", os.path.dirname(script_path),
        "-postScript", os.path.basename(script_path),
        "-deleteProject"
    ]
    return cmd


def clean_ghidra_project():


    # Delete .rep folder, .gpr and .lock files
    project_rep = os.path.join(PROJECT_DIR, "{}.rep".format(PROJECT_NAME))
    project_gpr = os.path.join(PROJECT_DIR, "{}.gpr".format(PROJECT_NAME))
    project_lock = os.path.join(PROJECT_DIR, "{}.lock".format(PROJECT_NAME))

    for path in [project_rep, project_gpr, project_lock]:
        if os.path.exists(path):
            try:
                if os.path.isdir(path):
                    shutil.rmtree(path)
                else:
                    os.remove(path)
                print("Removed: {}".format(path))
            except Exception as e:
                print("Warning: Failed to remove {}: {}".format(path, e))


class TimeoutException(Exception):
    pass


def timeout_handler(signum, frame):
    """Timeout signal handler"""
    raise TimeoutException("Processing timeout")


def process_func_file_to_controlblock(func_file_path, output_json_path, timeout_seconds=60):
    old_stdout = sys.stdout
    old_stderr = sys.stderr
    old_handler = None
    binary_name = Path(output_json_path).resolve().parents[1].name
    thunk_name_map = load_thunk_name_map(binary_name)

    try:
        # Setup timeout (Linux/Unix only)
        old_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(timeout_seconds)

        # Analyze with CBMaker (C language)
        try:
            analyzer = CBMaker(language='c')
        except Exception as e:
            signal.alarm(0)
            if old_handler:
                signal.signal(signal.SIGALRM, old_handler)
            return (False, "CBMaker initialization failed: {}".format(str(e)))

        # Suppress output (both stdout and stderr)
        sys.stdout = io.StringIO()
        sys.stderr = io.StringIO()

        error_output = None
        callees = []
        try:
            func_name, callees = analyzer.analyze_file(func_file_path, output_json_path)
        except KeyboardInterrupt:
            signal.alarm(0)
            sys.stdout = old_stdout
            sys.stderr = old_stderr
            if old_handler:
                signal.signal(signal.SIGALRM, old_handler)
            raise
        except TimeoutException:
            signal.alarm(0)
            sys.stdout = old_stdout
            sys.stderr = old_stderr
            if old_handler:
                signal.signal(signal.SIGALRM, old_handler)
            return (False, "Timeout after {} seconds".format(timeout_seconds), [])
        except Exception as e:
            signal.alarm(0)
            error_output = str(e)
            sys.stdout = old_stdout
            sys.stderr = old_stderr
            if old_handler:
                signal.signal(signal.SIGALRM, old_handler)
            return (False, "Analysis exception: {}".format(error_output), [])

        # Cancel timeout on successful completion
        signal.alarm(0)
        sys.stdout = old_stdout
        sys.stderr = old_stderr
        if old_handler:
            signal.signal(signal.SIGALRM, old_handler)

        # Check if JSON file is created and contains data
        if not Path(output_json_path).exists():
            return (False, "Output JSON file not created", callees)

        try:
            with open(output_json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            data, changed = normalize_control_blocks(data, thunk_name_map)
            if changed:
                with open(output_json_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
            return (True, None, normalize_function_name_list(callees, thunk_name_map))
        except json.JSONDecodeError as e:
            return (False, "Invalid JSON generated: {}".format(str(e)), normalize_function_name_list(callees, thunk_name_map))
        except Exception as e:
            return (False, "JSON validation error: {}".format(str(e)), normalize_function_name_list(callees, thunk_name_map))

    except KeyboardInterrupt:
        signal.alarm(0)
        sys.stdout = old_stdout
        sys.stderr = old_stderr
        if old_handler:
            signal.signal(signal.SIGALRM, old_handler)
        raise
    except Exception as e:
        signal.alarm(0)
        sys.stdout = old_stdout
        sys.stderr = old_stderr
        if old_handler:
            signal.signal(signal.SIGALRM, old_handler)
        return (False, "Unexpected error: {}".format(str(e)), callees)


def generate_control_blocks_for_binary(binary_name):
    """
    Convert decompiled functions to control blocks

    Args:
        binary_name: Binary file name

    Returns:
        (success_count, total_count) tuple
    """
    # Decompiled functions path
    decompile_dir = Path(TargetOutputPath) / binary_name / "decompliecode" / binary_name
    # Control block output path
    funcblock_dir = Path(TargetOutputPath) / binary_name / "func_blocks"
    # Callgraph output path
    callgraph_path = Path(TargetOutputPath) / binary_name / "callgraph.json"
    # Function Name Index path
    idx_file_path = Path(TargetOutputPath) / binary_name / "func_names.json"

    if not decompile_dir.exists():
        print("  [!] Decompiled functions directory not found: {}".format(decompile_dir))
        return 0, 0

    # Create output directory
    funcblock_dir.mkdir(parents=True, exist_ok=True)

    # Find all .c files
    func_files = list(decompile_dir.glob("*.c"))

    if not func_files:
        print("  [!] No decompiled .c files found in {}".format(decompile_dir))
        return 0, 0

    total_count = len(func_files)
    print("  [+] Converting {} functions to control blocks...".format(total_count))

    # Error log file
    error_log_path = funcblock_dir / "processing_errors.log"
    error_log_file = open(error_log_path, 'w', encoding='utf-8')
    error_log_file.write("Control Block Processing Errors for {}\n".format(binary_name))
    error_log_file.write("="*80 + "\n\n")

    success_count = 0
    failed_count = 0
    error_types = {}
    callgraph = {}

    with open(idx_file_path, 'r', encoding='utf-8') as f:
        thunk_name_map = load_thunk_name_map(binary_name)
        real_func_names = normalize_function_name_mapping(json.load(f), thunk_name_map)
    try:
        for i, func_file in enumerate(func_files, 1):
            func_name = func_file.stem  # Filename without extension
            output_json = funcblock_dir / "{}.json".format(func_name)

            # Skip already processed files
            if output_json.exists():
                try:
                    with open(output_json, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    data, changed = normalize_control_blocks(data, thunk_name_map)
                    if changed:
                        with open(output_json, "w", encoding="utf-8") as f:
                            json.dump(data, f, indent=2, ensure_ascii=False)
                    callees = []
                    for block in data:
                        if block.get("block_type") != "CalleeFunc":
                            continue
                        vector = block.get("key_feature_dvector", {})
                        callees.extend(vector.get("function_values", []))
                    callgraph[real_func_names.get(func_name, func_name)] = normalize_function_name_list(callees, thunk_name_map)
                except Exception:
                    callgraph[normalize_binary_function_name(func_name, thunk_name_map)] = []
                success_count += 1
                continue
            # Generate control block
            success, error_msg, callees = process_func_file_to_controlblock(
                str(func_file),
                str(output_json),
                timeout_seconds=60
            )
            callgraph[real_func_names[func_name]] = normalize_function_name_list(callees, thunk_name_map)

            if success:
                success_count += 1
            else:
                failed_count += 1

                # Extract error type
                if "Timeout" in error_msg:
                    error_type = "Timeout"
                elif "Analysis exception" in error_msg:
                    error_type = "Analysis Exception"
                elif "Empty control blocks" in error_msg:
                    error_type = "Empty Blocks"
                elif "JSON" in error_msg:
                    error_type = "JSON Error"
                else:
                    error_type = "Other"

                error_types[error_type] = error_types.get(error_type, 0) + 1

                # Detailed error log
                error_log_file.write("[{}] {}\n  Reason: {}\n\n".format(
                    failed_count, func_file.name, error_msg))
                error_log_file.flush()

            # Show progress (every 100 items)
            if i % 100 == 0 or i == total_count:
                print("    Progress: {}/{} ({} successful, {} failed)".format(
                    i, total_count, success_count, failed_count))

        # Error statistics
        error_log_file.write("\n" + "="*80 + "\n")
        error_log_file.write("Error Statistics:\n")
        error_log_file.write("="*80 + "\n")
        error_log_file.write("Total Failed: {}\n".format(failed_count))
        for error_type, count in sorted(error_types.items(), key=lambda x: x[1], reverse=True):
            error_log_file.write("  - {}: {}\n".format(error_type, count))

        with open(callgraph_path, "w", encoding="utf-8") as f:
            json.dump(callgraph, f, indent=2, ensure_ascii=False)
        print(f"  [+] Callgraph saved: {callgraph_path}")

    finally:
        error_log_file.close()

    print("  [+] Control blocks: {}/{} functions successfully converted".format(
        success_count, total_count))

    return success_count, total_count


def extract_filtered_strings_from_blocks(blocks):
    strings = set()
    for block in blocks:
        if not isinstance(block, dict):
            continue
        if block.get("block_type", "") != "String":
            continue
        for value in block.get("key_feature_dvector", {}).get("literal_values", []):
            if isinstance(value, str) and is_discriminative_string(value):
                strings.add(value)
    return sorted(strings)


def load_binary_name_mapping(binary_name):
    func_names_path = Path(TargetOutputPath) / binary_name / "func_names.json"
    thunk_name_map = load_thunk_name_map(binary_name)
    if not func_names_path.exists():
        return {}, thunk_name_map
    try:
        with open(func_names_path, "r", encoding="utf-8") as f:
            return normalize_function_name_mapping(json.load(f), thunk_name_map), thunk_name_map
    except Exception:
        return {}, thunk_name_map


def write_binary_features(binary_name):
    funcblock_dir = Path(TargetOutputPath) / binary_name / "func_blocks"
    callgraph_path = Path(TargetOutputPath) / binary_name / "callgraph.json"
    output_path = Path(TargetOutputPath) / binary_name / "binary_features.json"
    hash_to_name, thunk_name_map = load_binary_name_mapping(binary_name)

    callgraph = {}
    if callgraph_path.exists():
        try:
            with open(callgraph_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                callgraph = {
                    normalize_binary_function_name(caller, thunk_name_map): normalize_function_name_list(callees, thunk_name_map)
                    for caller, callees in loaded.items()
                }
        except Exception:
            callgraph = {}

    functions = []
    for file_path in sorted(funcblock_dir.glob("*.json")):
        if file_path.name == "processing_errors.log":
            continue
        func_hash = file_path.stem
        func_name = hash_to_name.get(func_hash, normalize_binary_function_name(func_hash, thunk_name_map))
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                blocks = json.load(f)
        except Exception:
            blocks = []
        if not isinstance(blocks, list):
            blocks = []
        functions.append({
            "function_name": func_name,
            "symbol_kind": classify_symbol_kind(func_name, thunk_name_map),
            "control_blocks": blocks,
            "strings": extract_filtered_strings_from_blocks(blocks),
            "callstr_tokens": sorted(extract_callstr_tokens_from_blocks(blocks, True)),
            "callees": callgraph.get(func_name, []),
        })

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump({
            "binary": binary_name,
            "functions": functions,
            "callgraph": callgraph,
        }, f, indent=2, ensure_ascii=False)
    print(f"  [+] Binary features saved: {output_path}")
    print(f"      - Functions: {len(functions)}")

def process_binary(binary_path, binary_name):
    target_dir = os.path.join(TargetOutputPath, binary_name)
    output_dir = os.path.join(TargetOutputPath, binary_name, "decompliecode")
    decompile_dir = Path(output_dir) / binary_name
    has_decompiled_sources = decompile_dir.exists() and any(decompile_dir.glob("*.c"))

    os.makedirs(target_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)

    print("\n" + "="*80)
    print("Processing binary: {}".format(binary_name))
    print("="*80)
    print("Output directory: {}".format(output_dir))

    if has_decompiled_sources:
        func_count = len(list(decompile_dir.glob("*.c")))
        print("\n[Step 1/2] Reusing existing decompiled code...")
        print("  [+] Found {} decompiled functions at {}".format(func_count, decompile_dir))
    else:
        # Step 1: Ghidra decompilation
        print("\n[Step 1/2] Decompiling with Ghidra...")
        clean_ghidra_project()

        cmd = build_headless_command(
            ghidra_install_dir=GHIDRA_PATH,
            project_dir=PROJECT_DIR,
            project_name=PROJECT_NAME,
            binary_path=binary_path,
            script_path=SCRIPT_PATH
        )

        try:
            print("Running:", " ".join(cmd))
            completed = subprocess.run(cmd, text=True)

            if completed.returncode != 0:
                print("  [!] Ghidra decompilation failed")
                return False

            if decompile_dir.exists():
                func_count = len(list(decompile_dir.glob("*.c")))
                print("  [+] Decompiled {} functions".format(func_count))
            else:
                print("  [!] No functions were decompiled")
                return False

        except FileNotFoundError as e:
            print("Execution failed: {}".format(e), file=sys.stderr)
            return False

    print("\n[Step 2/2] Generating control blocks...")
    success_count, total_count = generate_control_blocks_for_binary(binary_name)

    if success_count == 0:
        print("  [!] No control blocks were generated")
        return False

    write_binary_features(binary_name)

    print("\n" + "="*80)
    print("Successfully processed: {}".format(binary_name))
    print("  - Decompiled functions: {}".format(total_count))
    print("  - Control blocks generated: {}".format(success_count))
    print("="*80)

    return True


def main():
    parser = argparse.ArgumentParser(description="Preprocess binaries: decompile → CB")
    parser.parse_args()

    if not os.path.exists(TargetBinaryPath):
        print("Target binary path does not exist: {}".format(TargetBinaryPath), file=sys.stderr)
        sys.exit(1)

    binary_files = []
    for filename in os.listdir(TargetBinaryPath):
        filepath = os.path.join(TargetBinaryPath, filename)
        if os.path.isfile(filepath):
            binary_files.append((filepath, filename))

    if not binary_files:
        print("No binary files found in: {}".format(TargetBinaryPath), file=sys.stderr)
        sys.exit(1)

    success_count = 0
    fail_count = 0

    for binary_path, binary_name in binary_files:
        if process_binary(binary_path, binary_name):
            success_count += 1
        else:
            fail_count += 1
            print("\n[!] Failed to process: {}".format(binary_name), file=sys.stderr)

    print("\n\n" + "="*80)

    if fail_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
