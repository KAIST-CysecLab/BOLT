from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import os
import json
import codecs
import sys
import re
import hashlib

script_dir = os.path.dirname(os.path.abspath(__file__))
config_path = os.path.join(script_dir, 'config.json')
with open(config_path, 'r') as config_file:
    config = json.load(config_file)

def normalize_path(path):
    if path.startswith('~'):
        return os.path.expanduser(path)
    return os.path.abspath(path)


def normalize_binary_function_name(func_name):
    if not isinstance(func_name, str):
        return func_name
    normalized = func_name.strip()
    while normalized.startswith("thunk_"):
        normalized = normalized[len("thunk_") :]
    return normalized


def sanitize_ghidra_function_name(func_name):
    func_name = func_name.split(".")[0]
    func_name = func_name.split("<")[0]
    return func_name.strip()


def resolve_function_name(function):
    raw_name = sanitize_ghidra_function_name(function.getName())
    if not function.isThunk():
        return normalize_binary_function_name(raw_name), None

    target = None
    try:
        target = function.getThunkedFunction(True)
    except TypeError:
        try:
            target = function.getThunkedFunction(False)
        except Exception:
            target = None
    except Exception:
        target = None

    if target is not None:
        target_name = normalize_binary_function_name(sanitize_ghidra_function_name(target.getName()))
        return target_name, (raw_name, target_name)
    return normalize_binary_function_name(raw_name), None

INPUT_PATH = normalize_path(config['input_path'])
DETAIL_PATH = os.path.join(INPUT_PATH, "decompliecode")

def get_output_filenames():
    program_name = currentProgram.getDomainFile().getName()
    base_name = program_name
    return os.path.join(DETAIL_PATH, base_name)

def decompile_functions():
    monitor = ConsoleTaskMonitor()
    decompInterface = DecompInterface()

    if not decompInterface.openProgram(currentProgram):
        print("Failed to initialize DecompInterface.")
        return

    function_manager = currentProgram.getFunctionManager()
    functions = list(function_manager.getFunctions(True))

    details_dir = get_output_filenames()
    if not os.path.exists(details_dir):
        os.makedirs(details_dir)

    func_names = {}
    thunk_map = {}
    for function in functions:
        func_name, thunk_info = resolve_function_name(function)
        if thunk_info is not None:
            thunk_raw_name, thunk_target_name = thunk_info
            thunk_map[thunk_raw_name] = thunk_target_name
        hash_name = hashlib.sha256(func_name).hexdigest()
        func_names[hash_name] = func_name
        if not func_name:
            continue
        if function.isThunk():
            continue
        if func_name == 'entry' or func_name == '_start': # or func_name.startswith('_'):
            continue

        result = decompInterface.decompileFunction(function, 30, monitor)
        if not result.decompileCompleted():
            print("Decompilation error for function {}: {}".format(func_name, result.errorMessage))
            continue

        decompiled_func = result.getDecompiledFunction().getC()

        lines = decompiled_func.split('\n')
        start_idx = 0
        for i, line in enumerate(lines):
            line_strip = line.strip()
            if (not line_strip.startswith('/*') and
                not line_strip.startswith('//') and
                not line_strip == ''):
                start_idx = i
                break

        decompiled_func = '\n'.join(lines[start_idx:])

        func_file_path = os.path.join(details_dir, "{}.c".format(hash_name))
        with codecs.open(func_file_path, 'w', 'utf-8') as f:
            f.write(decompiled_func)
    idx_file_path = os.path.join(INPUT_PATH, "func_names.json")
    with codecs.open(idx_file_path, 'w', 'utf-8') as f:
        json.dump(func_names, f, indent=2, ensure_ascii=False)
    thunk_map_path = os.path.join(INPUT_PATH, "thunk_map.json")
    with codecs.open(thunk_map_path, 'w', 'utf-8') as f:
        json.dump(thunk_map, f, indent=2, ensure_ascii=False)
decompile_functions()
