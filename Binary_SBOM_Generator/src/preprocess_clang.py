import os
import re
import subprocess


def generate_clang_command(file_path, root_path):

    if file_path.endswith((".cpp", ".cc", ".hpp", ".hxx")):
        lang = "c++"
    else:
        lang = "c"

    return [
        "clang",
        "-E",
        "-P",
        "-x", lang,
        "-Ilib",
        "-Isrc",
        f"-I{root_path}",
        "-o", file_path + ".i",
        file_path
    ]


def process_files_in_directory(root_path):
    possible_exts = (".c", ".cc", ".cpp", ".hpp", ".hxx", ".h")
    for dirpath, _, filenames in os.walk(root_path):
        for filename in filenames:
            if not filename.endswith(possible_exts):
                continue
            file_path = os.path.join(dirpath, filename)
            output_file = file_path + '.i'

            if os.path.exists(output_file):
                # Already preprocessed
                continue

            clang_command = generate_clang_command(file_path, root_path)
            try:
                completed = subprocess.run(
                    clang_command,
                    check=False,
                    capture_output=True,
                    text=True,
                )
                if completed.returncode != 0:
                    # Preprocessing failed for this file; skip silently
                    continue
            except Exception:
                # Unexpected error; skip this file
                continue
