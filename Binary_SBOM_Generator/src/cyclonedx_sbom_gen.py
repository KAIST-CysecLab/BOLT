from __future__ import annotations
import json
import os
import re
import sys
import hashlib
import argparse
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from uuid import uuid4
from typing import Dict, List, Optional, Any, Tuple

SPEC_VERSION = "1.5"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_components_json(path: Optional[Path]) -> List[Dict[str, Any]]:
    if not path:
        return []
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict):
        # Allow both dict with "components" key or plain list
        data = data.get("components", [])
    if not isinstance(data, list):
        raise ValueError("--components JSON must be a list or an object with 'components' list")
    return data


def safe_bom_ref(name: str, version: Optional[str]) -> str:
    base = f"lib:{name.strip()}"
    if version:
        base += f"@{version.strip()}"
    # Replace problematic characters with '-'
    return re.sub(r"[^A-Za-z0-9._:@+\-]", "-", base)


def guess_version_from_soname(soname: str) -> Optional[str]:
    # e.g., "libssl.so.1.1" -> "1.1"
    m = re.search(r"\.so\.(\d[\w\.]*)$", soname)
    if m:
        return m.group(1)
    # macOS: "libssl.1.1.dylib" -> "1.1"
    m = re.search(r"\.(\d[\w\.]*)\.dylib$", soname)
    if m:
        return m.group(1)
    return None


def normalize_component(entry: Dict[str, Any]) -> Dict[str, Any]:
    name = entry.get("name")
    if not name:
        raise ValueError("Component missing required field: 'name'")
    version = entry.get("version")
    bom_ref = entry.get("bom-ref") or safe_bom_ref(name, version)

    _type = entry.get("type", "library")
    comp: Dict[str, Any] = {
        "bom-ref": bom_ref,
        "type": _type,
        "name": name,
    }
    if version:
        comp["version"] = str(version)

    if "purl" in entry and entry["purl"]:
        comp["purl"] = entry["purl"]

    # Preserve supplied identity and evidence for vulnerability matching.
    # Neither field can be reconstructed safely from the component name alone.
    if "cpe" in entry and entry["cpe"]:
        comp["cpe"] = entry["cpe"]
    if "evidence" in entry:
        comp["evidence"] = entry["evidence"]

    # Licenses: accept ["MIT"] or [{"license":{"id":"MIT"}}] or {"expression": ...}
    licenses = entry.get("licenses")
    if isinstance(licenses, list):
        lic_objs = []
        for lic in licenses:
            if isinstance(lic, str):
                lic_objs.append({"license": {"id": lic}})
            elif isinstance(lic, dict):
                # allow {"license":{"id":"MIT"}} or {"expression":"MIT OR Apache-2.0"}
                if "license" in lic or "expression" in lic:
                    lic_objs.append(lic)
        if lic_objs:
            comp["licenses"] = lic_objs
    elif isinstance(licenses, dict):
        comp["licenses"] = [licenses]

    if "hashes" in entry:
        comp["hashes"] = entry["hashes"]

    if "properties" in entry:
        comp["properties"] = entry["properties"]

    if "externalReferences" in entry:
        comp["externalReferences"] = entry["externalReferences"]

    return comp


def detect_binary_info(path: Path) -> Dict[str, str]:
    """
    Returns binary info: kind, arch, os, pie status.
    """
    info = {
        "kind": "unknown",
        "arch": "unknown",
        "os": "unknown",
        "pie": "unknown"
    }

    with open(path, "rb") as f:
        hdr = f.read(0x1000)

    # ELF
    if hdr[:4] == b"\x7fELF":
        ei_class = hdr[4]  # 1 = 32-bit, 2 = 64-bit
        ei_data = hdr[5]   # 1 = little endian, 2 = big endian
        ei_osabi = hdr[7]  # OS/ABI
        byte_order = "little" if ei_data == 1 else "big"

        info["kind"] = "ELF64" if ei_class == 2 else "ELF32"

        # e_type at offset 16 (2 bytes)
        e_type = int.from_bytes(hdr[16:18], byte_order)
        if e_type == 2:  # ET_EXEC
            info["pie"] = "no-pie"
        elif e_type == 3:  # ET_DYN (PIE or shared lib)
            info["pie"] = "pie"

        # e_machine at offset 18 (2 bytes)
        e_machine = int.from_bytes(hdr[18:20], byte_order)
        arch_map = {
            0x03: "i386",
            0x3E: "x86_64",
            0x28: "arm",
            0xB7: "aarch64",
            0xF3: "riscv",
        }
        info["arch"] = arch_map.get(e_machine, f"0x{e_machine:x}")

        # OS from EI_OSABI
        osabi_map = {
            0x00: "linux",  # ELFOSABI_NONE/SYSV (commonly Linux)
            0x03: "linux",  # ELFOSABI_LINUX
            0x09: "freebsd",
            0x0C: "openbsd",
        }
        info["os"] = osabi_map.get(ei_osabi, "linux")  # Default to linux for ELF

        return info

    # PE (Windows)
    if hdr[:2] == b"MZ":
        info["os"] = "windows"
        if len(hdr) >= 0x3C + 4:
            pe_offset = int.from_bytes(hdr[0x3C:0x40], "little", signed=False)
            if pe_offset + 6 < len(hdr) and hdr[pe_offset:pe_offset+4] == b"PE\x00\x00":
                machine = int.from_bytes(hdr[pe_offset+4:pe_offset+6], "little", signed=False)
                if machine == 0x8664:
                    info["kind"] = "PE32+"
                    info["arch"] = "x86_64"
                elif machine == 0x14c:
                    info["kind"] = "PE32"
                    info["arch"] = "i386"
                else:
                    info["kind"] = "PE"
        else:
            info["kind"] = "PE"
        return info

    # Mach-O (macOS)
    mach_magics = {
        0xfeedface: ("Mach-O", "i386"),
        0xfeedfacf: ("Mach-O 64", "x86_64"),
        0xcefaedfe: ("Mach-O (BE)", "ppc"),
        0xcffaedfe: ("Mach-O 64 (BE)", "ppc64"),
        0xcafebabe: ("Mach-O (Fat)", "universal"),
        0xbebafeca: ("Mach-O (Fat BE)", "universal"),
    }
    if len(hdr) >= 4:
        magic = int.from_bytes(hdr[:4], "big", signed=False)
        if magic in mach_magics:
            info["kind"], info["arch"] = mach_magics[magic]
            info["os"] = "macos"
            return info

    return info


def run_ldd(binary: Path) -> List[Tuple[str, str]]:
    """
    Linux: returns list of (soname, fullpath|None).
    """
    try:
        out = subprocess.check_output(["ldd", str(binary)], stderr=subprocess.STDOUT, text=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        return []
    deps: List[Tuple[str, str]] = []
    # Example lines:
    #   libssl.so.1.1 => /lib/x86_64-linux-gnu/libssl.so.1.1 (0x00007f...)
    #   libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f...)
    #   linux-vdso.so.1 (0x00007fff...)
    for line in out.splitlines():
        line = line.strip()
        if "=>" in line:
            left, right = [x.strip() for x in line.split("=>", 1)]
            soname = left.split()[0]
            path = right.split()[0] if right and right != "not found" else None
            deps.append((soname, path))
        else:
            # e.g., "linux-vdso.so.1 (0x...)"
            m = re.match(r"^(\S+)\s+\(", line)
            if m:
                soname = m.group(1)
                deps.append((soname, None))
    return deps


def run_otool(binary: Path) -> List[Tuple[str, str]]:
    """
    macOS: returns list of (soname, fullpath|None).
    """
    try:
        out = subprocess.check_output(["otool", "-L", str(binary)], stderr=subprocess.STDOUT, text=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        return []
    lines = out.splitlines()
    if not lines:
        return []
    deps: List[Tuple[str, str]] = []
    # First line is the binary path, skip it
    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue
        # Example: /usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1311.100.3)
        path = line.split(" (", 1)[0].strip()
        soname = os.path.basename(path)
        deps.append((soname, path))
    return deps



def merge_components(*lists: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: Dict[str, Dict[str, Any]] = {}
    for lst in lists:
        for entry in lst:
            norm = normalize_component(entry)
            key = norm["bom-ref"]
            if key not in merged:
                merged[key] = norm
            else:
                # merge fields conservatively; do not overwrite existing non-empty
                for k, v in norm.items():
                    if k not in merged[key] or not merged[key][k]:
                        merged[key][k] = v
                    elif k == "properties":
                        # concatenate unique properties
                        existing = merged[key].setdefault("properties", [])
                        existing_names = {(p.get("name"), p.get("value")) for p in existing}
                        for p in v:
                            pair = (p.get("name"), p.get("value"))
                            if pair not in existing_names:
                                existing.append(p)
                    elif k == "licenses":
                        existing_licenses = merged[key].setdefault("licenses", [])
                        # naive de-dup
                        existing_licenses_json = {json.dumps(x, sort_keys=True) for x in existing_licenses}
                        for lic in v:
                            s = json.dumps(lic, sort_keys=True)
                            if s not in existing_licenses_json:
                                existing_licenses.append(lic)
    return list(merged.values())


# --------------------------- SBOM Builder --------------------------

def build_bom(binary: Path,
              root_name: Optional[str],
              root_version: Optional[str],
              supplier: Optional[str],
              user_components_path: Optional[Path],
              use_autodiscover: bool,
              display_path: Optional[str] = None) -> Dict[str, Any]:
    if not binary.exists():
        raise FileNotFoundError(f"Binary not found: {binary}")

    # display_path lets callers that analyze a copy (e.g. a file extracted from a
    # container image) report the original location instead of the scratch path.
    reported_path = display_path or str(binary)
    root_name = root_name or Path(reported_path).name
    sha256 = sha256_file(binary)
    binary_info = detect_binary_info(binary)

    # Print binary information
    print(f"    [*] Binary information:")
    print(f"        - File type: {binary_info['kind']}")
    print(f"        - Architecture: {binary_info['arch']}")
    print(f"        - OS: {binary_info['os']}")
    print(f"        - PIE: {binary_info['pie']}")
    print(f"        - SHA-256: {sha256[:16]}...")

    user_components = read_components_json(user_components_path)
    components = merge_components(user_components)

    # Print component information
    print(f"    [*] Loaded {len(components)} component(s) from components file")
    for comp in components:
        comp_name = comp.get("name", "unknown")
        comp_ver = comp.get("version", "N/A")
        print(f"        - {comp_name} @ {comp_ver}")

    # Get dynamic libraries from ldd (only include libs with actual file path, exclude vdso/ld-linux)
    # Gated on --ldd: these refs land in dependsOn without matching components, and
    # ldd resolves against the host, which is wrong when the binary came from an image.
    dynamic_libs = []
    if use_autodiscover:
        dynamic_libs = run_ldd(binary) if sys.platform.startswith("linux") else run_otool(binary) if sys.platform == "darwin" else []
    dynamic_lib_refs = [safe_bom_ref(soname, None) for soname, fullpath in dynamic_libs if fullpath]

    # Print dynamic library information
    if use_autodiscover and dynamic_libs:
        actual_libs = [(soname, path) for soname, path in dynamic_libs if path]
        print(f"    [*] Discovered {len(actual_libs)} dynamic libraries (ldd):")
        for soname, fullpath in actual_libs[:5]:  # Show first 5
            print(f"        - {soname}")
        if len(actual_libs) > 5:
            print(f"        - ... and {len(actual_libs) - 5} more")

    # Metadata + subject component
    subject_bom_ref = f"app:{root_name}" + (f"@{root_version}" if root_version else "")
    metadata_component = {
        "bom-ref": subject_bom_ref,
        "type": "application",
        "name": root_name,
    }
    if root_version:
        metadata_component["version"] = str(root_version)

    metadata_component["hashes"] = [
        {"alg": "SHA-256", "content": sha256}
    ]
    metadata_component["properties"] = [
        {"name": "analysis:scope", "value": "binary-only:static"},
        {"name": "binary:file:type", "value": binary_info["kind"]},
        {"name": "binary:file:path", "value": reported_path},
        {"name": "build:target:arch", "value": binary_info["arch"]},
        {"name": "build:target:os", "value": binary_info["os"]},
        {"name": "binary:pie", "value": binary_info["pie"]},
    ]
    if supplier:
        metadata_component["supplier"] = {"name": supplier}

    bom: Dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "tools": [
                {"vendor": "Software Security and Privacy Laboratory @ Korea University", "name": "SBridge-SBOM", "version": "0.1"}
            ],
            "component": metadata_component
        },
        "components": components,
        "dependencies": [
            {
                "ref": subject_bom_ref,
                "dependsOn": (
                    [c["bom-ref"] for c in components if c.get("type") == "library"] + dynamic_lib_refs
                ) if components or dynamic_lib_refs else []
            }
        ],
    }
    return bom


def main(argv: Optional[List[str]] = None) -> int:
    # Get script directory for output path
    script_dir = Path(__file__).resolve().parent

    p = argparse.ArgumentParser(description="Generate CycloneDX SBOM (JSON) for a binary.")
    p.add_argument("binary", help="Path to the binary")
    p.add_argument("components", help="Path to components JSON")
    p.add_argument("--ldd", action="store_true", help="Auto-discover shared libs.")
    p.add_argument("--display-path", help="Report this path for the binary instead of its actual location.")
    args = p.parse_args(argv)

    binary_path = Path(args.binary).resolve()
    comps_path = Path(args.components).resolve() if args.components else None

    # Auto-generate output path: output/{binary_name}-sbom.json
    output_dir = script_dir.parent / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    binary_name = binary_path.stem  # filename without extension
    output_path = output_dir / f"{binary_name}-sbom.json"

    bom = build_bom(
        binary=binary_path,
        root_name=None,
        root_version=None,
        supplier=None,
        user_components_path=comps_path,
        use_autodiscover=args.ldd,
        display_path=args.display_path
    )

    out_json = json.dumps(bom, indent=2, ensure_ascii=False)
    output_path.write_text(out_json, encoding="utf-8")
    print(f"SBOM generated: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
