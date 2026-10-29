#!/usr/bin/env python3
import argparse
import json
import os
import re
from typing import Dict, List, Set, Tuple

currentPath = os.getcwd()
OUTPUT_DIR = currentPath + "/output"
BIN_DIR = currentPath + "/testset/bin"
TPL_GT_PATH = currentPath + "/testset/ground_truth.json"
CB_DIR = currentPath + "/database/componentDB/control_blocks"

BINARY_NAME_RE = re.compile(r"^(.*)_(x64|x86|arm64|arm32)_(O0|O2)$")


def _build_tail_to_stem() -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    if os.path.isdir(CB_DIR):
        for fn in os.listdir(CB_DIR):
            if not fn.endswith(".json"):
                continue
            stem = fn[:-5]
            mapping[stem.split("@@")[-1].lower()] = stem
    mapping["giflib"] = "p@@giflib@@code"
    return mapping


TAIL_TO_STEM = _build_tail_to_stem()


def canon(name: str) -> str:
    key = name.lower()
    if "@@" in key:
        return key
    return TAIL_TO_STEM.get(key, key).lower()


def parse_binary_name(binary_name: str) -> Tuple[str, str, str]:
    match = BINARY_NAME_RE.match(binary_name)
    if not match:
        return binary_name, None, None
    return match.group(1), match.group(2), match.group(3)


def load_detected(binary_name: str) -> Set[str]:
    path = os.path.join(OUTPUT_DIR, binary_name, f"{binary_name}.components.json")
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        items = json.load(f)
    return {canon(item["name"]) for item in items}


def target_binaries(explicit: List[str]) -> List[str]:
    if explicit:
        return explicit
    if not os.path.isdir(BIN_DIR):
        return []
    return sorted(os.listdir(BIN_DIR))


def score(gt: Set[str], detected: Set[str]) -> Dict:
    tp = detected & gt
    fp = detected - gt
    fn = gt - detected
    precision = len(tp) / len(detected) if detected else (1.0 if not gt else 0.0)
    recall = len(tp) / len(gt) if gt else (1.0 if not detected else 0.0)
    return {
        "tp": sorted(tp), "fp": sorted(fp), "fn": sorted(fn),
        "precision": precision, "recall": recall,
    }


def print_breakdown(rows: List[Dict], title: str, key: str) -> None:
    print("-" * 78)
    print(title)
    by_key: Dict[str, Dict[str, int]] = {}
    for r in rows:
        agg = by_key.setdefault(r[key], {"tp": 0, "fp": 0, "fn": 0})
        agg["tp"] += len(r["tp"])
        agg["fp"] += len(r["fp"])
        agg["fn"] += len(r["fn"])
    for group in sorted(by_key):
        tp, fp, fn = by_key[group]["tp"], by_key[group]["fp"], by_key[group]["fn"]
        p = tp / (tp + fp) if (tp + fp) else (1.0 if not fn else 0.0)
        r_ = tp / (tp + fn) if (tp + fn) else (1.0 if not fp else 0.0)
        print(f"  {group:25s} Precision={p:.3f}  Recall={r_:.3f}  (TP={tp}, FP={fp}, FN={fn})")


def main() -> None:
    parser = argparse.ArgumentParser(description="Score detector.py output against ground truth.")
    parser.add_argument("binaries", nargs="*", help="Specific binary names to score. Defaults to all under testset/bin.")
    parser.add_argument("--json", dest="json_out", default=None, help="Optional path to dump a machine-readable JSON report.")
    args = parser.parse_args()

    with open(TPL_GT_PATH, "r", encoding="utf-8") as f:
        tpl_gt_raw = json.load(f)
    tpl_gt = {binary: {canon(c) for c in comps} for binary, comps in tpl_gt_raw.items()}

    rows = []
    no_groundtruth = []
    missing_output = []

    for binary_name in target_binaries(args.binaries):
        family, arch, opt = parse_binary_name(binary_name)
        if binary_name not in tpl_gt:
            no_groundtruth.append(binary_name)
            continue
        detected = load_detected(binary_name)
        if detected is None:
            missing_output.append(binary_name)
            continue
        gt = tpl_gt[binary_name]
        result = score(gt, detected)
        rows.append({"binary": binary_name, "family": family, "arch": arch, "opt": opt,
                      "gt": sorted(gt), "detected": sorted(detected), **result})

    tp_sum = sum(len(r["tp"]) for r in rows)
    fp_sum = sum(len(r["fp"]) for r in rows)
    fn_sum = sum(len(r["fn"]) for r in rows)
    precision = tp_sum / (tp_sum + fp_sum) if (tp_sum + fp_sum) else 0.0
    recall = tp_sum / (tp_sum + fn_sum) if (tp_sum + fn_sum) else 0.0

    print("=" * 78)
    print("Detector vs. Ground-Truth Report")
    print("=" * 78)
    for r in sorted(rows, key=lambda x: x["binary"]):
        n_tp, n_gt, n_detected = len(r["tp"]), len(r["gt"]), len(r["detected"])
        print(f"[*] {r['binary']:35s} GT {n_tp}/{n_gt}  Detected {n_tp}/{n_detected}"
              f"  FP={r['fp']}  FN={r['fn']}")

    print_breakdown(rows, "Per-program Precision / Recall", "family")
    print_breakdown(rows, "Per-architecture Precision / Recall", "arch")
    print_breakdown(rows, "Per-optimization Precision / Recall", "opt")

    print("-" * 78)
    print(f"Overall Precision : {precision:.3f}  (TP={tp_sum}, FP={fp_sum})")
    print(f"Overall Recall    : {recall:.3f}  (TP={tp_sum}, FN={fn_sum})")
    if missing_output:
        print(f"\nNo detector output ({len(missing_output)}): {missing_output}")
    if no_groundtruth:
        print(f"\nNo ground truth ({len(no_groundtruth)}): {no_groundtruth}")

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump({
                "rows": rows,
                "summary": {"precision": precision, "recall": recall},
                "missing_output": missing_output,
                "no_groundtruth": no_groundtruth,
            }, f, indent=2)
        print(f"\n[*] JSON report written to {args.json_out}")


if __name__ == "__main__":
    main()
