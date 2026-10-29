"""
Similarity measurement for ControlBlock matching
Uses pre-computed static vectors + dynamic extension
"""
import math
from typing import List, Dict, Tuple, Set

from .cb_vector import combined_vector_similarity, param_values_similarity


# Block similarity threshold
BLOCK_THRESHOLD = 0.7


def calculate_block_similarity(src_block: dict, bin_block: dict, is_second_pass: bool = False) -> float:
    src_type = src_block.get("block_type", "")
    bin_type = bin_block.get("block_type", "")

    if not is_second_pass:
        if src_type != bin_type:
            return 0.0
        return _first_pass_similarity(src_type, src_block, bin_type, bin_block)

    return _second_pass_similarity(src_type, src_block, bin_type, bin_block)


def _first_pass_similarity(src_type: str, src_block: dict, bin_type: str, bin_block: dict) -> float:
    if src_type in ("Condition", "Loop"):
        return _condition_loop_similarity(src_block, bin_block)
    if src_type == "String":
        return _string_similarity(src_block, bin_block)
    if src_type == "LibcFunc":
        return _libc_similarity(src_block, bin_block, is_second_pass=False)
    if src_type in ("CalleeFunc", "RecursiveFunc"):
        return _callee_similarity(src_block, bin_block, is_second_pass=False)
    if src_type == "Else":
        return _else_similarity(src_block, bin_block)
    return 0.0


def _second_pass_similarity(src_type: str, src_block: dict, bin_type: str, bin_block: dict) -> float:
    # Condition / Loop
    if src_type == "Condition":
        if bin_type in ("Condition", "Loop"):
            return _condition_loop_similarity(src_block, bin_block)
        if bin_type == "Else":
            return _else_similarity(src_block, bin_block)
        return 0.0
    if src_type == "Loop":
        if bin_type in ("Loop", "Condition"):
            return _condition_loop_similarity(src_block, bin_block)
        return 0.0

    # String
    if src_type == "String":
        return _string_similarity(src_block, bin_block) if bin_type == "String" else 0.0

    # LibcFunc
    if src_type == "LibcFunc":
        return _libc_similarity(src_block, bin_block, is_second_pass=True) if bin_type in ("LibcFunc", "CalleeFunc") else 0.0

    # CalleeFunc / RecursiveFunc
    if src_type in ("CalleeFunc", "RecursiveFunc"):
        return _callee_similarity(src_block, bin_block, is_second_pass=True) if bin_type in ("LibcFunc", "CalleeFunc") else 0.0

    # Else
    if src_type == "Else":
        return _else_similarity(src_block, bin_block) if bin_type in ("Else", "Condition") else 0.0

    return 0.0


def _key_feature_similarity(src_block: dict, bin_block: dict) -> float:
    return combined_vector_similarity(
        src_block.get("key_feature_vector", ""),
        src_block.get("key_feature_dvector", {}),
        bin_block.get("key_feature_vector", ""),
        bin_block.get("key_feature_dvector", {})
    )


def _block_content_similarity(src_block: dict, bin_block: dict) -> float:
    bin_vec = bin_block.get("block_content_vector", "")
    bin_dvec = bin_block.get("block_content_dvector", {})
    if not bin_vec and not bin_dvec:
        return 0.0

    return combined_vector_similarity(
        src_block.get("block_content_vector", ""),
        src_block.get("block_content_dvector", {}),
        bin_vec,
        bin_dvec
    )


def _condition_loop_similarity(src_block: dict, bin_block: dict) -> float:
    cond_sim = _key_feature_similarity(src_block, bin_block)
    if cond_sim == 1.0:
        return 1.0

    block_sim = _block_content_similarity(src_block, bin_block)

    if not src_block.get("block_content_vector", "") and not src_block.get("block_content_dvector", {}):
        return cond_sim

    return (cond_sim * 0.5) + (block_sim * 0.5)


def _string_similarity(src_block: dict, bin_block: dict) -> float:
    src_literals = src_block.get("key_feature_dvector", {}).get("literal_values", [])
    bin_literals = bin_block.get("key_feature_dvector", {}).get("literal_values", [])
    if not src_literals or not bin_literals:
        return 0.0
    return 1.0 if src_literals[0] == bin_literals[0] else 0.0


def _libc_similarity(src_block: dict, bin_block: dict, is_second_pass: bool) -> float:
    """
    LibcFunc 로직:
      - 첫 패스: 이름 동일 → 1.0
                 이름 다르고 param count 동일 → paramCheck
      - 두 번째 패스: 이름 동일 → 1.0
                     둘 다 param count 0 → 1.0
                     param count 동일 → paramCheck
    """
    src_kf = src_block.get("key_feature_dvector", {})
    bin_kf = bin_block.get("key_feature_dvector", {})

    src_func = (src_kf.get("function_values", []) or [""])[0]
    bin_func = (bin_kf.get("function_values", []) or [""])[0]
    src_params = (src_kf.get("param_numbers", []) or [0])[0]
    bin_params = (bin_kf.get("param_numbers", []) or [0])[0]

    if src_func == bin_func:
        return 1.0

    if is_second_pass and src_params == 0 and bin_params == 0:
        return 1.0

    if src_params == bin_params:
        if src_params == 0:
            return 1.0
        src_pv = src_block.get("block_content_dvector", {}).get("param_values", [])
        bin_pv = bin_block.get("block_content_dvector", {}).get("param_values", [])
        return param_values_similarity(src_pv, bin_pv)

    return 0.0


def _callee_similarity(src_block: dict, bin_block: dict, is_second_pass: bool) -> float:
    """
    CalleeFunc / RecursiveFunc 로직:
      - 첫 패스: 이름 동일 + param count 동일 → 1.0
                 이름 다르고 param count 동일 → paramCheck
      - 두 번째 패스: 이름 동일 + param count 동일 → 1.0
                     둘 다 param count 0 → 1.0
                     param count 동일 → paramCheck
    """
    src_kf = src_block.get("key_feature_dvector", {})
    bin_kf = bin_block.get("key_feature_dvector", {})

    src_func = (src_kf.get("function_values", []) or [""])[0]
    bin_func = (bin_kf.get("function_values", []) or [""])[0]
    src_params = (src_kf.get("param_numbers", []) or [0])[0]
    bin_params = (bin_kf.get("param_numbers", []) or [0])[0]

    if src_func == bin_func and src_params == bin_params:
        return 1.0

    if is_second_pass and src_params == 0 and bin_params == 0:
        return 1.0

    if src_params == bin_params:
        if src_params == 0:
            return 1.0
        src_pv = src_block.get("block_content_dvector", {}).get("param_values", [])
        bin_pv = bin_block.get("block_content_dvector", {}).get("param_values", [])
        return param_values_similarity(src_pv, bin_pv)

    return 0.0


def _else_similarity(src_block: dict, bin_block: dict) -> float:
    """F# trueBlockCheck: bin block_content 없으면 0"""
    return _block_content_similarity(src_block, bin_block)


def compare_functions(
    source_blocks: List[dict],
    binary_blocks: List[dict],
    check_length: bool = True,
    block_threshold: float = BLOCK_THRESHOLD
) -> float:
    total_source = len(source_blocks)
    if total_source == 0:
        return 0.0

    total_binary = len(binary_blocks)
    if total_binary == 0:
        return 0.0

    remaining = list(binary_blocks)
    matched_count = 0

    for src_block in source_blocks:
        if not remaining:
            break

        best_score = 0.0
        best_idx = -1

        for i, bin_block in enumerate(remaining):
            score = calculate_block_similarity(src_block, bin_block, is_second_pass=True)
            if score > best_score:
                best_score = score
                best_idx = i

        if best_score >= block_threshold:
            matched_count += 1
            remaining.pop(best_idx)

    if matched_count == 0:
        return 0.0

    matched_ratio = matched_count / total_source

    if check_length:
        length_weight = 1.0 / (math.log(1.0 + total_binary / total_source) + 1.0)
        return length_weight * matched_ratio

    return matched_ratio


def extract_string_features(blocks: List[dict]) -> Set[str]:
    features = set()
    for block in blocks:
        if block.get("block_type") == "String":
            literals = block.get("key_feature_dvector", {}).get("literal_values", [])
            features.update(literals)
    return features
