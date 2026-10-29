import math
from typing import List, Dict, Optional, Set, Tuple


def cosine_similarity(vec1: List[float], vec2: List[float]) -> float:
    if len(vec1) != len(vec2):
        # Pad shorter vector
        max_len = max(len(vec1), len(vec2))
        vec1 = vec1 + [0.0] * (max_len - len(vec1))
        vec2 = vec2 + [0.0] * (max_len - len(vec2))

    dot_product = sum(v1 * v2 for v1, v2 in zip(vec1, vec2))
    norm1 = math.sqrt(sum(v * v for v in vec1))
    norm2 = math.sqrt(sum(v * v for v in vec2))

    if norm1 == 0.0 or norm2 == 0.0:
        return 0.0

    return dot_product / (norm1 * norm2)


def bitvector_to_floats(bitvec: str) -> List[float]:
    if not bitvec:
        return []
    return [float(c) for c in bitvec]

# Build dynamic vocabulary from both dvectors (SBridge bcVocabulary style)
def build_dynamic_vocab(src_dvector: dict, bin_dvector: dict) -> Tuple[Dict[str, int], int]:
    vocab = {}
    idx = 0

    # Collect all dynamic features from both sides
    src_numbers = set(src_dvector.get("numbers", []))
    bin_numbers = set(bin_dvector.get("numbers", []))
    all_numbers = src_numbers | bin_numbers

    src_literals = set(src_dvector.get("literal_values", []))
    bin_literals = set(bin_dvector.get("literal_values", []))
    all_literals = src_literals | bin_literals

    src_functions = set(src_dvector.get("function_values", []))
    bin_functions = set(bin_dvector.get("function_values", []))
    all_functions = src_functions | bin_functions

    # Build vocab with type prefixes to avoid collisions
    for num in sorted(all_numbers):
        vocab[f"NUM_{num}"] = idx
        idx += 1

    for lit in sorted(all_literals):
        vocab[f"LIT_{lit}"] = idx
        idx += 1

    for func in sorted(all_functions):
        vocab[f"FUNC_{func}"] = idx
        idx += 1

    # Function count match slot (fixed index like SBridge)
    func_count_index = idx
    vocab["FUNC_COUNT_MATCH"] = idx

    return vocab, func_count_index

# Convert dvector to float vector using vocabulary (SBridge blockContentVectorize style)
def dvector_to_vector(
    dvector: dict,
    vocab: Dict[str, int],
    func_count_index: int,
    src_func_count: int,
    is_source: bool = True
) -> Tuple[List[float], List[int]]:

    vec = [0.0] * len(vocab)
    numbers_list = []

    for num in dvector.get("numbers", []):
        numbers_list.append(num)
        key = f"NUM_{num}"
        if key in vocab:
            vec[vocab[key]] += 1.0

    for lit in dvector.get("literal_values", []):
        key = f"LIT_{lit}"
        if key in vocab:
            vec[vocab[key]] += 1.0

    for func in dvector.get("function_values", []):
        key = f"FUNC_{func}"
        if key in vocab:
            vec[vocab[key]] += 1.0

    bin_func_count = dvector.get("function_count", 0)
    if is_source:
        vec[func_count_index] = 1.0
    else:
        vec[func_count_index] = 1.0 if bin_func_count == src_func_count else 0.0

    return vec, numbers_list

# Apply NUMTYPE wildcard
def apply_numtype_absorption(
    vec: List[float],
    own_numbers: List[int],
    other_numbers: List[int],
    numtype_count: int,
    vocab: Dict[str, int]
) -> List[float]:

    if numtype_count <= 0:
        return vec

    expanded_vec = vec.copy()

    own_set = set(own_numbers)
    available_numbers = [n for n in other_numbers if n not in own_set]

    numbers_to_absorb = available_numbers[:numtype_count]

    for num in numbers_to_absorb:
        key = f"NUM_{num}"
        if key in vocab:
            idx = vocab[key]
            if idx < len(expanded_vec):
                expanded_vec[idx] += 1.0

    return expanded_vec


def combined_vector_similarity(
    src_static_vec: str,
    src_dvector: dict,
    bin_static_vec: str,
    bin_dvector: dict
) -> float:
    # Convert static vectors
    src_static = bitvector_to_floats(src_static_vec)
    bin_static = bitvector_to_floats(bin_static_vec)

    # Build dynamic vocabulary (SBridge bcVocabulary style)
    dyn_vocab, func_count_index = build_dynamic_vocab(src_dvector, bin_dvector)

    # No dynamic features - just compare static
    if not dyn_vocab or len(dyn_vocab) <= 1:  # Only FUNC_COUNT_MATCH
        if not src_static and not bin_static:
            return 1.0
        if not src_static or not bin_static:
            return 0.0
        return cosine_similarity(src_static, bin_static)

    # Get source function count as reference
    src_func_count = src_dvector.get("function_count", 0)

    # Convert dynamic parts to vectors (SBridge blockContentVectorize style)
    src_dynamic, src_numbers = dvector_to_vector(
        src_dvector, dyn_vocab, func_count_index, src_func_count, is_source=True
    )
    bin_dynamic, bin_numbers = dvector_to_vector(
        bin_dvector, dyn_vocab, func_count_index, src_func_count, is_source=False
    )

    src_numtype_count = src_dvector.get("numtype_count", 0)
    bin_numtype_count = bin_dvector.get("numtype_count", 0)

    if src_numtype_count > 0:
        src_dynamic = apply_numtype_absorption(
            src_dynamic, src_numbers, bin_numbers, src_numtype_count, dyn_vocab
        )
    if bin_numtype_count > 0:
        bin_dynamic = apply_numtype_absorption(
            bin_dynamic, bin_numbers, src_numbers, bin_numtype_count, dyn_vocab
        )

    # Combine: static + dynamic
    src_combined = src_static + src_dynamic
    bin_combined = bin_static + bin_dynamic

    # Handle empty cases
    if not src_combined and not bin_combined:
        return 1.0
    if not src_combined or not bin_combined:
        return 0.0

    return cosine_similarity(src_combined, bin_combined)


def param_values_similarity(src_params: List[str], bin_params: List[str]) -> float:
    # Calculate similarity between parameter value lists.
    # Used for function call blocks (LibcFunc, CalleeFunc).

    if not src_params and not bin_params:
        return 1.0
    if not src_params or not bin_params:
        return 0.0

    max_params = max(len(src_params), len(bin_params))
    matched_score = 0.0
    used_indices: Set[int] = set()

    for src_param in src_params:
        best_score = 0.0
        best_idx = -1

        src_elements = [e.strip() for e in src_param.split(";")]

        for bin_idx, bin_param in enumerate(bin_params):
            if bin_idx in used_indices:
                continue

            bin_elements = [e.strip() for e in bin_param.split(";")]
            score = _element_list_similarity(src_elements, bin_elements)

            if score > best_score:
                best_score = score
                best_idx = bin_idx

        if best_idx >= 0:
            matched_score += best_score
            used_indices.add(best_idx)

    return matched_score / max_params


def _element_list_similarity(src_elements: List[str], bin_elements: List[str]) -> float:
    if not src_elements and not bin_elements:
        return 1.0
    if not src_elements or not bin_elements:
        return 0.0

    max_elements = max(len(src_elements), len(bin_elements))
    matched_score = 0.0
    used_indices: Set[int] = set()

    for src_elem in src_elements:
        best_score = 0.0
        best_idx = -1

        src_type = _extract_type(src_elem)
        src_value = _extract_value(src_elem)

        for bin_idx, bin_elem in enumerate(bin_elements):
            if bin_idx in used_indices:
                continue

            bin_type = _extract_type(bin_elem)
            bin_value = _extract_value(bin_elem)

            if src_elem == bin_elem:
                score = 1.0
            elif src_type == bin_type:
                if src_type in ("IDENTIFIER", "POINTERVAR"):
                    if src_value in ("LVAR", "PVAR") and bin_value in ("LVAR", "PVAR"):
                        score = 1.0 if src_value == bin_value else 0.5
                    else:
                        score = 0.5
                else:
                    score = 0.5
            elif (src_type == "NUMTYPE" and bin_type == "NUM") or \
                 (src_type == "NUM" and bin_type == "NUMTYPE"):
                score = 1.0
            else:
                score = 0.0

            if score > best_score:
                best_score = score
                best_idx = bin_idx

        if best_idx >= 0:
            matched_score += best_score
            used_indices.add(best_idx)

    return matched_score / max_elements


def _extract_type(element: str) -> str:
    element = element.strip()
    if element.startswith("(") and "," in element:
        return element[1:element.index(",")]
    return ""


def _extract_value(element: str) -> str:
    element = element.strip()
    if "," in element:
        value_part = element[element.index(",") + 1:]
        return value_part.rstrip(")")
    return ""
