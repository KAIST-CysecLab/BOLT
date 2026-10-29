import argparse
import hashlib
import json
import os
import re
import sys
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, DefaultDict, Dict, FrozenSet, Iterable, List, Optional, Set, Tuple


SRC_DIR = os.path.dirname(os.path.abspath(__file__))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from utils.similarity_measure import compare_functions
from llm_verifier import LLMVerifierConfig, OllamaLLMVerifier

currentPath = os.getcwd()
OUTPUT_DIR = currentPath + "/output"
COMPONENT_DB_DIR = currentPath + "/database/componentDB"
TARGET_DIR = currentPath + "/testset"
TARGET_BIN_DIR = currentPath + "/testset/bin"
BINARY_FEATURES_TEMPLATE = currentPath + "/testset/{binary}/binary_features.json"
PROVENANCE_DEP_GRAPH = currentPath + "/database/provenance/dependency_graph.json"
REPO_META_DIR = currentPath + "/osscollector/repo_meta"
RARE_CONTROL_INDEX_PATH = currentPath + "/database/componentDB/rare_control_token_index.json"
RARE_CONTROL_SHARD_DIR = currentPath + "/database/componentDB/rare_control_token_index"
STARTUP_INDEX_PATH = currentPath + "/database/componentDB/startup_index.json"
NAMESPACE_OWNER_INDEX_PATH = currentPath + "/database/componentDB/namespace_owner_index.json"

# Set True via --verbose to log intermediate phase/progress output.
VERBOSE = False


def log(*args: Any, **kwargs: Any) -> None:
    if VERBOSE:
        print(*args, **kwargs)

# Constants
MIN_ANCHOR_STR_LEN = 4
PHASE1B_MIN_SYMBOL_HITS = 1      # any discriminative symbol hit is a candidate
PHASE2_MIN_SIZE = 2
PHASE3_MIN_SIZE = 2
PHASE15_RECOVERY_TOPK = 8
PHASE15_PAIR_TOPK_PER_BIN_FUNC = 5
PHASE16_SHARED_EVIDENCE_TOPK = 24
MIN_SHARED_ONLY_GRAPH_SIZE = 8
MIN_DEPENDENCY_CHILD_GRAPH_SIZE = 8
DEBUG_STRING_PRINT_LIMIT = 10

UNSUPPORTED_SYMBOLS = {"main", "usage", "_start", "__libc_start_main"}
GENERIC_CONTROL_FUNCTION_VALUES = {
    "__cxa_atexit",
    "__stack_chk_fail",
    "_unwind_resume",
    "abort",
    "calloc",
    "free",
    "malloc",
    "memcpy",
    "memmove",
    "memset",
    "operator_delete",
    "operator_new",
    "printf",
    "puts",
    "snprintf",
    "sprintf",
    "strcmp",
    "strlen",
}
GENERIC_CONTROL_NUMBERS = {"-1", "0", "1", "2", "4", "8", "10", "16"}
GENERIC_SHARED_STRINGS = {
    "(null)",
    "false",
    "null",
    "true",
}

FORMAT_PATTERN = re.compile(
    r"^%[-+0 #]*(\d+|\*)?(\.(\d+|\*))?[hlLzjt]*[diouxXeEfFgGaAcspn%]$"
)
FORMAT_ONLY_PATTERN = re.compile(
    r"^[\s%\-+0-9.#hlLzjtdiouxXeEfFgGaAcspn\[\]\(\)\{\}:,'\"\ntr]*$"
)
PATH_PATTERN = re.compile(r"^([a-zA-Z]:)?[\\/][^\s]+")


# Data classes


@dataclass
class FunctionStringProfile:
    self_strings: Set[str] = field(default_factory=set)
    ancestor_reachable_strings: Set[str] = field(default_factory=set)
    descendant_reachable_strings: Set[str] = field(default_factory=set)


@dataclass
class OssFuncEntry:
    plain_name: str
    strings: FrozenSet[str]
    control_tokens: FrozenSet[str]
    callstr_tokens: FrozenSet[str]
    control_blocks: Tuple[dict, ...]
    birthdate: str


@dataclass
class OssIndex:
    oss_name: str
    all_strings: FrozenSet[str]
    funcs: Dict[str, OssFuncEntry]
    funcs_by_local_str: Dict[str, Set[str]]
    funcs_by_string: Dict[str, Set[str]]
    callgraph: Dict[str, List[str]]
    reverse_cg: Dict[str, List[str]]
    reach_cache: Dict[str, Set[str]]
    string_profiles: Dict[str, FunctionStringProfile]
    # Pre-dedup callgraph (keeps bridge funcs); used only for connectivity checks.
    full_callgraph: Dict[str, List[str]] = field(default_factory=dict)
    full_reverse_cg: Dict[str, List[str]] = field(default_factory=dict)


@dataclass
class MatchedComponent:
    oss_name: str
    phase: str
    matched_pairs_plain: Dict[str, str]
    matched_meta: Dict[str, Dict[str, Any]]
    reachable_edge_count: int = 0
    direct_edge_count: int = 0
    unsupported_edge_count: int = 0
    graph_decision: str = ""
    inlined_plain_symbols: Set[str] = field(default_factory=set)


@dataclass
class RareControlTokenIndex:
    component_count: int
    component_df: Dict[str, int]
    function_df: Dict[str, int]
    token_weight: Dict[str, float]
    source_index: Dict[str, List[Tuple[str, str]]]


# General utilities (reused from new_detector2.py)


def is_stripped_binary(func_names: Set[str]) -> bool:
    if not func_names:
        return True
    fun_count = sum(1 for name in func_names if name.startswith("FUN_"))
    return (fun_count / len(func_names)) >= 0.5


def is_generated_function_name(func_name: str) -> bool:
    if not func_name:
        return True
    lowered = func_name.lower()
    generated_prefixes = ("fun_", "func_", "sub_", "thunk_", "nullsub_", "lab_", "loc_", "unk_", "j_")
    if lowered.startswith(generated_prefixes):
        return True
    return bool(re.fullmatch(r"(sub|fun|func|loc|lab|unk)_[0-9a-f]+", lowered))


def get_all_nodes(callgraph: Dict[str, List[str]]) -> Set[str]:
    all_nodes = set(callgraph.keys())
    for callees in callgraph.values():
        all_nodes.update(callees)
    return all_nodes


def build_reverse_callgraph(callgraph: Dict[str, List[str]]) -> Dict[str, List[str]]:
    reverse: DefaultDict[str, List[str]] = defaultdict(list)
    for caller, callees in callgraph.items():
        for callee in callees:
            reverse[callee].append(caller)
    return dict(reverse)


def get_neighbors(func: str, callgraph: Dict[str, List[str]], reverse_callgraph: Dict[str, List[str]]) -> Set[str]:
    return set(callgraph.get(func, [])) | set(reverse_callgraph.get(func, []))


def reachability(graph: Dict[str, List[str]], start: str) -> Set[str]:
    reachable: Set[str] = set()
    stack = [start]
    while stack:
        cur = stack.pop()
        for nxt in graph.get(cur, []):
            if nxt not in reachable:
                reachable.add(nxt)
                stack.append(nxt)
    return reachable


def reachable_nodes_excluding_self(graph: Dict[str, List[str]], start: str, cache: Dict[str, Set[str]]) -> Set[str]:
    cached = cache.get(start)
    if cached is not None:
        return cached
    seen = {start}
    out: Set[str] = set()
    stack = [start]
    while stack:
        cur = stack.pop()
        for nxt in graph.get(cur, []):
            if nxt in seen:
                continue
            seen.add(nxt)
            out.add(nxt)
            stack.append(nxt)
    cache[start] = out
    return out


def date_sort_key(value: str) -> Tuple[int, str]:
    if not value or value == "NODATE":
        return (1, "9999-99-99")
    return (0, value)


def normalize_string_token(token: str) -> str:
    if not isinstance(token, str):
        return ""
    normalized = token.strip()
    if normalized.startswith("ASSIGNSTR:"):
        normalized = normalized[len("ASSIGNSTR:"):]
    normalized = "".join(normalized.lower().split())
    return normalized


def is_usable_string(value: str) -> bool:
    return bool(value and value.strip()) and len(value.strip()) > 1


def is_noise_string(value: str) -> bool:
    if not isinstance(value, str):
        return True
    text = value.strip()
    if not text:
        return True
    if PATH_PATTERN.match(text):
        return True
    if FORMAT_PATTERN.match(text):
        return True
    if FORMAT_ONLY_PATTERN.match(text) and "%" in text:
        return True
    return False


def read_json(path: str, default: Any) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as exc:
        print(f"[!] Invalid JSON: {path}: {exc}")
        return default
    except OSError:
        return default


def normalize_feature_string(value: str) -> str:
    normalized = normalize_string_token(value)
    if not is_usable_string(normalized) or is_noise_string(normalized):
        return ""
    return normalized


def component_alias_tokens(component: str) -> Set[str]:
    tail = component.split("@@")[-1].lower()
    aliases = {tail, re.sub(r"[^a-z0-9]+", "", tail)}
    aliases.update(part for part in re.split(r"[^a-z0-9]+", tail) if part)
    for alias in list(aliases):
        if alias.startswith("lib") and len(alias) > 3:
            aliases.add(alias[3:])
    return {alias for alias in aliases if len(alias) >= 3}


def normalized_string_words(value: str) -> Set[str]:
    return {word for word in re.split(r"[^a-z0-9]+", str(value).lower()) if word}


def string_mentions_alias(value: str, aliases: Set[str]) -> bool:
    words = normalized_string_words(value)
    compact = re.sub(r"[^a-z0-9]+", "", str(value).lower())
    return any(alias in words or compact == alias for alias in aliases)


def normalize_feature_token(value: str) -> str:
    return "".join(str(value or "").lower().split())


def collect_scalar_tokens(prefix: str, value: Any, out: Set[str]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            collect_scalar_tokens(f"{prefix}:{key}", child, out)
        return
    if isinstance(value, list):
        for child in value:
            collect_scalar_tokens(prefix, child, out)
        return
    token = normalize_feature_token(value)
    if token and len(token) >= 2 and not is_noise_string(token):
        out.add(f"{prefix}:{token}")


def control_block_tokens(blocks: List[dict]) -> Set[str]:
    tokens: Set[str] = set()
    for block in blocks or []:
        if not isinstance(block, dict):
            continue
        block_type = normalize_feature_token(block.get("block_type", ""))
        if block_type:
            tokens.add(f"BLOCK:{block_type}")
        key_features = block.get("key_feature_dvector", {})
        if isinstance(key_features, dict):
            for key, value in key_features.items():
                collect_scalar_tokens(f"KEY:{key}", value, tokens)
        block_content = block.get("block_content_dvector", {})
        if isinstance(block_content, dict):
            for key, value in block_content.items():
                collect_scalar_tokens(f"CONTENT:{key}", value, tokens)
    return tokens


def is_noise_control_token(token: str) -> bool:
    if not token or token.startswith("BLOCK:"):
        return True

    parts = token.split(":")
    value = parts[-1].lower() if parts else token.lower()
    field = ":".join(parts[:-1]).lower()

    if len(value) < 2:
        return True
    if value in GENERIC_CONTROL_NUMBERS and field.endswith("numbers"):
        return True
    if field.endswith("function_values") and value in GENERIC_CONTROL_FUNCTION_VALUES:
        return True
    if field.endswith("literal_values") and is_noise_string(value):
        return True
    if "param_values" in field:
        generic_param = re.sub(r"\(identifier,[lp]var\)|[;(),]", "", value)
        if not generic_param or len(value) < 16:
            return True
    return False


def usable_control_tokens(tokens: Set[str]) -> Set[str]:
    return {token for token in tokens if not is_noise_control_token(token)}


def load_component_json(feature_name: str, component: str) -> dict:
    key = (feature_name, component)
    cached = _COMPONENT_JSON_CACHE.get(key)
    if cached is not None:
        return cached
    data = read_json(os.path.join(COMPONENT_DB_DIR, feature_name, f"{component}.json"), {})
    _COMPONENT_JSON_CACHE[key] = data
    return data


def has_componentdb_layout() -> bool:
    required = [
        os.path.join(COMPONENT_DB_DIR, "components.json"),
        os.path.join(COMPONENT_DB_DIR, "functions.json"),
        os.path.join(COMPONENT_DB_DIR, "strings"),
        os.path.join(COMPONENT_DB_DIR, "symbols"),
        os.path.join(COMPONENT_DB_DIR, "control_blocks"),
        os.path.join(COMPONENT_DB_DIR, "call_graph"),
    ]
    return all(os.path.exists(path) for path in required)


def weak_components_subset(
    nodes: Set[str],
    callgraph: Dict[str, List[str]],
    reverse_callgraph: Dict[str, List[str]],
) -> List[Set[str]]:
    seen: Set[str] = set()
    components: List[Set[str]] = []
    for node in nodes:
        if node in seen:
            continue
        comp: Set[str] = set()
        queue: deque = deque([node])
        seen.add(node)
        while queue:
            cur = queue.popleft()
            comp.add(cur)
            for nxt in get_neighbors(cur, callgraph, reverse_callgraph):
                if nxt in nodes and nxt not in seen:
                    seen.add(nxt)
                    queue.append(nxt)
        components.append(comp)
    return components


def build_function_string_profiles(
    self_strings_by_func: Dict[str, Set[str]],
    callgraph: Dict[str, List[str]],
    reverse_callgraph: Dict[str, List[str]],
) -> Dict[str, FunctionStringProfile]:
    all_nodes = set(self_strings_by_func.keys()) | get_all_nodes(callgraph) | get_all_nodes(reverse_callgraph)
    desc_cache: Dict[str, Set[str]] = {}
    anc_cache: Dict[str, Set[str]] = {}
    profiles: Dict[str, FunctionStringProfile] = {}
    for node in all_nodes:
        descendant_strings: Set[str] = set()
        for rn in reachable_nodes_excluding_self(callgraph, node, desc_cache):
            descendant_strings.update(self_strings_by_func.get(rn, set()))
        ancestor_strings: Set[str] = set()
        for rn in reachable_nodes_excluding_self(reverse_callgraph, node, anc_cache):
            ancestor_strings.update(self_strings_by_func.get(rn, set()))
        profiles[node] = FunctionStringProfile(
            self_strings=set(self_strings_by_func.get(node, set())),
            ancestor_reachable_strings=ancestor_strings,
            descendant_reachable_strings=descendant_strings,
        )
    return profiles


def get_component_string_graph_summary(component: MatchedComponent) -> Dict[str, int]:
    summary = {
        "required_caller_count": 0,
        "required_callee_count": 0,
    }
    for meta in component.matched_meta.values():
        summary["required_caller_count"] += len(meta.get("caller_required_strings", []))
        summary["required_callee_count"] += len(meta.get("callee_required_strings", []))
    return summary


# String graph helpers


def evaluate_reachable_string_direction(
    bin_profile: FunctionStringProfile,
    oss_profile: FunctionStringProfile,
) -> Dict[str, Any]:
    caller_required = set(oss_profile.ancestor_reachable_strings)
    callee_required = set(oss_profile.descendant_reachable_strings)
    bin_caller_strings = set(bin_profile.ancestor_reachable_strings)
    bin_callee_strings = set(bin_profile.descendant_reachable_strings)

    caller_wrong = caller_required & (bin_callee_strings - bin_caller_strings)
    callee_wrong = callee_required & (bin_caller_strings - bin_callee_strings)
    caller_missing = caller_required - bin_caller_strings - caller_wrong
    callee_missing = callee_required - bin_callee_strings - callee_wrong

    reasons = []
    if caller_missing:
        reasons.append("missing_required_caller_strings")
    if callee_missing:
        reasons.append("missing_required_callee_strings")
    if caller_wrong:
        reasons.append("wrong_direction_caller_context")
    if callee_wrong:
        reasons.append("wrong_direction_callee_context")
    if not caller_required and not callee_required:
        reasons.append("no_reachable_context")

    string_graph_ok = not caller_missing and not callee_missing and not caller_wrong and not callee_wrong

    return {
        "caller_required_strings": sorted(caller_required),
        "callee_required_strings": sorted(callee_required),
        "caller_missing_required": sorted(caller_missing),
        "callee_missing_required": sorted(callee_missing),
        "caller_wrong_direction_hits": sorted(caller_wrong),
        "callee_wrong_direction_hits": sorted(callee_wrong),
        "string_graph_ok": string_graph_ok,
        "string_graph_reason": ",".join(reasons) if reasons else "ok",
    }


def build_pair_string_graph_meta(
    bin_func: str,
    oss_plain_name: str,
    bin_string_profiles: Dict[str, FunctionStringProfile],
    idx: OssIndex,
) -> Dict[str, Any]:
    bin_profile = bin_string_profiles.get(bin_func, FunctionStringProfile())
    oss_profile = idx.string_profiles.get(oss_plain_name, FunctionStringProfile())
    return evaluate_reachable_string_direction(bin_profile, oss_profile)


# Callgraph relation helpers


def relation_class(
    bin_src: str,
    bin_dst: str,
    oss_src: str,
    oss_dst: str,
    bin_callgraph: Dict[str, List[str]],
    bin_reverse_cg: Dict[str, List[str]],
    oss_callgraph: Dict[str, List[str]],
    oss_reverse_cg: Dict[str, List[str]],
    bin_reach_cache: Dict[str, Set[str]],
    oss_reach_cache: Dict[str, Set[str]],
) -> str:
    if bin_dst in bin_callgraph.get(bin_src, []) and oss_dst in oss_callgraph.get(oss_src, []):
        return "direct"
    if bin_src in bin_callgraph.get(bin_dst, []) and oss_src in oss_callgraph.get(oss_dst, []):
        return "direct"
    if bin_dst in bin_reverse_cg.get(bin_src, []) and oss_dst in oss_reverse_cg.get(oss_src, []):
        return "direct"
    if bin_src in bin_reverse_cg.get(bin_dst, []) and oss_src in oss_reverse_cg.get(oss_dst, []):
        return "direct"

    bin_src_reach = bin_reach_cache.setdefault(bin_src, reachability(bin_callgraph, bin_src))
    oss_src_reach = oss_reach_cache.setdefault(oss_src, reachability(oss_callgraph, oss_src))
    if bin_dst in bin_callgraph.get(bin_src, []) and oss_dst in oss_src_reach:
        return "inlined_bridge"
    if bin_dst in bin_src_reach and oss_dst in oss_src_reach:
        return "reachable"

    bin_dst_reach = bin_reach_cache.setdefault(bin_dst, reachability(bin_callgraph, bin_dst))
    oss_dst_reach = oss_reach_cache.setdefault(oss_dst, reachability(oss_callgraph, oss_dst))
    if bin_src in bin_callgraph.get(bin_dst, []) and oss_src in oss_dst_reach:
        return "inlined_bridge"
    if bin_src in bin_dst_reach and oss_src in oss_dst_reach:
        return "reachable"

    return "none"


def shortest_reachable_path(graph: Dict[str, List[str]], start: str, target: str) -> List[str]:
    if start == target:
        return [start]
    queue: deque = deque([start])
    parents: Dict[str, Optional[str]] = {start: None}
    while queue:
        cur = queue.popleft()
        for nxt in graph.get(cur, []):
            if nxt in parents:
                continue
            parents[nxt] = cur
            if nxt == target:
                path = [target]
                cursor = target
                while parents[cursor] is not None:
                    cursor = parents[cursor]
                    path.append(cursor)
                path.reverse()
                return path
            queue.append(nxt)
    return []


def count_supported_edges_for_pairs(
    matched_pairs_plain: Dict[str, str],
    bin_callgraph: Dict[str, List[str]],
    oss_callgraph: Dict[str, List[str]],
    bin_reverse_cg: Dict[str, List[str]],
    oss_reverse_cg: Dict[str, List[str]],
    bin_reach_cache: Dict[str, Set[str]],
    oss_reach_cache: Dict[str, Set[str]],
) -> Tuple[int, int, int, Set[str]]:
    analysis = analyze_supported_edges_for_pairs(
        matched_pairs_plain,
        bin_callgraph,
        oss_callgraph,
        bin_reverse_cg,
        oss_reverse_cg,
        bin_reach_cache,
        oss_reach_cache,
    )
    return (
        analysis["direct_edges"],
        analysis["reachable_edges"] + analysis["inlined_edges"],
        analysis["unsupported_edges"],
        set(analysis["inlined_plain_symbols"]),
    )


def analyze_supported_edges_for_pairs(
    matched_pairs_plain: Dict[str, str],
    bin_callgraph: Dict[str, List[str]],
    oss_callgraph: Dict[str, List[str]],
    bin_reverse_cg: Dict[str, List[str]],
    oss_reverse_cg: Dict[str, List[str]],
    bin_reach_cache: Dict[str, Set[str]],
    oss_reach_cache: Dict[str, Set[str]],
) -> Dict[str, Any]:
    matched_nodes = set(matched_pairs_plain.keys())
    direct_edges = 0
    reachable_edges = 0
    inlined_edges = 0
    unsupported_edges = 0
    inlined_plain_symbols: Set[str] = set()
    supported_edges = []
    unsupported_edge_items = []

    for caller in matched_nodes:
        for callee in bin_callgraph.get(caller, []):
            if callee not in matched_nodes:
                continue
            oss_caller = matched_pairs_plain[caller]
            oss_callee = matched_pairs_plain[callee]
            rel = relation_class(
                caller, callee, oss_caller, oss_callee,
                bin_callgraph, bin_reverse_cg,
                oss_callgraph, oss_reverse_cg,
                bin_reach_cache, oss_reach_cache,
            )
            if rel == "direct":
                direct_edges += 1
                supported_edges.append((caller, callee, rel))
            elif rel in {"reachable", "inlined_bridge"}:
                if rel == "reachable":
                    reachable_edges += 1
                else:
                    inlined_edges += 1
                supported_edges.append((caller, callee, rel))
                path = shortest_reachable_path(oss_callgraph, oss_caller, oss_callee)
                if len(path) > 2:
                    inlined_plain_symbols.update(path[1:-1])
            else:
                unsupported_edges += 1
                unsupported_edge_items.append((caller, callee))

    return {
        "direct_edges": direct_edges,
        "reachable_edges": reachable_edges,
        "inlined_edges": inlined_edges,
        "unsupported_edges": unsupported_edges,
        "supported_edges": supported_edges,
        "unsupported_edge_items": unsupported_edge_items,
        "inlined_plain_symbols": inlined_plain_symbols,
    }


def phase35_relation_to_component(
    bin_func: str,
    oss_plain_name: str,
    matched_pairs_plain: Dict[str, str],
    bin_callgraph: Dict[str, List[str]],
    bin_reverse_cg: Dict[str, List[str]],
    idx: OssIndex,
    bin_reach_cache: Dict[str, Set[str]],
) -> Optional[Tuple[int, int]]:
    direct_count = 0
    reachable_count = 0
    has_supported_edge = False

    for matched_bin, matched_oss in matched_pairs_plain.items():
        linked = (
            matched_bin in bin_callgraph.get(bin_func, [])
            or bin_func in bin_callgraph.get(matched_bin, [])
            or matched_bin in bin_reverse_cg.get(bin_func, [])
            or bin_func in bin_reverse_cg.get(matched_bin, [])
        )
        if not linked:
            continue
        rel = relation_class(
            bin_func, matched_bin,
            oss_plain_name, matched_oss,
            bin_callgraph, bin_reverse_cg,
            idx.callgraph, idx.reverse_cg,
            bin_reach_cache, idx.reach_cache,
        )
        if rel == "none":
            return None
        has_supported_edge = True
        if rel == "direct":
            direct_count += 1
        else:
            reachable_count += 1

    if not has_supported_edge:
        return None
    return direct_count, reachable_count


def supported_groups_from_edges(
    supported_edges: Iterable[Tuple[str, str, str]],
) -> List[Tuple[Set[str], int]]:
    edge_list = list(supported_edges)
    adjacency: DefaultDict[str, Set[str]] = defaultdict(set)
    for caller, callee, _rel in edge_list:
        adjacency[caller].add(callee)
        adjacency[callee].add(caller)

    seen: Set[str] = set()
    groups: List[Tuple[Set[str], int]] = []
    for node in sorted(adjacency):
        if node in seen:
            continue
        nodes: Set[str] = set()
        queue: deque = deque([node])
        seen.add(node)
        while queue:
            cur = queue.popleft()
            nodes.add(cur)
            for nxt in adjacency.get(cur, set()):
                if nxt not in seen:
                    seen.add(nxt)
                    queue.append(nxt)

        edge_count = sum(1 for caller, callee, _rel in edge_list if caller in nodes and callee in nodes)
        if len(nodes) >= 2 and edge_count >= 1:
            groups.append((nodes, edge_count))

    return sorted(groups, key=lambda item: (-len(item[0]), -item[1], sorted(item[0])))


def supported_node_groups(analysis: Dict[str, Any]) -> List[Tuple[Set[str], int]]:
    return supported_groups_from_edges(analysis.get("supported_edges", []))


# Token Jaccard similarity


def token_jaccard(a: Set[str], b: Set[str]) -> float:
    if not a and not b:
        return 0.0
    inter = len(a & b)
    union = len(a) + len(b) - inter
    return inter / union if union > 0 else 0.0


def informative_control_tokens(tokens: Set[str]) -> Set[str]:
    """Keep tokens that carry more evidence than the mere presence of a block type."""
    informative = {token for token in tokens if not token.startswith("BLOCK:")}
    return informative if informative else set(tokens)


def anchor_rank_key(
    shared_local_disc: int,
    shared_all: int,
    tok_sim: float,
    string_graph_ok: bool,
    birthdate: str,
    plain_name: str,
) -> Tuple:
    return (
        0 if shared_local_disc > 0 else 1,
        -shared_local_disc,
        -shared_all,
        -tok_sim,
        0 if string_graph_ok else 1,
        date_sort_key(birthdate),
        plain_name,
    )


# Loaders


_BINARY_FEATURE_CACHE: Dict[str, dict] = {}
_COMPONENT_FUNCTIONS_CACHE: Optional[Dict[str, Dict[str, dict]]] = None
_DEPENDENCY_CHILD_ALIASES_CACHE: Optional[Dict[str, Set[str]]] = None
_COMPONENT_JSON_CACHE: Dict[Tuple[str, str], dict] = {}
_OSS_INDEX_CACHE: Dict[Tuple[str, FrozenSet[str]], "OssIndex"] = {}


def load_binary_features(binary_name: str) -> dict:
    cached = _BINARY_FEATURE_CACHE.get(binary_name)
    if cached is not None:
        return cached
    path = BINARY_FEATURES_TEMPLATE.format(binary=binary_name)
    data = read_json(path, {})
    if not data:
        print(f"[!] Preprocessing First: {path} does not exist or is invalid.")
    _BINARY_FEATURE_CACHE[binary_name] = data
    return data


def load_bin_callgraph(binary_name: str) -> Dict[str, List[str]]:
    data = load_binary_features(binary_name)
    callgraph = data.get("callgraph", {}) if isinstance(data, dict) else {}
    if isinstance(callgraph, dict):
        return {str(caller): [str(callee) for callee in callees] for caller, callees in callgraph.items()}
    return {}


def load_bin_func_string_refs(binary_name: str) -> Dict[str, Set[str]]:
    out: Dict[str, Set[str]] = {}
    for item in load_binary_features(binary_name).get("functions", []):
        func_name = item.get("function_name", "")
        strings = {
            normalized
            for raw in item.get("strings", [])
            for normalized in [normalize_feature_string(raw)]
            if normalized
        }
        if strings:
            out[func_name] = strings
    return out


def load_bin_control_tokens(binary_name: str) -> Dict[str, Set[str]]:
    out: Dict[str, Set[str]] = {}
    for item in load_binary_features(binary_name).get("functions", []):
        func_name = item.get("function_name", "")
        tokens = control_block_tokens(item.get("control_blocks", []))
        if tokens:
            out[func_name] = tokens
    return out


def load_bin_control_blocks(binary_name: str) -> Dict[str, List[dict]]:
    out: Dict[str, List[dict]] = {}
    for item in load_binary_features(binary_name).get("functions", []):
        func_name = item.get("function_name", "")
        blocks = item.get("control_blocks", [])
        if func_name and isinstance(blocks, list) and blocks:
            out[func_name] = [block for block in blocks if isinstance(block, dict)]
    return out


def load_bin_callstr_tokens(binary_name: str) -> Dict[str, Set[str]]:
    out: Dict[str, Set[str]] = {}
    for item in load_binary_features(binary_name).get("functions", []):
        func_name = item.get("function_name", "")
        tokens = {normalize_feature_token(token) for token in item.get("callstr_tokens", []) if normalize_feature_token(token)}
        if tokens:
            out[func_name] = tokens
    return out


def load_bin_strings(binary_name: str) -> Set[str]:
    strings: Set[str] = set()
    for values in load_bin_func_string_refs(binary_name).values():
        strings.update(values)
    return strings


def load_bin_real_symbols(binary_name: str) -> Set[str]:
    symbols = set()
    for item in load_binary_features(binary_name).get("functions", []):
        if item.get("symbol_kind") != "real":
            continue
        name = item.get("function_name", "")
        if name and name not in UNSUPPORTED_SYMBOLS and not is_generated_function_name(name):
            symbols.add(name)
    return symbols


def load_component_functions() -> Dict[str, Dict[str, dict]]:
    global _COMPONENT_FUNCTIONS_CACHE
    if _COMPONENT_FUNCTIONS_CACHE is not None:
        return _COMPONENT_FUNCTIONS_CACHE
    path = os.path.join(COMPONENT_DB_DIR, "functions.json")
    data = read_json(path, {})
    by_component: DefaultDict[str, Dict[str, dict]] = defaultdict(dict)
    for item in data.get("functions", []):
        component = item.get("origin_component")
        function_id = item.get("function_id")
        if not component or not function_id:
            continue
        if item.get("origin_decision") == "unknown":
            continue
        by_component[component][function_id] = item
    _COMPONENT_FUNCTIONS_CACHE = {component: dict(functions) for component, functions in by_component.items()}
    return _COMPONENT_FUNCTIONS_CACHE


def available_components() -> List[str]:
    component_functions = load_component_functions()
    own_source_components = {
        component
        for component, functions in component_functions.items()
        if any("own" in meta.get("roles", []) for meta in functions.values())
    }
    data = read_json(os.path.join(COMPONENT_DB_DIR, "components.json"), {})
    components = [
        item.get("component")
        for item in data.get("components", [])
        if item.get("component") in own_source_components
    ]
    if components:
        return sorted(components)
    return sorted(own_source_components)


def _load_dep_edges() -> List[dict]:
    return read_json(PROVENANCE_DEP_GRAPH, {}).get("edges", [])


def load_dependency_children() -> Dict[str, Set[str]]:
    children: DefaultDict[str, Set[str]] = defaultdict(set)
    for edge in _load_dep_edges():
        parent, child = edge.get("parent"), edge.get("child")
        if parent and child:
            children[parent].add(child)
    return dict(children)


def load_hub_components() -> Set[str]:
    """Components that vendor/share code with many others (benchmark harnesses like lzbench/TurboBench/precomp-cpp) rather than being a single distinct origin. Precomputed by preprocessor.py alongside startup_index.json."""
    return set(read_json(STARTUP_INDEX_PATH, {}).get("hub_components", []))


def load_child_to_parents() -> Dict[str, Set[str]]:
    child_to_parents: DefaultDict[str, Set[str]] = defaultdict(set)
    for edge in _load_dep_edges():
        parent, child = edge.get("parent"), edge.get("child")
        if parent and child:
            child_to_parents[child].add(parent)
    return dict(child_to_parents)


def load_dependency_child_aliases() -> Dict[str, Set[str]]:
    global _DEPENDENCY_CHILD_ALIASES_CACHE
    if _DEPENDENCY_CHILD_ALIASES_CACHE is not None:
        return _DEPENDENCY_CHILD_ALIASES_CACHE
    aliases_by_parent: Dict[str, Set[str]] = {}
    for parent, children in load_dependency_children().items():
        aliases: Set[str] = set()
        for child in children:
            aliases.update(component_alias_tokens(child))
        aliases_by_parent[parent] = aliases
    _DEPENDENCY_CHILD_ALIASES_CACHE = aliases_by_parent
    return aliases_by_parent


def remove_child_dependency_string_evidence(component: MatchedComponent) -> None:
    aliases = load_dependency_child_aliases().get(component.oss_name, set())
    if not aliases:
        return
    for meta in component.matched_meta.values():
        for key in ("shared_local_disc_strings", "shared_strings"):
            kept = [
                value for value in meta.get(key, [])
                if not string_mentions_alias(value, aliases)
            ]
            if len(kept) != len(meta.get(key, [])):
                meta[f"{key}_excluded_child_dependency"] = [
                    value for value in meta.get(key, [])
                    if string_mentions_alias(value, aliases)
                ]
                meta[key] = kept


def load_oss_all_strings(oss_name: str) -> FrozenSet[str]:
    data = load_component_json("strings", oss_name)
    out: Set[str] = set()
    for item in data.get("items", []):
        normalized = normalize_feature_string(item.get("string", ""))
        if normalized and len(normalized) >= MIN_ANCHOR_STR_LEN:
            out.add(normalized)
    return frozenset(out)


def load_oss_funcstr_plain(oss_name: str) -> Dict[str, Set[str]]:
    function_meta = load_component_functions().get(oss_name, {})
    names_by_id = {fid: meta.get("function_name", "") for fid, meta in function_meta.items()}
    plain_strings: DefaultDict[str, Set[str]] = defaultdict(set)
    data = load_component_json("strings", oss_name)
    for item in data.get("items", []):
        normalized = normalize_feature_string(item.get("string", ""))
        if not normalized:
            continue
        for function_id in item.get("function_ids", []):
            plain_name = names_by_id.get(function_id, "")
            if plain_name:
                plain_strings[plain_name].add(normalized)
    return dict(plain_strings)


def load_oss_control_tokens_plain(oss_name: str) -> Dict[str, Set[str]]:
    out: DefaultDict[str, Set[str]] = defaultdict(set)
    data = load_component_json("control_blocks", oss_name)
    for item in data.get("items", []):
        plain_name = item.get("function_name", "")
        if not plain_name:
            continue
        out[plain_name].update(control_block_tokens(item.get("control_blocks", [])))
    return dict(out)


def load_oss_control_blocks_plain(oss_name: str) -> Dict[str, List[dict]]:
    out: DefaultDict[str, List[dict]] = defaultdict(list)
    data = load_component_json("control_blocks", oss_name)
    for item in data.get("items", []):
        plain_name = item.get("function_name", "")
        blocks = item.get("control_blocks", [])
        if not plain_name or not isinstance(blocks, list):
            continue
        out[plain_name].extend(block for block in blocks if isinstance(block, dict))
    return dict(out)


def load_oss_callstr_plain(oss_name: str) -> Dict[str, Set[str]]:
    function_meta = load_component_functions().get(oss_name, {})
    names_by_id = {fid: meta.get("function_name", "") for fid, meta in function_meta.items()}
    out: DefaultDict[str, Set[str]] = defaultdict(set)
    data = load_component_json("callstr_tokens", oss_name)
    for item in data.get("items", []):
        token = normalize_feature_token(item.get("token", ""))
        if not token:
            continue
        for function_id in item.get("function_ids", []):
            plain_name = names_by_id.get(function_id, "")
            if plain_name:
                out[plain_name].add(token)
    return dict(out)


def load_oss_symbols_plain(oss_name: str) -> Set[str]:
    data = load_component_json("symbols", oss_name)
    symbols = set()
    for item in data.get("items", []):
        if item.get("symbol_kind", "real") != "real":
            continue
        symbol = item.get("symbol", "")
        if symbol and symbol not in UNSUPPORTED_SYMBOLS and not is_generated_function_name(symbol):
            symbols.add(symbol)
    return symbols


def load_oss_callgraph(oss_name: str) -> Dict[str, List[str]]:
    data = load_component_json("call_graph", oss_name)
    graph: DefaultDict[str, Set[str]] = defaultdict(set)
    for edge in data.get("edges", []):
        caller = edge.get("caller_name", "")
        callee = edge.get("callee_name", "")
        if caller and callee and callee not in UNSUPPORTED_SYMBOLS:
            graph[caller].add(callee)
    return {caller: sorted(callees) for caller, callees in graph.items()}


def load_oss_func_name_dates(oss_name: str) -> Dict[str, str]:
    by_plain: Dict[str, str] = {}
    for meta in load_component_functions().get(oss_name, {}).values():
        plain_name = meta.get("function_name", "")
        dates = [
            item.get("path_birth_date")
            for item in meta.get("source_occurrences", [])
            if item.get("path_birth_date")
        ]
        if not plain_name or not dates:
            continue
        date = min(dates)
        current = by_plain.get(plain_name)
        if current is None or date < current:
            by_plain[plain_name] = date
    return by_plain


# Startup index building


def build_disc_funcname_index() -> Dict[str, Set[str]]:
    """Build globally component-unique real-symbol index from source feature files."""
    func_to_oss: DefaultDict[str, Set[str]] = defaultdict(set)

    for oss_name in available_components():
        for plain_name in load_oss_symbols_plain(oss_name):
            if plain_name and len(plain_name) >= 5 and plain_name not in UNSUPPORTED_SYMBOLS:
                func_to_oss[plain_name].add(oss_name)

    return {
        name: oss_set
        for name, oss_set in func_to_oss.items()
        if len(oss_set) == 1
    }


def build_funcname_owner_index() -> Dict[str, Set[str]]:
    """Build all real-symbol owners, including symbols shared by parent/child code."""
    func_to_oss: DefaultDict[str, Set[str]] = defaultdict(set)
    for oss_name in available_components():
        for plain_name in load_oss_symbols_plain(oss_name):
            if plain_name and len(plain_name) >= 3 and plain_name not in UNSUPPORTED_SYMBOLS:
                func_to_oss[plain_name].add(oss_name)
    return {name: set(owners) for name, owners in func_to_oss.items()}


def build_all_oss_unique_str() -> Dict[str, FrozenSet[str]]:
    """Compute component-unique strings from new componentDB/strings files."""
    strings_by_component: Dict[str, FrozenSet[str]] = {
        component: load_oss_all_strings(component)
        for component in available_components()
    }
    string_count = Counter(s for strings in strings_by_component.values() for s in strings)
    return {
        component: frozenset(s for s in strings if string_count[s] == 1)
        for component, strings in strings_by_component.items()
        if any(string_count[s] == 1 for s in strings)
    }


def build_string_owner_index() -> Dict[str, Set[str]]:
    string_to_oss: DefaultDict[str, Set[str]] = defaultdict(set)
    for oss_name in available_components():
        for string_value in load_oss_all_strings(oss_name):
            string_to_oss[string_value].add(oss_name)
    return dict(string_to_oss)


def load_startup_indexes(
    path: str = STARTUP_INDEX_PATH,
) -> Tuple[Dict[str, Set[str]], Dict[str, Set[str]], Dict[str, FrozenSet[str]], Dict[str, Set[str]], bool]:
    data = read_json(path, {})
    if not data:
        return (
            build_disc_funcname_index(),
            build_funcname_owner_index(),
            build_all_oss_unique_str(),
            build_string_owner_index(),
            False,
        )

    disc_funcname_index = {
        str(name): {str(owner) for owner in owners if owner}
        for name, owners in data.get("disc_funcname_index", {}).items()
        if isinstance(owners, list)
    }
    funcname_owner_index = {
        str(name): {str(owner) for owner in owners if owner}
        for name, owners in data.get("funcname_owner_index", {}).items()
        if isinstance(owners, list)
    }
    all_oss_unique_str: Dict[str, FrozenSet[str]] = {}
    for component, strings in data.get("all_oss_unique_str", {}).items():
        if not isinstance(strings, list):
            continue
        normalized_strings = {
            normalized
            for value in strings
            for normalized in [normalize_feature_string(value)]
            if normalized
        }
        if normalized_strings:
            all_oss_unique_str[str(component)] = frozenset(normalized_strings)

    string_owner_accum: DefaultDict[str, Set[str]] = defaultdict(set)
    for string_value, owners in data.get("string_owner_index", {}).items():
        if not isinstance(owners, list):
            continue
        normalized = normalize_feature_string(string_value)
        if normalized:
            string_owner_accum[normalized].update(str(owner) for owner in owners if owner)
    string_owner_index = dict(string_owner_accum)
    return (
        disc_funcname_index,
        funcname_owner_index,
        all_oss_unique_str,
        string_owner_index,
        True,
    )


_CB_ANN_INTERNAL_TYPES = {"Condition", "Loop", "Else"}
CB_ANN_TOP_K = 5
CB_ANN_MAX_HAMMING = 80    # ~22% of 368 bits
CB_ANN_BATCH = 512


def load_rare_control_token_index(path: str) -> RareControlTokenIndex:
    data = read_json(path, {})
    if not data:
        return RareControlTokenIndex(0, {}, {}, {}, {})
    source_index = {
        str(token): [(str(item[0]), str(item[1])) for item in postings if isinstance(item, list) and len(item) == 2]
        for token, postings in data.get("source_index", {}).items()
        if isinstance(postings, list)
    }
    return RareControlTokenIndex(
        component_count=int(data.get("component_count", 0) or 0),
        component_df={str(k): int(v) for k, v in data.get("component_df", {}).items()},
        function_df={str(k): int(v) for k, v in data.get("function_df", {}).items()},
        token_weight={str(k): float(v) for k, v in data.get("token_weight", {}).items()},
        source_index=source_index,
    )


def rare_control_token_shard(token: str) -> str:
    return hashlib.sha1(str(token).encode("utf-8")).hexdigest()[:2]


def load_rare_control_manifest(shard_dir: str = RARE_CONTROL_SHARD_DIR) -> dict:
    return read_json(os.path.join(shard_dir, "manifest.json"), {})


def load_rare_control_index_for_binary(
    bin_control_tokens: Dict[str, Set[str]],
    shard_dir: str = RARE_CONTROL_SHARD_DIR,
    legacy_path: str = RARE_CONTROL_INDEX_PATH,
) -> RareControlTokenIndex:
    wanted_tokens: Set[str] = set()
    for raw_tokens in bin_control_tokens.values():
        wanted_tokens.update(usable_control_tokens(set(raw_tokens)))
    if not wanted_tokens:
        return RareControlTokenIndex(0, {}, {}, {}, {})

    if os.path.isdir(shard_dir) and os.path.exists(os.path.join(shard_dir, "manifest.json")):
        wanted_by_shard: DefaultDict[str, Set[str]] = defaultdict(set)
        for token in wanted_tokens:
            wanted_by_shard[rare_control_token_shard(token)].add(token)

        token_weight: Dict[str, float] = {}
        source_index: Dict[str, List[Tuple[str, str]]] = {}
        for shard, tokens in wanted_by_shard.items():
            shard_data = read_json(os.path.join(shard_dir, f"{shard}.json"), {})
            shard_tokens = shard_data.get("tokens", {})
            if not isinstance(shard_tokens, dict):
                continue
            for token in tokens:
                record = shard_tokens.get(token)
                if not isinstance(record, dict):
                    continue
                postings = record.get("postings", [])
                if not isinstance(postings, list):
                    continue
                token_weight[token] = float(record.get("weight", 0.0) or 0.0)
                source_index[token] = [
                    (str(item[0]), str(item[1]))
                    for item in postings
                    if isinstance(item, list) and len(item) == 2
                ]
        return RareControlTokenIndex(0, {}, {}, token_weight, source_index)

    legacy_index = load_rare_control_token_index(legacy_path)
    if not legacy_index.token_weight:
        return legacy_index
    token_weight = {
        token: weight
        for token, weight in legacy_index.token_weight.items()
        if token in wanted_tokens
    }
    source_index = {
        token: legacy_index.source_index.get(token, [])
        for token in token_weight
    }
    return RareControlTokenIndex(
        legacy_index.component_count,
        {},
        {},
        token_weight,
        source_index,
    )


# Phase 1: dual-criterion candidate filtering


def filter_candidates_phase1a(
    bin_strings: Set[str],
    all_oss_unique_str: Dict[str, FrozenSet[str]],
) -> Set[str]:
    """String-based: ≥1 unique-string hit (quality-filtered)."""
    candidates: Set[str] = set()
    for oss_name, oss_uniq in all_oss_unique_str.items():
        if bin_strings & oss_uniq:
            candidates.add(oss_name)
    return candidates


def filter_candidates_phase1b(
    all_bin_nodes: Set[str],
    disc_funcname_index: Dict[str, Set[str]],
) -> Set[str]:
    """Symbol-based: ≥ PHASE1B_MIN_SYMBOL_HITS discriminative function name hits."""
    oss_hit_count: Counter = Counter()
    for bin_func in all_bin_nodes:
        if (
            bin_func in UNSUPPORTED_SYMBOLS
            or len(bin_func) < 5
            or is_generated_function_name(bin_func)
        ):
            continue
        for oss_name in disc_funcname_index.get(bin_func, set()):
            oss_hit_count[oss_name] += 1
    return {oss for oss, cnt in oss_hit_count.items() if cnt >= PHASE1B_MIN_SYMBOL_HITS}


def filter_candidates_phase15_control_recovery(
    bin_control_tokens: Dict[str, Set[str]],
    rare_control_index: RareControlTokenIndex,
    existing_candidates: Set[str],
    topk: int = PHASE15_RECOVERY_TOPK,
) -> Tuple[Set[str], Dict[str, Dict[str, Any]]]:
    """Recover component candidates from rare local control-token anchors."""
    if not rare_control_index.token_weight:
        return set(), {}

    component_score: Counter = Counter()
    component_pairs: DefaultDict[str, Dict[Tuple[str, str], float]] = defaultdict(dict)
    component_pair_tokens: DefaultDict[str, Dict[Tuple[str, str], Set[str]]] = defaultdict(lambda: defaultdict(set))

    for bin_func, raw_tokens in bin_control_tokens.items():
        rare_tokens = usable_control_tokens(set(raw_tokens)) & set(rare_control_index.token_weight)
        if not rare_tokens:
            continue

        pair_score: Counter = Counter()
        pair_tokens: DefaultDict[Tuple[str, str], Set[str]] = defaultdict(set)
        for token in rare_tokens:
            postings = rare_control_index.source_index.get(token, [])
            if not postings:
                continue
            weight = rare_control_index.token_weight[token]
            for oss_name, source_func in postings:
                if oss_name in existing_candidates:
                    continue
                key = (oss_name, source_func)
                pair_score[key] += weight
                pair_tokens[key].add(token)

        for (oss_name, source_func), score in pair_score.most_common(PHASE15_PAIR_TOPK_PER_BIN_FUNC):
            pair_key = (bin_func, source_func)
            previous = component_pairs[oss_name].get(pair_key, 0.0)
            if score > previous:
                component_score[oss_name] += score - previous
                component_pairs[oss_name][pair_key] = score
                component_pair_tokens[oss_name][pair_key].update(pair_tokens[(oss_name, source_func)])

    ranked = []
    for oss_name, score in component_score.items():
        pairs = component_pairs[oss_name]
        if not pairs:
            continue
        unique_bin_funcs = {bin_func for bin_func, _source_func in pairs}
        unique_source_funcs = {source_func for _bin_func, source_func in pairs}
        shared_tokens = set()
        for tokens in component_pair_tokens[oss_name].values():
            shared_tokens.update(tokens)
        ranked.append((
            (-score, -len(unique_bin_funcs), -len(unique_source_funcs), oss_name),
            oss_name,
            {
                "rare_control_score": score,
                "anchor_pair_count": len(pairs),
                "unique_binary_functions": len(unique_bin_funcs),
                "unique_source_functions": len(unique_source_funcs),
                "shared_rare_control_tokens": sorted(shared_tokens)[:20],
                "anchor_pairs_sample": [
                    {
                        "binary_function": bin_func,
                        "source_function": source_func,
                        "score": pairs[(bin_func, source_func)],
                        "tokens": sorted(component_pair_tokens[oss_name][(bin_func, source_func)])[:8],
                    }
                    for bin_func, source_func in sorted(pairs, key=lambda pair: -pairs[pair])[:8]
                ],
            },
        ))

    ranked.sort(key=lambda item: item[0])
    selected = ranked[:topk]
    return {oss_name for _rank, oss_name, _meta in selected}, {
        oss_name: meta for _rank, oss_name, meta in selected
    }


def filter_candidates_phase16_shared_evidence(
    bin_real_symbols: Set[str],
    bin_strings: Set[str],
    funcname_owner_index: Dict[str, Set[str]],
    string_owner_index: Dict[str, Set[str]],
    existing_candidates: Set[str],
    topk: int = PHASE16_SHARED_EVIDENCE_TOPK,
) -> Tuple[Set[str], Dict[str, Dict[str, Any]]]:
    """Recover candidates from non-unique symbols and non-unique strings."""
    symbol_hits: DefaultDict[str, Set[str]] = defaultdict(set)
    for symbol in bin_real_symbols:
        if symbol in UNSUPPORTED_SYMBOLS or is_generated_function_name(symbol):
            continue
        for oss_name in funcname_owner_index.get(symbol, set()):
            if oss_name not in existing_candidates:
                symbol_hits[oss_name].add(symbol)

    string_hits: DefaultDict[str, Set[str]] = defaultdict(set)
    for string_value in bin_strings:
        if string_value in GENERIC_SHARED_STRINGS:
            continue
        for oss_name in string_owner_index.get(string_value, set()):
            if oss_name not in existing_candidates:
                string_hits[oss_name].add(string_value)

    ranked = []
    for oss_name in set(symbol_hits) | set(string_hits):
        if oss_name in existing_candidates:
            continue
        shared_symbols = symbol_hits.get(oss_name, set())
        shared_strings = string_hits.get(oss_name, set())
        if not shared_symbols and not shared_strings:
            continue
        score = (len(shared_symbols) * 2.0) + (len(shared_strings) * 3.0)
        if score <= 0.0:
            continue
        ranked.append((
            (-score, -len(shared_symbols), -len(shared_strings), oss_name),
            oss_name,
            {
                "shared_evidence_score": score,
                "shared_symbol_count": len(shared_symbols),
                "shared_symbols_sample": sorted(shared_symbols)[:30],
                "shared_string_count": len(shared_strings),
                "shared_strings_sample": sorted(shared_strings)[:30],
            },
        ))

    ranked.sort(key=lambda item: item[0])
    selected = ranked[:topk]
    return {oss_name for _rank, oss_name, _meta in selected}, {
        oss_name: meta for _rank, oss_name, meta in selected
    }


def load_namespace_owner_index(path: str = NAMESPACE_OWNER_INDEX_PATH) -> Dict[str, str]:
    """Load globally-unique namespace token → OSS owner mapping."""
    data = read_json(path, {})
    owners = data.get("unique_owner_index", {}) if isinstance(data, dict) else {}
    return {str(token): str(owner) for token, owner in owners.items() if token and owner}


def collect_bin_identifier_pool(bin_control_blocks: Dict[str, List[dict]]) -> Set[str]:
    """Collect IDENTIFIER tokens that appear in control-block param_values."""
    ident_re = re.compile(r"IDENTIFIER,([A-Za-z_][A-Za-z0-9_]*)")
    pool: Set[str] = set()
    for blocks in bin_control_blocks.values():
        for block in blocks:
            if not isinstance(block, dict):
                continue
            for section_key in ("key_feature_dvector", "block_content_dvector"):
                section = block.get(section_key, {})
                if not isinstance(section, dict):
                    continue
                for value in section.values():
                    if isinstance(value, list):
                        for v in value:
                            if isinstance(v, str):
                                pool.update(ident_re.findall(v))
                    elif isinstance(value, str):
                        pool.update(ident_re.findall(value))
    return pool


def filter_candidates_phase17_namespace(
    bin_strings: Set[str],
    bin_identifier_pool: Set[str],
    namespace_owner_index: Dict[str, str],
    existing_candidates: Set[str],
) -> Tuple[Set[str], Dict[str, Dict[str, Any]]]:
    """Match unique namespace tokens against binary strings and IDENTIFIER residue."""
    if not namespace_owner_index:
        return set(), {}
    hits_by_oss: DefaultDict[str, Set[str]] = defaultdict(set)
    for token, owner in namespace_owner_index.items():
        if owner in existing_candidates:
            continue
        if token in bin_identifier_pool:
            hits_by_oss[owner].add(token)
            continue
        for bin_str in bin_strings:
            if bin_str and token in bin_str:
                hits_by_oss[owner].add(token)
                break
    meta: Dict[str, Dict[str, Any]] = {}
    selected: Set[str] = set()
    for oss_name, tokens in hits_by_oss.items():
        selected.add(oss_name)
        meta[oss_name] = {
            "namespace_hit_count": len(tokens),
            "namespace_hits_sample": sorted(tokens)[:10],
        }
    return selected, meta


# OssIndex builder


def build_oss_index(oss_name: str, local_disc_strings: FrozenSet[str]) -> Optional[OssIndex]:
    cache_key = (oss_name, local_disc_strings)
    cached = _OSS_INDEX_CACHE.get(cache_key)
    if cached is not None:
        return cached
    funcs_str = load_oss_funcstr_plain(oss_name)
    funcs_control = load_oss_control_tokens_plain(oss_name)
    funcs_control_blocks = load_oss_control_blocks_plain(oss_name)
    funcs_callstr = load_oss_callstr_plain(oss_name)
    funcs_symbols = load_oss_symbols_plain(oss_name)
    all_str = load_oss_all_strings(oss_name)
    callgraph = load_oss_callgraph(oss_name)
    reverse_cg = build_reverse_callgraph(callgraph)
    birthdate_by_plain = load_oss_func_name_dates(oss_name)

    funcs: Dict[str, OssFuncEntry] = {}
    plain_names = set(funcs_str) | set(funcs_control) | set(funcs_control_blocks) | set(funcs_callstr) | funcs_symbols | get_all_nodes(callgraph)
    if not plain_names:
        return None
    for plain_name in sorted(plain_names):
        strings = funcs_str.get(plain_name, set())
        quality_strings = frozenset(s for s in strings if len(s) >= MIN_ANCHOR_STR_LEN)
        funcs[plain_name] = OssFuncEntry(
            plain_name=plain_name,
            strings=quality_strings,
            control_tokens=frozenset(funcs_control.get(plain_name, set())),
            callstr_tokens=frozenset(funcs_callstr.get(plain_name, set())),
            control_blocks=tuple(funcs_control_blocks.get(plain_name, [])),
            birthdate=birthdate_by_plain.get(plain_name, ""),
        )

    funcs_by_local_str: DefaultDict[str, Set[str]] = defaultdict(set)
    funcs_by_string: DefaultDict[str, Set[str]] = defaultdict(set)
    for pn, entry in funcs.items():
        for s in entry.strings & local_disc_strings:
            funcs_by_local_str[s].add(pn)
        for s in entry.strings:
            funcs_by_string[s].add(pn)

    plain_self_strings = {pn: set(entry.strings) for pn, entry in funcs.items()}
    string_profiles = build_function_string_profiles(plain_self_strings, callgraph, reverse_cg)

    result = OssIndex(
        oss_name=oss_name,
        all_strings=all_str,
        funcs=funcs,
        funcs_by_local_str=dict(funcs_by_local_str),
        funcs_by_string=dict(funcs_by_string),
        callgraph=callgraph,
        reverse_cg=reverse_cg,
        reach_cache={},
        string_profiles=string_profiles,
        full_callgraph=callgraph,
        full_reverse_cg=reverse_cg,
    )
    _OSS_INDEX_CACHE[cache_key] = result
    return result


# Component validation


def validate_component(
    component: MatchedComponent,
    idx: OssIndex,
    bin_callgraph: Dict[str, List[str]],
    bin_reverse_cg: Dict[str, List[str]],
    bin_reach_cache: Dict[str, Set[str]],
    bin_string_profiles: Dict[str, FunctionStringProfile],
) -> Optional[MatchedComponent]:
    allow_single = component.phase in ("phase3_unified_direct",)
    is_symbol_phase = component.phase in {"phase2_symbol", "phase2_shared_symbol", "phase2_shared_symbol_set"}

    if not component.matched_pairs_plain:
        return None
    if not allow_single and len(component.matched_pairs_plain) < 2:
        return None

    for bin_func, oss_plain_name in list(component.matched_pairs_plain.items()):
        meta = component.matched_meta.setdefault(bin_func, {})
        if "string_graph_ok" not in meta:
            evidence = build_pair_string_graph_meta(bin_func, oss_plain_name, bin_string_profiles, idx)
            meta.update(evidence)
    remove_child_dependency_string_evidence(component)

    if allow_single:
        only_func = next(iter(component.matched_pairs_plain))
        meta = component.matched_meta[only_func]
        has_local_disc = len(meta.get("shared_local_disc_strings", [])) > 0
        if not has_local_disc:
            return None
        if not meta.get("string_graph_ok", True):
            return None
        component.direct_edge_count = 0
        component.reachable_edge_count = 0
        component.unsupported_edge_count = 0
        component.graph_decision = "single_direct_string_anchor"
        meta["graph_decision"] = component.graph_decision
        component.inlined_plain_symbols = set()
        return component

    if is_symbol_phase:
        # Phase 2 anchor is a structural signal; callgraph subgraph is the gate.
        pass
    else:
        has_valid_anchor = any(
            len(meta.get("shared_local_disc_strings", [])) > 0 and meta.get("string_graph_ok", True)
            for meta in component.matched_meta.values()
        )
        if not has_valid_anchor:
            return None

    if component.phase == "phase2_shared_symbol_set":
        if len(component.matched_pairs_plain) < 3:
            return None
        component.direct_edge_count = 0
        component.reachable_edge_count = 0
        component.unsupported_edge_count = 0
        component.graph_decision = "shared_symbol_set_supported_by_recovery"
        for meta in component.matched_meta.values():
            meta["graph_decision"] = component.graph_decision
            meta["supported_edge_count"] = 0
            meta["unsupported_edge_count"] = 0
        return component

    original_size = len(component.matched_pairs_plain)
    analysis = analyze_supported_edges_for_pairs(
        component.matched_pairs_plain,
        bin_callgraph,
        idx.callgraph,
        bin_reverse_cg,
        idx.reverse_cg,
        bin_reach_cache,
        idx.reach_cache,
    )
    groups = supported_node_groups(analysis)
    if not groups:
        for meta in component.matched_meta.values():
            meta["graph_decision"] = "rejected_unsupported_root"
        return None

    keep_nodes = groups[0][0]
    if len(keep_nodes) < original_size:
        component.matched_pairs_plain = {
            node: plain
            for node, plain in component.matched_pairs_plain.items()
            if node in keep_nodes
        }
        component.matched_meta = {
            node: meta
            for node, meta in component.matched_meta.items()
            if node in keep_nodes
        }

    trimmed_analysis = analyze_supported_edges_for_pairs(
        component.matched_pairs_plain,
        bin_callgraph,
        idx.callgraph,
        bin_reverse_cg,
        idx.reverse_cg,
        bin_reach_cache,
        idx.reach_cache,
    )
    direct_edges = trimmed_analysis["direct_edges"]
    reachable_edges = trimmed_analysis["reachable_edges"]
    inlined_edges = trimmed_analysis["inlined_edges"]
    unsupported_edges = trimmed_analysis["unsupported_edges"]
    inlined = set(trimmed_analysis["inlined_plain_symbols"])

    if direct_edges + reachable_edges + inlined_edges < 1 or len(component.matched_pairs_plain) < 2:
        for meta in component.matched_meta.values():
            meta["graph_decision"] = "insufficient_supported_subgraph"
        return None

    component.direct_edge_count = direct_edges
    component.reachable_edge_count = direct_edges + reachable_edges + inlined_edges
    component.unsupported_edge_count = unsupported_edges
    component.inlined_plain_symbols = set(inlined)
    if inlined_edges > 0:
        component.graph_decision = "callgraph_supported_with_inlining"
    elif len(keep_nodes) < original_size:
        component.graph_decision = "trimmed_unsupported_branch"
    else:
        component.graph_decision = "callgraph_supported_component"
    for meta in component.matched_meta.values():
        meta["graph_decision"] = component.graph_decision
        meta["supported_edge_count"] = component.reachable_edge_count
        meta["unsupported_edge_count"] = component.unsupported_edge_count
    return component


# Committed state helper


def build_committed_state(
    components: List[MatchedComponent],
) -> Tuple[Set[str], Dict[str, Set[str]]]:
    committed_bin_funcs: Set[str] = set()
    committed_plain_by_oss: DefaultDict[str, Set[str]] = defaultdict(set)
    for component in components:
        for bin_func, plain_name in component.matched_pairs_plain.items():
            committed_bin_funcs.add(bin_func)
            committed_plain_by_oss[component.oss_name].add(plain_name)
    return committed_bin_funcs, {k: set(v) for k, v in committed_plain_by_oss.items()}


# Phase 2: symbol matching


def build_phase2_components(
    candidate_names: List[str],
    oss_indices: Dict[str, OssIndex],
    all_bin_nodes: Set[str],
    disc_funcname_index: Dict[str, Set[str]],
    bin_callgraph: Dict[str, List[str]],
    bin_reverse_cg: Dict[str, List[str]],
    bin_reach_cache: Dict[str, Set[str]],
    bin_string_profiles: Dict[str, FunctionStringProfile],
) -> List[MatchedComponent]:
    components: List[MatchedComponent] = []

    for oss_name in candidate_names:
        idx = oss_indices.get(oss_name)
        if not idx:
            continue

        # Functions from the binary that appear in this OSS's callgraph
        shared_all = {
            sym for sym in all_bin_nodes
            if sym in idx.funcs
            and sym not in UNSUPPORTED_SYMBOLS
            and not is_generated_function_name(sym)
            and disc_funcname_index.get(sym) == {oss_name}
        }

        # Names are globally unique; don't exclude ones in another candidate's call_graph (forks).
        shared_symbols = shared_all
        if len(shared_symbols) < PHASE2_MIN_SIZE:
            continue

        supported_edges: List[Tuple[str, str, str]] = []
        for caller in shared_symbols:
            for callee in bin_callgraph.get(caller, []):
                if callee not in shared_symbols:
                    continue
                rel = relation_class(
                    caller, callee, caller, callee,
                    bin_callgraph, bin_reverse_cg,
                    idx.callgraph, idx.reverse_cg,
                    bin_reach_cache, idx.reach_cache,
                )
                if rel != "none":
                    supported_edges.append((caller, callee, rel))

        if len({node for edge in supported_edges for node in edge[:2]}) < PHASE2_MIN_SIZE:
            continue

        for node_group, _edge_count in supported_groups_from_edges(supported_edges):
            matched_pairs_plain = {node: node for node in node_group}
            matched_meta: Dict[str, Dict[str, Any]] = {}
            for node in node_group:
                sg_meta = build_pair_string_graph_meta(node, node, bin_string_profiles, idx)
                matched_meta[node] = {
                    "oss_plain_name": node,
                    "phase": "phase2_symbol",
                    "shared_local_disc_strings": [],
                    "shared_strings": [],
                    "shared_real_symbols": [node],
                    "control_block_jaccard": None,
                    "callstr_token_jaccard": None,
                    "relation_class": "symbol_exact_reachable",
                    **sg_meta,
                }
            component = MatchedComponent(
                oss_name=oss_name,
                phase="phase2_symbol",
                matched_pairs_plain=matched_pairs_plain,
                matched_meta=matched_meta,
            )
            validated = validate_component(
                component, idx, bin_callgraph, bin_reverse_cg, bin_reach_cache, bin_string_profiles
            )
            if validated is not None:
                components.append(validated)

    return components


def build_phase2_shared_symbol_components(
    candidate_names: List[str],
    oss_indices: Dict[str, OssIndex],
    all_bin_nodes: Set[str],
    bin_callgraph: Dict[str, List[str]],
    bin_reverse_cg: Dict[str, List[str]],
    bin_reach_cache: Dict[str, Set[str]],
    bin_string_profiles: Dict[str, FunctionStringProfile],
    recovery_meta: Dict[str, Dict[str, Any]],
) -> List[MatchedComponent]:
    components: List[MatchedComponent] = []

    for oss_name in candidate_names:
        idx = oss_indices.get(oss_name)
        if not idx or oss_name not in recovery_meta:
            continue

        shared_symbols = {
            sym for sym in all_bin_nodes
            if sym in idx.funcs
            and sym not in UNSUPPORTED_SYMBOLS
            and not is_generated_function_name(sym)
        }
        if len(shared_symbols) < PHASE2_MIN_SIZE:
            continue

        supported_edges: List[Tuple[str, str, str]] = []
        for caller in shared_symbols:
            for callee in bin_callgraph.get(caller, []):
                if callee not in shared_symbols:
                    continue
                rel = relation_class(
                    caller, callee, caller, callee,
                    bin_callgraph, bin_reverse_cg,
                    idx.callgraph, idx.reverse_cg,
                    bin_reach_cache, idx.reach_cache,
                )
                if rel != "none":
                    supported_edges.append((caller, callee, rel))

        if len({node for edge in supported_edges for node in edge[:2]}) < PHASE2_MIN_SIZE:
            continue

        for node_group, _edge_count in supported_groups_from_edges(supported_edges):
            matched_pairs_plain = {node: node for node in node_group}
            matched_meta: Dict[str, Dict[str, Any]] = {}
            for node in node_group:
                sg_meta = build_pair_string_graph_meta(node, node, bin_string_profiles, idx)
                matched_meta[node] = {
                    "oss_plain_name": node,
                    "phase": "phase2_shared_symbol",
                    "shared_local_disc_strings": [],
                    "shared_strings": [],
                    "shared_real_symbols": [node],
                    "control_block_jaccard": None,
                    "callstr_token_jaccard": None,
                    "relation_class": "shared_symbol_reachable",
                    "candidate_recovery": recovery_meta.get(oss_name, {}),
                    **sg_meta,
                }
            component = MatchedComponent(
                oss_name=oss_name,
                phase="phase2_shared_symbol",
                matched_pairs_plain=matched_pairs_plain,
                matched_meta=matched_meta,
            )
            validated = validate_component(
                component, idx, bin_callgraph, bin_reverse_cg, bin_reach_cache, bin_string_profiles
            )
            if validated is not None:
                components.append(validated)

    return components


def build_phase2_shared_symbol_set_components(
    candidate_names: List[str],
    oss_indices: Dict[str, OssIndex],
    all_bin_nodes: Set[str],
    bin_string_profiles: Dict[str, FunctionStringProfile],
    recovery_meta: Dict[str, Dict[str, Any]],
) -> List[MatchedComponent]:
    components: List[MatchedComponent] = []

    for oss_name in candidate_names:
        idx = oss_indices.get(oss_name)
        meta = recovery_meta.get(oss_name, {})
        if not idx or not meta:
            continue
        shared_symbol_count = int(meta.get("shared_symbol_count", 0) or 0)
        has_rare_control = "rare_control_score" in meta
        has_strong_shared_symbols = shared_symbol_count >= 8 and len(idx.funcs) <= 1000
        if not has_rare_control and not has_strong_shared_symbols:
            continue
        if has_rare_control and len(idx.funcs) > 100:
            continue

        shared_symbols = sorted(
            sym for sym in all_bin_nodes
            if sym in idx.funcs
            and sym not in UNSUPPORTED_SYMBOLS
            and not is_generated_function_name(sym)
        )
        if len(shared_symbols) < 3:
            continue

        matched_pairs_plain = {node: node for node in shared_symbols}
        matched_meta: Dict[str, Dict[str, Any]] = {}
        for node in shared_symbols:
            sg_meta = build_pair_string_graph_meta(node, node, bin_string_profiles, idx)
            matched_meta[node] = {
                "oss_plain_name": node,
                "phase": "phase2_shared_symbol_set",
                "shared_local_disc_strings": [],
                "shared_strings": [],
                "shared_real_symbols": [node],
                "control_block_jaccard": None,
                "callstr_token_jaccard": None,
                "relation_class": "shared_symbol_set",
                "candidate_recovery": meta,
                **sg_meta,
            }

        component = MatchedComponent(
            oss_name=oss_name,
            phase="phase2_shared_symbol_set",
            matched_pairs_plain=matched_pairs_plain,
            matched_meta=matched_meta,
        )
        components.append(component)

    return components


# Phase 3: locally-discriminative anchor + token Jaccard BFS


def choose_neighbor(
    bin_neighbor: str,
    matched_pairs_plain: Dict[str, str],
    idx: OssIndex,
    bin_callgraph: Dict[str, List[str]],
    bin_reverse_cg: Dict[str, List[str]],
    bin_string_refs: Dict[str, Set[str]],
    bin_control_tokens: Dict[str, Set[str]],
    bin_callstr_tokens: Dict[str, Set[str]],
    bin_string_profiles: Dict[str, FunctionStringProfile],
    bin_reach_cache: Dict[str, Set[str]],
    local_used_plain: Set[str],
    reject_stats: DefaultDict[str, int],
    llm_verifier: Optional[OllamaLLMVerifier] = None,
) -> Optional[Dict[str, Any]]:
    candidate_plains: Set[str] = set()
    for matched_plain in matched_pairs_plain.values():
        candidate_plains.update(get_neighbors(matched_plain, idx.callgraph, idx.reverse_cg))
    candidate_plains -= set(matched_pairs_plain.values())
    candidate_plains -= local_used_plain

    if not candidate_plains:
        return None

    bin_strings = bin_string_refs.get(bin_neighbor, set())
    bin_cb_tokens = bin_control_tokens.get(bin_neighbor, set())
    bin_callstr = bin_callstr_tokens.get(bin_neighbor, set())
    local_disc_strs = set(idx.funcs_by_local_str.keys())

    # Prioritize string-supported candidates for iteration order
    string_supported: Set[str] = set()
    for s in bin_strings:
        string_supported.update(idx.funcs_by_string.get(s, set()) & candidate_plains)
    ordered = list(string_supported) + [p for p in sorted(candidate_plains) if p not in string_supported]

    best_rank: Optional[Tuple] = None
    best_candidate: Optional[Dict[str, Any]] = None

    for plain_name in ordered:
        entry = idx.funcs.get(plain_name)
        if not entry:
            continue

        sg_meta = build_pair_string_graph_meta(bin_neighbor, plain_name, bin_string_profiles, idx)
        if not sg_meta["string_graph_ok"]:
            reject_stats["neighbor_string_graph_fail"] += 1
            continue

        relation_counts = phase35_relation_to_component(
            bin_neighbor, plain_name, matched_pairs_plain,
            bin_callgraph, bin_reverse_cg, idx, bin_reach_cache,
        )
        if relation_counts is None:
            reject_stats["relation_conflict"] += 1
            continue

        shared_local_disc = bin_strings & entry.strings & local_disc_strs
        shared_all = bin_strings & entry.strings
        control_sim = token_jaccard(bin_cb_tokens, set(entry.control_tokens))
        callstr_sim = token_jaccard(bin_callstr, set(entry.callstr_tokens))
        rank_sim = max(control_sim, callstr_sim)

        rank = anchor_rank_key(
            len(shared_local_disc), len(shared_all), rank_sim,
            True, entry.birthdate, plain_name,
        )

        if best_rank is None or rank < best_rank:
            best_rank = rank
            best_candidate = {
                "oss_plain_name": plain_name,
                "shared_local_disc_strings": sorted(shared_local_disc),
                "shared_strings": sorted(shared_all),
                "control_block_jaccard": control_sim,
                "callstr_token_jaccard": callstr_sim,
                **sg_meta,
            }

    return best_candidate


def run_phase3(
    candidate_names: List[str],
    oss_indices: Dict[str, OssIndex],
    bin_callgraph: Dict[str, List[str]],
    bin_reverse_cg: Dict[str, List[str]],
    bin_string_refs: Dict[str, Set[str]],
    bin_control_tokens: Dict[str, Set[str]],
    bin_callstr_tokens: Dict[str, Set[str]],
    bin_string_profiles: Dict[str, FunctionStringProfile],
    committed_components: List[MatchedComponent],
    bin_control_blocks: Optional[Dict[str, List[dict]]] = None,
    cb_db_dir: str = "",
    bin_reach_cache: Optional[Dict[str, Set[str]]] = None,
) -> Tuple[List[MatchedComponent], Dict[str, int]]:
    committed_bin_funcs, committed_plain_by_oss = build_committed_state(committed_components)
    if bin_reach_cache is None:
        bin_reach_cache = {}
    bfs_seeds: List[Dict[str, Any]] = []
    reject_stats: DefaultDict[str, int] = defaultdict(int)

    # Global inverted index disc_str -> pairs, plus per-oss disc-string cache.
    disc_str_to_pairs: DefaultDict[str, List[Tuple[str, str]]] = defaultdict(list)
    local_disc_strs_by_oss: Dict[str, Set[str]] = {}
    for oss_name in candidate_names:
        idx = oss_indices.get(oss_name)
        if not idx:
            continue
        local_disc_strs_by_oss[oss_name] = set(idx.funcs_by_local_str.keys())
        for s, plains in idx.funcs_by_local_str.items():
            for pn in plains:
                disc_str_to_pairs[s].append((oss_name, pn))

    for bin_func in sorted(bin_string_refs.keys()):
        if bin_func in committed_bin_funcs:
            continue
        bin_strings = bin_string_refs.get(bin_func, set())
        if not bin_strings:
            continue

        # Collect (oss_name, plain_name) pairs that share at least one disc string with bin_func.
        candidates_by_oss: DefaultDict[str, Set[str]] = defaultdict(set)
        for s in bin_strings:
            for oss_name, plain_name in disc_str_to_pairs.get(s, ()):
                candidates_by_oss[oss_name].add(plain_name)
        if not candidates_by_oss:
            continue

        bin_cb_tokens = bin_control_tokens.get(bin_func, set())
        bin_callstr = bin_callstr_tokens.get(bin_func, set())

        best_rank: Optional[Tuple] = None
        best_seed: Optional[Dict[str, Any]] = None

        for oss_name, candidate_plains in candidates_by_oss.items():
            idx = oss_indices.get(oss_name)
            if not idx:
                continue
            used_plain = committed_plain_by_oss.get(oss_name, set())
            candidate_plains = candidate_plains - used_plain
            if not candidate_plains:
                continue
            local_disc_strs = local_disc_strs_by_oss.get(oss_name, set())

            for plain_name in candidate_plains:
                entry = idx.funcs.get(plain_name)
                if not entry:
                    continue
                shared_local_disc = bin_strings & entry.strings & local_disc_strs
                if not shared_local_disc:
                    continue
                shared_all = bin_strings & entry.strings
                control_sim = token_jaccard(bin_cb_tokens, set(entry.control_tokens))
                callstr_sim = token_jaccard(bin_callstr, set(entry.callstr_tokens))
                rank_sim = max(control_sim, callstr_sim)
                sg_meta = build_pair_string_graph_meta(bin_func, plain_name, bin_string_profiles, idx)

                rank = anchor_rank_key(
                    len(shared_local_disc), len(shared_all), rank_sim,
                    sg_meta["string_graph_ok"], entry.birthdate, plain_name,
                )
                if best_rank is None or rank < best_rank:
                    best_rank = rank
                    best_seed = {
                        "oss_name": oss_name,
                        "bin_func": bin_func,
                        "plain_name": plain_name,
                        "shared_local_disc_strings": shared_local_disc,
                        "shared_strings": shared_all,
                        "control_block_jaccard": control_sim,
                        "callstr_token_jaccard": callstr_sim,
                        "string_graph_ok": sg_meta["string_graph_ok"],
                        "sg_meta": sg_meta,
                        "birthdate": entry.birthdate,
                        "rank": rank,
                    }

        if best_seed is None:
            continue

        # Only strong seeds (string_graph_ok==True) advance to BFS
        if best_seed["string_graph_ok"]:
            bfs_seeds.append(best_seed)

    # ANN-based seeds: block vector similarity + control token Jaccard, no string anchor required
    if bin_control_blocks and cb_db_dir:
        import cb_index as cbi
        if cbi.has_index(cb_db_dir):
            candidate_set = set(candidate_names)
            seeded_bin_funcs: Set[str] = {s["bin_func"] for s in bfs_seeds}

            queries: List[Tuple[str, bytes]] = []
            for func_name, blocks in bin_control_blocks.items():
                if func_name in committed_bin_funcs or func_name in seeded_bin_funcs:
                    continue
                for block in blocks:
                    if block.get("block_type", "") not in _CB_ANN_INTERNAL_TYPES:
                        continue
                    vec = cbi.kfv_to_bytes(block.get("key_feature_vector", ""))
                    if vec is not None:
                        queries.append((func_name, vec))

            for i in range(0, len(queries), CB_ANN_BATCH):
                chunk = queries[i: i + CB_ANN_BATCH]
                vecs = [v for _, v in chunk]
                func_names_chunk = [f for f, _ in chunk]
                try:
                    batch_results = cbi.search_batch(vecs, cb_db_dir, top_k=CB_ANN_TOP_K, max_hamming=CB_ANN_MAX_HAMMING)
                except Exception:
                    continue

                # Aggregate per bin_func: (comp, oss_func) -> (min_hamming, hit_count)
                func_pairs: DefaultDict[str, DefaultDict[Tuple[str, str], List[int]]] = defaultdict(lambda: defaultdict(list))
                for bin_func, hits in zip(func_names_chunk, batch_results):
                    for h in hits:
                        comp = h["component"]
                        if comp not in candidate_set:
                            continue
                        func_pairs[bin_func][(comp, h["function_name"])].append(h["distance"])

                for bin_func, pairs in func_pairs.items():
                    if bin_func in seeded_bin_funcs:
                        continue
                    bin_tokens = bin_control_tokens.get(bin_func, set())

                    best_rank: Optional[tuple] = None
                    best_seed: Optional[Dict[str, Any]] = None

                    for (comp, oss_func), dists in pairs.items():
                        idx = oss_indices.get(comp)
                        if not idx:
                            continue
                        entry = idx.funcs.get(oss_func)
                        if not entry:
                            continue

                        min_dist = min(dists)
                        hit_count = len(dists)
                        oss_tokens = set(entry.control_tokens)
                        token_j = token_jaccard(bin_tokens, oss_tokens)

                        if hit_count < 2 and token_j < 0.05:
                            continue

                        hamming_norm = min_dist / cbi.CB_VECTOR_DIM
                        rank = (1, hamming_norm, -token_j, -hit_count, date_sort_key(entry.birthdate), oss_func)
                        if best_rank is None or rank < best_rank:
                            best_rank = rank
                            sg_meta = build_pair_string_graph_meta(bin_func, oss_func, bin_string_profiles, idx)
                            best_seed = {
                                "oss_name":                  comp,
                                "bin_func":                  bin_func,
                                "plain_name":                oss_func,
                                "shared_local_disc_strings": set(),
                                "shared_strings":            set(),
                                "control_block_jaccard":     token_j,
                                "callstr_token_jaccard":     0.0,
                                "string_graph_ok":           True,
                                "sg_meta":                   sg_meta,
                                "birthdate":                 entry.birthdate,
                                "source":                    "ann_cb",
                                "rank":                      rank,
                            }

                    if best_seed:
                        bfs_seeds.append(best_seed)
                        seeded_bin_funcs.add(bin_func)

    # Higher-evidence seeds run first (fewer conflicts when committing)
    bfs_seeds.sort(key=lambda s: s["rank"])

    direct_components: List[MatchedComponent] = []
    expanded_components: List[MatchedComponent] = []

    for seed in bfs_seeds:
        if seed["bin_func"] in committed_bin_funcs:
            continue
        oss_name = seed["oss_name"]
        idx = oss_indices.get(oss_name)
        if not idx:
            continue
        if seed["plain_name"] in committed_plain_by_oss.get(oss_name, set()):
            continue

        sg_meta = seed["sg_meta"]
        matched_pairs_plain: Dict[str, str] = {seed["bin_func"]: seed["plain_name"]}
        matched_meta: Dict[str, Dict[str, Any]] = {
            seed["bin_func"]: {
                "oss_plain_name": seed["plain_name"],
                "phase": "phase35_controlblock_callstr",
                "shared_local_disc_strings": sorted(seed["shared_local_disc_strings"]),
                "shared_strings": sorted(seed["shared_strings"]),
                "control_block_jaccard": seed["control_block_jaccard"],
                "callstr_token_jaccard": seed["callstr_token_jaccard"],
                "relation_class": "seed_direct_string_controlblock",
                "string_graph_ok": True,
                "string_graph_reason": sg_meta["string_graph_reason"],
                "caller_required_strings": sg_meta["caller_required_strings"],
                "callee_required_strings": sg_meta["callee_required_strings"],
                "caller_missing_required": sg_meta["caller_missing_required"],
                "callee_missing_required": sg_meta["callee_missing_required"],
                "caller_wrong_direction_hits": sg_meta["caller_wrong_direction_hits"],
                "callee_wrong_direction_hits": sg_meta["callee_wrong_direction_hits"],
            }
        }

        local_used_bin: Set[str] = set(committed_bin_funcs)
        local_used_plain: Set[str] = set(committed_plain_by_oss.get(oss_name, set()))
        local_used_bin.add(seed["bin_func"])
        local_used_plain.add(seed["plain_name"])
        frontier: deque = deque([seed["bin_func"]])

        while frontier:
            current_bin = frontier.popleft()
            for bin_neighbor in sorted(get_neighbors(current_bin, bin_callgraph, bin_reverse_cg)):
                if bin_neighbor in local_used_bin:
                    continue
                best_nbr = choose_neighbor(
                    bin_neighbor, matched_pairs_plain, idx,
                    bin_callgraph, bin_reverse_cg,
                    bin_string_refs, bin_control_tokens, bin_callstr_tokens, bin_string_profiles,
                    bin_reach_cache, local_used_plain, reject_stats,
                )
                if not best_nbr:
                    continue
                pn = best_nbr["oss_plain_name"]
                matched_pairs_plain[bin_neighbor] = pn
                matched_meta[bin_neighbor] = {
                    "oss_plain_name": pn,
                    "phase": "phase35_controlblock_callstr",
                    "shared_local_disc_strings": best_nbr["shared_local_disc_strings"],
                    "shared_strings": best_nbr["shared_strings"],
                    "control_block_jaccard": best_nbr["control_block_jaccard"],
                    "callstr_token_jaccard": best_nbr["callstr_token_jaccard"],
                    "relation_class": "expanded_controlblock_callstr",
                    "string_graph_ok": best_nbr["string_graph_ok"],
                    "string_graph_reason": best_nbr["string_graph_reason"],
                    "caller_required_strings": best_nbr["caller_required_strings"],
                    "callee_required_strings": best_nbr["callee_required_strings"],
                    "caller_missing_required": best_nbr["caller_missing_required"],
                    "callee_missing_required": best_nbr["callee_missing_required"],
                    "caller_wrong_direction_hits": best_nbr["caller_wrong_direction_hits"],
                    "callee_wrong_direction_hits": best_nbr["callee_wrong_direction_hits"],
                }
                local_used_bin.add(bin_neighbor)
                local_used_plain.add(pn)
                frontier.append(bin_neighbor)

        if len(matched_pairs_plain) == 1:
            single_meta = dict(matched_meta[seed["bin_func"]])
            single_meta["phase"] = "phase3_unified_direct"
            single_component = MatchedComponent(
                oss_name=oss_name,
                phase="phase3_unified_direct",
                matched_pairs_plain={seed["bin_func"]: seed["plain_name"]},
                matched_meta={seed["bin_func"]: single_meta},
            )
            validated = validate_component(
                single_component, idx, bin_callgraph, bin_reverse_cg, bin_reach_cache, bin_string_profiles
            )
            if validated:
                direct_components.append(validated)
                committed_bin_funcs.add(seed["bin_func"])
                committed_plain_by_oss.setdefault(oss_name, set()).add(seed["plain_name"])
            continue

        component = MatchedComponent(
            oss_name=oss_name,
            phase="phase35_controlblock_callstr",
            matched_pairs_plain=matched_pairs_plain,
            matched_meta=matched_meta,
        )
        validated = validate_component(
            component, idx, bin_callgraph, bin_reverse_cg, bin_reach_cache, bin_string_profiles
        )
        if validated is not None and len(validated.matched_pairs_plain) >= PHASE3_MIN_SIZE:
            expanded_components.append(validated)
            for bf, pn in validated.matched_pairs_plain.items():
                committed_bin_funcs.add(bf)
                committed_plain_by_oss.setdefault(oss_name, set()).add(pn)
        else:
            # Multi-function validation failed: seed alone as single-function direct
            single_meta = dict(matched_meta[seed["bin_func"]])
            single_meta["phase"] = "phase3_unified_direct"
            single_component = MatchedComponent(
                oss_name=oss_name,
                phase="phase3_unified_direct",
                matched_pairs_plain={seed["bin_func"]: seed["plain_name"]},
                matched_meta={seed["bin_func"]: single_meta},
            )
            validated_single = validate_component(
                single_component, idx, bin_callgraph, bin_reverse_cg, bin_reach_cache, bin_string_profiles
            )
            if validated_single:
                direct_components.append(validated_single)
                committed_bin_funcs.add(seed["bin_func"])
                committed_plain_by_oss.setdefault(oss_name, set()).add(seed["plain_name"])

    return direct_components + expanded_components, dict(reject_stats)


# Overlap resolution


def build_overlap_clusters(
    components: List[MatchedComponent],
    bin_callgraph: Dict[str, List[str]],
    reverse_cg: Dict[str, List[str]],
) -> List[Set[str]]:
    owners_by_node: DefaultDict[str, Set[int]] = defaultdict(set)
    for i, component in enumerate(components):
        for node in component.matched_pairs_plain:
            owners_by_node[node].add(i)
    overlap_nodes = {node for node, owners in owners_by_node.items() if len(owners) >= 2}
    if not overlap_nodes:
        return []
    return weak_components_subset(overlap_nodes, bin_callgraph, reverse_cg)


def count_subset_supported_edges(
    component: MatchedComponent,
    cluster_nodes: Set[str],
    idx: OssIndex,
    bin_callgraph: Dict[str, List[str]],
    bin_reverse_cg: Dict[str, List[str]],
) -> int:
    subset_pairs = {
        node: pn
        for node, pn in component.matched_pairs_plain.items()
        if node in cluster_nodes
    }
    if len(subset_pairs) <= 1 and component.phase == "phase3_unified_direct":
        return 0
    direct_edges, reachable_edges, _, _ = count_supported_edges_for_pairs(
        subset_pairs,
        bin_callgraph,
        idx.callgraph,
        bin_reverse_cg,
        idx.reverse_cg,
        {},
        {},
    )
    return direct_edges + reachable_edges


def cluster_birthdate_votes(
    candidate_indices: List[int],
    components: List[MatchedComponent],
    cluster_nodes: Set[str],
    oss_indices: Dict[str, OssIndex],
) -> Dict[int, int]:
    votes: DefaultDict[int, int] = defaultdict(int)
    for node in cluster_nodes:
        dated = []
        for i in candidate_indices:
            component = components[i]
            if node not in component.matched_pairs_plain:
                continue
            idx = oss_indices.get(component.oss_name)
            if not idx:
                continue
            plain_name = component.matched_pairs_plain[node]
            entry = idx.funcs.get(plain_name)
            date = entry.birthdate if entry else ""
            if date:
                dated.append((i, date))
        if len(dated) < 2:
            continue
        earliest = min(date for _, date in dated)
        winners = [i for i, date in dated if date == earliest]
        if len(winners) == 1:
            votes[winners[0]] += 1
    return dict(votes)


def split_component_after_trim(
    component: MatchedComponent,
    idx: OssIndex,
    bin_callgraph: Dict[str, List[str]],
    bin_reverse_cg: Dict[str, List[str]],
) -> List[MatchedComponent]:
    remaining_nodes = set(component.matched_pairs_plain.keys())
    if not remaining_nodes:
        return []

    if component.phase == "phase3_unified_direct":
        return [
            MatchedComponent(
                oss_name=component.oss_name,
                phase=component.phase,
                matched_pairs_plain={node: component.matched_pairs_plain[node]},
                matched_meta={node: component.matched_meta[node]},
            )
            for node in sorted(remaining_nodes)
        ]

    supported_edges: List[Tuple[str, str, str]] = []
    for caller in remaining_nodes:
        for callee in bin_callgraph.get(caller, []):
            if callee not in remaining_nodes:
                continue
            rel = relation_class(
                caller, callee,
                component.matched_pairs_plain[caller],
                component.matched_pairs_plain[callee],
                bin_callgraph, bin_reverse_cg,
                idx.callgraph, idx.reverse_cg,
                {}, {},
            )
            if rel != "none":
                supported_edges.append((caller, callee, rel))

    if len({node for edge in supported_edges for node in edge[:2]}) < 2:
        return []

    out: List[MatchedComponent] = []
    for node_group, _edge_count in supported_groups_from_edges(supported_edges):
        out.append(MatchedComponent(
            oss_name=component.oss_name,
            phase=component.phase,
            matched_pairs_plain={node: component.matched_pairs_plain[node] for node in node_group},
            matched_meta={node: component.matched_meta[node] for node in node_group},
        ))
    return out


def resolve_component_overlaps(
    components: List[MatchedComponent],
    oss_indices: Dict[str, OssIndex],
    bin_callgraph: Dict[str, List[str]],
    bin_reverse_cg: Dict[str, List[str]],
    bin_string_profiles: Dict[str, FunctionStringProfile],
) -> List[MatchedComponent]:
    changed = True
    while changed:
        changed = False
        clusters = build_overlap_clusters(components, bin_callgraph, bin_reverse_cg)
        if not clusters:
            break

        for cluster_nodes in clusters:
            candidate_indices = [
                i for i, c in enumerate(components)
                if set(c.matched_pairs_plain.keys()) & cluster_nodes
            ]
            if len(candidate_indices) < 2:
                continue

            edge_scores: Dict[int, int] = {}
            for i in candidate_indices:
                idx = oss_indices.get(components[i].oss_name)
                if not idx:
                    continue
                edge_scores[i] = count_subset_supported_edges(
                    components[i], cluster_nodes, idx, bin_callgraph, bin_reverse_cg
                )
            birth_votes = cluster_birthdate_votes(
                candidate_indices, components, cluster_nodes, oss_indices
            )
            dependency_children = load_dependency_children()
            hub_components = load_hub_components()
            dependency_child_votes: Dict[int, int] = {}
            candidate_names = {i: components[i].oss_name for i in candidate_indices}
            for i, oss_name in candidate_names.items():
                dependency_child_votes[i] = sum(
                    1
                    for j, parent_name in candidate_names.items()
                    if i != j and oss_name in dependency_children.get(parent_name, set())
                )

            winner = sorted(
                candidate_indices,
                key=lambda i: (
                    # Vendoring hub never wins over a non-hub.
                    1 if components[i].oss_name in hub_components else 0,
                    -dependency_child_votes.get(i, 0),
                    -edge_scores.get(i, 0),
                    -birth_votes.get(i, 0),
                    components[i].oss_name,
                    components[i].phase,
                ),
            )[0]

            for i in candidate_indices:
                if i == winner:
                    continue
                to_remove = set(components[i].matched_pairs_plain.keys()) & cluster_nodes
                for node in to_remove:
                    components[i].matched_pairs_plain.pop(node, None)
                    components[i].matched_meta.pop(node, None)
                changed = True

        if changed:
            rebuilt: List[MatchedComponent] = []
            for c in components:
                idx = oss_indices.get(c.oss_name)
                if not idx:
                    continue
                rebuilt.extend(split_component_after_trim(c, idx, bin_callgraph, bin_reverse_cg))
            components = rebuilt

    validated: List[MatchedComponent] = []
    bin_reach_cache: Dict[str, Set[str]] = {}
    for component in components:
        idx = oss_indices.get(component.oss_name)
        if not idx:
            continue
        checked = validate_component(
            component, idx, bin_callgraph, bin_reverse_cg, bin_reach_cache, bin_string_profiles
        )
        if checked:
            validated.append(checked)
    return validated


# Final merge and reporting


def merge_components_by_oss(components: List[MatchedComponent]) -> List[dict]:
    merged: Dict[str, dict] = {}
    for component in components:
        entry = merged.setdefault(
            component.oss_name,
            {
                "name": component.oss_name,
                "graph_size": 0,
                "matched_pairs": {},
                "matched_meta": {},
                "inlined_funcs": set(),
                "phases": set(),
                "graph_decisions": set(),
            },
        )
        for bin_func, plain_name in component.matched_pairs_plain.items():
            if bin_func in entry["matched_pairs"] and entry["matched_pairs"][bin_func] != plain_name:
                continue
            entry["matched_pairs"][bin_func] = plain_name
            entry["matched_meta"][bin_func] = component.matched_meta.get(bin_func, {})
        entry["inlined_funcs"].update(component.inlined_plain_symbols)
        entry["phases"].add(component.phase)
        if component.graph_decision:
            entry["graph_decisions"].add(component.graph_decision)

    for entry in merged.values():
        entry["graph_size"] = len(entry["matched_pairs"])
        entry["phases"] = sorted(entry["phases"])
        entry["graph_decisions"] = sorted(entry["graph_decisions"])

    return sorted(merged.values(), key=lambda item: (-item["graph_size"], item["name"]))


def attach_dependency_children(detected_oss: List[dict], dependency_children: Dict[str, Set[str]]) -> List[dict]:
    detected_names = {item["name"] for item in detected_oss}
    for item in detected_oss:
        children = sorted(child for child in dependency_children.get(item["name"], set()) if child not in detected_names)
        item["dependency_children"] = children
    return detected_oss


def llm_suppress_fp(
    detected_oss: List[dict],
    llm_verifier: "OllamaLLMVerifier",
    overlap_threshold: float = 0.5,
) -> List[dict]:
    """Use LLM to suppress false positives whose matched functions overlap heavily with a larger already-detected component."""
    if not llm_verifier.config.enabled:
        return detected_oss

    # Build per-component oss_plain_name sets from matched_pairs
    oss_funcs_by_comp: Dict[str, Set[str]] = {
        item["name"]: set(item.get("matched_pairs", {}).values())
        for item in detected_oss
    }
    by_name = {item["name"]: item for item in detected_oss}

    suppressed: Set[str] = set()
    # Check smaller components first
    for item in sorted(detected_oss, key=lambda x: x["graph_size"]):
        name = item["name"]
        if name in suppressed:
            continue
        my_funcs = oss_funcs_by_comp.get(name, set())
        if not my_funcs:
            continue

        # Find dominant overlap among other (larger) detected components
        best_comp, best_overlap = None, set()
        for other_name, other_funcs in oss_funcs_by_comp.items():
            if other_name == name or other_name in suppressed:
                continue
            if by_name[other_name]["graph_size"] <= item["graph_size"]:
                continue
            overlap = my_funcs & other_funcs
            if len(overlap) > len(best_overlap):
                best_comp, best_overlap = other_name, overlap

        if not best_comp:
            continue
        overlap_ratio = len(best_overlap) / len(my_funcs)
        if overlap_ratio < overlap_threshold:
            continue

        unique_funcs = sorted(my_funcs - best_overlap)
        overlap_funcs = sorted(best_overlap)
        log(f"    [LLM-FP] checking {name} (overlap {overlap_ratio:.0%} with {best_comp})")
        if llm_verifier.verify_fp(item, by_name[best_comp], overlap_funcs, unique_funcs):
            suppressed.add(name)

    return [item for item in detected_oss if item["name"] not in suppressed]


def suppress_weak_shared_symbol_roots(
    detected_oss: List[dict],
    oss_indices: Dict[str, OssIndex],
) -> List[dict]:
    """Drop detections that rest entirely on shared (non-unique) symbol evidence."""
    out = []
    shared_only_phases = {"phase2_shared_symbol", "phase2_shared_symbol_set"}
    for item in detected_oss:
        phases = set(item.get("phases", []))
        if phases <= shared_only_phases:
            if item.get("graph_size", 0) < MIN_SHARED_ONLY_GRAPH_SIZE:
                continue
        out.append(item)
    return out


COHERENCE_MIN_FUNCS = 3
COHERENCE_THRESHOLD = 0.20


def suppress_by_match_quality(
    detected_oss: List[dict],
    threshold: float = COHERENCE_THRESHOLD,
) -> List[dict]:
    """Suppress components whose Phase 2-3 CB matches are collectively weak."""
    out = []
    for item in detected_oss:
        meta = item.get("matched_meta", {})
        scores = [
            m.get("control_block_structural_similarity", 0.0)
            for m in meta.values()
            if isinstance(m, dict) and "control_block_structural_similarity" in m
        ]
        if len(scores) < COHERENCE_MIN_FUNCS:
            out.append(item)
            continue
        mean_score = sum(scores) / len(scores)
        if mean_score < threshold:
            log(
                f"    [-] Suppressing {item['name']}: "
                f"mean CB similarity {mean_score:.3f} < {threshold} "
                f"({len(scores)} pairs)"
            )
            continue
        out.append(item)
    return out


def suppress_subcomponent_spillover(
    detected_oss: List[dict],
    component_functions: Dict[str, Dict[str, dict]],
    dependency_children: Dict[str, Set[str]],
    llm_verifier: Optional["OllamaLLMVerifier"] = None,
    hub_components: Optional[Set[str]] = None,
) -> List[dict]:
    """Suppress a parent whose every matched function also lives in a known sub-component."""
    detected_names = {item["name"] for item in detected_oss}
    out: List[dict] = []
    for item in detected_oss:
        name = item["name"]
        children = dependency_children.get(name, set())
        if hub_components and name not in hub_components:
            # Hub edges are ~symmetric; a hub is the derivative, never a child.
            children = children - hub_components
        if not children:
            out.append(item)
            continue

        bucket = component_functions.get(name, {})
        if not bucket:
            out.append(item)
            continue

        # Build plain_name → list of (function_id, observed_in_set)
        funcs_by_plain: DefaultDict[str, List[Tuple[str, Set[str]]]] = defaultdict(list)
        for fid, meta in bucket.items():
            fname = meta.get("function_name", "")
            if fname:
                funcs_by_plain[fname].append((fid, set(meta.get("observed_in", []))))

        own_unique_to_parent: Set[str] = set()  # plain_names not present in any child
        shared_with_children: Set[str] = set()  # plain_names present in ≥1 child
        contributing_children: Set[str] = set()

        for _bin_func, plain_name in item.get("matched_pairs", {}).items():
            records = funcs_by_plain.get(plain_name, [])
            if not records:
                continue
            present_in_child = False
            for _fid, observed in records:
                overlap = observed & children
                if overlap:
                    present_in_child = True
                    contributing_children.update(overlap)
                    break
            if present_in_child:
                shared_with_children.add(plain_name)
            else:
                own_unique_to_parent.add(plain_name)

        if not shared_with_children:
            out.append(item)
            continue
        if own_unique_to_parent:
            # Parent has a matched func absent from every child → genuine; keep.
            out.append(item)
            continue

        # 100% of matched functions also exist inside a known sub-component.
        children_detected = contributing_children & detected_names
        if children_detected:
            log(
                f"    [-] Suppressing {name}: every matched function is also in "
                f"detected sub-component(s) {sorted(children_detected)}"
            )
            continue

        # Sub-components not independently detected → ambiguous. LLM verify.
        if llm_verifier is not None and llm_verifier.config.enabled:
            is_spillover = llm_verifier.verify_spillover(
                name,
                sorted(shared_with_children),
                sorted(contributing_children),
            )
            if is_spillover:
                continue
        elif hub_components and name in hub_components:
            # No LLM: hub fully explained by a known sub-component → drop.
            log(
                f"    [-] Suppressing {name}: 100% subcomponent overlap with "
                f"{sorted(contributing_children)} and {name} is a known vendoring hub"
            )
            continue
        else:
            log(
                f"    [?] {name}: 100% subcomponent overlap with "
                f"{sorted(contributing_children)} but no LLM verifier — keeping"
            )
        out.append(item)
    return out


def expand_dependency_children(
    detected_oss: List[dict],
    dependency_children: Dict[str, Set[str]],
    oss_indices: Dict[str, OssIndex],
    all_oss_unique_str: Dict[str, FrozenSet[str]],
    disc_funcname_index: Dict[str, Set[str]],
    bin_real_symbols: Set[str],
    bin_callgraph: Dict[str, List[str]],
    bin_reverse_cg: Dict[str, List[str]],
    bin_string_refs: Dict[str, Set[str]],
    bin_control_tokens: Dict[str, Set[str]],
    bin_callstr_tokens: Dict[str, Set[str]],
    bin_string_profiles: Dict[str, FunctionStringProfile],
) -> List[dict]:
    expanded = list(detected_oss)
    detected_names = {item["name"] for item in expanded}
    parents = list(expanded)

    for parent in parents:
        parent_name = parent["name"]
        for child in sorted(dependency_children.get(parent_name, set())):
            if child in detected_names:
                continue
            idx = oss_indices.get(child)
            if idx is None:
                idx = build_oss_index(child, all_oss_unique_str.get(child, frozenset()))
                if idx is None:
                    continue
                oss_indices[child] = idx

            child_reach_cache: Dict[str, Set[str]] = {}
            phase2_components = build_phase2_components(
                [child],
                oss_indices,
                bin_real_symbols,
                disc_funcname_index,
                bin_callgraph,
                bin_reverse_cg,
                child_reach_cache,
                bin_string_profiles,
            )
            phase2_components = resolve_component_overlaps(
                phase2_components,
                oss_indices,
                bin_callgraph,
                bin_reverse_cg,
                bin_string_profiles,
            )
            phase3_components, _stats = run_phase3(
                [child],
                oss_indices,
                bin_callgraph,
                bin_reverse_cg,
                bin_string_refs,
                bin_control_tokens,
                bin_callstr_tokens,
                bin_string_profiles,
                phase2_components,
            )
            child_components = resolve_component_overlaps(
                phase2_components + phase3_components,
                oss_indices,
                bin_callgraph,
                bin_reverse_cg,
                bin_string_profiles,
            )
            child_results = [
                item
                for item in merge_components_by_oss(child_components)
                if item["name"] == child and item["graph_size"] >= 2
            ]
            child_results = suppress_isolated_matches(child_results, bin_callgraph, bin_reverse_cg, oss_indices)
            if not child_results:
                continue

            child_result = child_results[0]
            child_phases = set(child_result.get("phases", []))
            if (
                child_result.get("graph_size", 0) < MIN_DEPENDENCY_CHILD_GRAPH_SIZE
                and not (child_phases & {"phase35_controlblock_callstr", "phase3_unified_direct"})
            ):
                continue
            child_result["decision"] = "dependency_supported_component"
            child_result["introduced_by"] = parent_name
            child_result["dependency_children"] = []
            expanded.append(child_result)
            detected_names.add(child)

    return expanded


def _has_callgraph_connection(
    funcs: List[str],
    callgraph: Dict[str, List[str]],
    reverse_cg: Dict[str, List[str]],
) -> bool:
    """Return True if any two functions in the list are connected (1-hop direct or 2-hop sibling)."""
    funcs_set = set(funcs)
    # 1-hop: direct neighbor
    for f in funcs:
        if (set(callgraph.get(f, [])) | set(reverse_cg.get(f, []))) & funcs_set:
            return True
    # 2-hop: shared caller (siblings under a common parent)
    callers = {f: set(reverse_cg.get(f, [])) for f in funcs}
    for i in range(len(funcs)):
        for j in range(i + 1, len(funcs)):
            if callers[funcs[i]] & callers[funcs[j]]:
                return True
    return False


_SUPPRESS_MIN_LOCAL_DISC_TOTAL = 3  # total local-disc strings across all matched funcs


def suppress_isolated_matches(
    detected_oss: List[dict],
    bin_callgraph: Dict[str, List[str]],
    bin_reverse_cg: Dict[str, List[str]],
    oss_indices: Optional[Dict[str, "OssIndex"]] = None,
) -> List[dict]:
    """Suppress OSS detected only via disconnected single-function Phase 3 matches."""
    kept = []
    for oss_info in detected_oss:
        phases = set(oss_info.get("phases", []))
        if phases - {"phase3_unified_direct"}:
            kept.append(oss_info)
            continue

        bin_funcs = list(oss_info["matched_pairs"].keys())
        oss_funcs = list(oss_info["matched_pairs"].values())

        # Binary-side connectivity
        if _has_callgraph_connection(bin_funcs, bin_callgraph, bin_reverse_cg):
            kept.append(oss_info)
            continue

        # OSS-side connectivity uses the full pre-dedup callgraph (keeps bridge funcs).
        if oss_indices is not None:
            idx = oss_indices.get(oss_info["name"])
            if idx and _has_callgraph_connection(oss_funcs, idx.full_callgraph, idx.full_reverse_cg):
                kept.append(oss_info)
                continue

    return kept


# Per-binary component list output (consumed later by Binary_SBOM_Generation.py)


def load_component_release_meta(oss_name: str) -> Optional[Dict[str, str]]:
    """Read version/purl/license/type recorded by OSScollector.py for this component."""
    path = os.path.join(REPO_META_DIR, f"{oss_name}.txt")
    try:
        with open(path, "r", encoding="utf-8") as f:
            first_line = f.readline().strip()
    except OSError:
        return None
    if not first_line:
        return None
    parts = [part.strip() for part in first_line.split(",")]
    if len(parts) < 4:
        return None
    reference_ref, purl, license_id, component_type = parts[0], parts[1], parts[2], parts[3]
    # Match the collector's normalization without damaging tags such as
    # "version-1.900.1". This is a source DB ref, not a detected binary version.
    version = re.sub(r"^[vV]\.?(?=\d)", "", reference_ref)
    return {
        "version": version,
        "reference_ref": reference_ref,
        "purl": purl,
        "license": license_id,
        "type": component_type,
    }


def write_binary_components_json(binary_name: str, detected_oss: List[dict]) -> str:
    """Write output/{binary}/{binary}.components.json, the input Binary_SBOM_Generation.py expects when generating the CycloneDX SBOM for this binary."""
    components = []
    for oss_info in detected_oss:
        oss_name = oss_info["name"]
        meta = load_component_release_meta(oss_name)
        if not meta:
            print(f"    [!] No release metadata for {oss_name}; skipping in components.json")
            continue
        components.append({
            "name": oss_name.split("@@")[-1],
            "version": meta["version"],
            "type": meta["type"],
            "purl": meta["purl"],
            "licenses": [{"license": {"id": meta["license"]}}],
            # Keep legacy version/purl fields, but make their origin explicit so
            # consumers cannot mistake a reference release for an installed one.
            "properties": [
                {"name": "bolt:binary:version-source", "value": "reference-metadata"},
                {"name": "bolt:binary:component-id", "value": oss_name},
                {"name": "bolt:binary:reference-ref", "value": meta["reference_ref"]},
            ],
        })
    output_bin_dir = os.path.join(OUTPUT_DIR, binary_name)
    os.makedirs(output_bin_dir, exist_ok=True)
    components_path = os.path.join(output_bin_dir, f"{binary_name}.components.json")
    with open(components_path, "w", encoding="utf-8") as f:
        json.dump(components, f, indent=4)
    return components_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Detect OSS components in target binaries."
    )
    parser.add_argument(
        "--llm",
        action="store_true",
        help="Enable the Ollama LLM verifier for FP suppression (off by default).",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print full phase-by-phase progress output.",
    )
    parser.add_argument(
        "binaries",
        nargs="*",
        help="Target binary names to process. Defaults to all in target/bin.",
    )
    return parser.parse_args()


def main() -> None:
    global VERBOSE
    args = parse_args()
    VERBOSE = args.verbose
    llm_verifier: Optional[OllamaLLMVerifier] = None
    if args.llm:
        llm_verifier = OllamaLLMVerifier(LLMVerifierConfig(
            enabled=True,
            model=os.environ.get("OLLAMA_MODEL", "qwen3-coder:30b-a3b-q4_K_M"),
            url=os.environ.get("OLLAMA_URL", "http://localhost:11434/api/chat"),
            timeout=float(os.environ.get("OLLAMA_TIMEOUT", "120")),
            min_confidence=float(os.environ.get("LLM_MIN_CONFIDENCE", "0.65")),
            max_candidate_checks=int(os.environ.get("LLM_MAX_CANDIDATE_CHECKS", "4")),
            temperature=float(os.environ.get("LLM_TEMPERATURE", "0.0")),
            top_p=float(os.environ.get("LLM_TOP_P", "0.1")),
            repeat_penalty=float(os.environ.get("LLM_REPEAT_PENALTY", "1.05")),
            max_prompt_chars=int(os.environ.get("LLM_MAX_PROMPT_CHARS", "24000")),
        ))

    if not has_componentdb_layout():
        print(f"[!] Missing new ComponentDB layout under {COMPONENT_DB_DIR}")
        print("    Run: uv run python src/preprocessor.py")
        return

    log("[*] Building startup indexes...")
    (
        disc_funcname_index,
        funcname_owner_index,
        all_oss_unique_str,
        string_owner_index,
        used_precomputed_startup,
    ) = load_startup_indexes()
    rare_control_shard_dir = RARE_CONTROL_INDEX_PATH if os.path.isdir(RARE_CONTROL_INDEX_PATH) else RARE_CONTROL_SHARD_DIR
    rare_control_manifest = load_rare_control_manifest(rare_control_shard_dir)
    namespace_owner_index = load_namespace_owner_index()
    dependency_children = load_dependency_children()
    hub_components = load_hub_components()
    child_to_parents = load_child_to_parents()
    available_comp_set = set(available_components())
    log(f"    startup_index: {'precomputed JSON' if used_precomputed_startup else 'fallback scan'}")
    log(f"    disc_funcname_index: {len(disc_funcname_index)} discriminative names")
    log(f"    funcname_owner_index: {len(funcname_owner_index)} real names")
    log(f"    all_oss_unique_str: {len(all_oss_unique_str)} OSS with quality unique strings")
    log(f"    string_owner_index: {len(string_owner_index)} strings")
    log(f"    namespace_owner_index: {len(namespace_owner_index)} unique tokens")
    if rare_control_manifest:
        log(
            f"    rare_control_token_index: {rare_control_manifest.get('token_count', 0)} tokens "
            f"in {rare_control_manifest.get('shard_count', 0)} shards"
        )
    else:
        log("    rare_control_token_index: shard manifest unavailable; legacy JSON will be loaded only if Phase 1.5 runs")

    binary_reports: Dict[str, List[Tuple[str, int]]] = {}
    available_binaries = sorted(os.listdir(TARGET_BIN_DIR))
    if args.binaries:
        requested = set(args.binaries)
        filenames = [name for name in available_binaries if name in requested]
        missing = sorted(requested - set(filenames))
        for missing_name in missing:
            log(f"[!] Requested binary not found: {missing_name}")
    else:
        filenames = available_binaries

    for filename in filenames:
        print(f"[*] Processing Binary: {filename}")
        log(f"\n{'=' * 60}")
        log(f"[*] Processing Binary: {filename}")
        log(f"{'=' * 60}")

        bin_callgraph = load_bin_callgraph(filename)
        all_bin_nodes = get_all_nodes(bin_callgraph)
        bin_string_refs = load_bin_func_string_refs(filename)
        bin_control_tokens = load_bin_control_tokens(filename)
        bin_control_blocks = load_bin_control_blocks(filename)
        bin_callstr_tokens = load_bin_callstr_tokens(filename)
        bin_strings = load_bin_strings(filename)
        bin_real_symbols = load_bin_real_symbols(filename)

        bin_reverse_cg = build_reverse_callgraph(bin_callgraph)
        bin_reach_cache: Dict[str, Set[str]] = {}

        bin_string_profiles = build_function_string_profiles(
            {func_name: set(strings) for func_name, strings in bin_string_refs.items()},
            bin_callgraph,
            bin_reverse_cg,
        )

        mode_str = "Stripped" if is_stripped_binary(all_bin_nodes) else "Non-Stripped"
        log(f"\n    Binary Info:")
        log(f"        - Functions in callgraph: {len(all_bin_nodes)}")
        log(f"        - Real symbols: {len(bin_real_symbols)}")
        log(f"        - Functions with string refs: {len(bin_string_refs)}")
        log(f"        - Functions with control tokens: {len(bin_control_tokens)}")
        log(f"        - Functions with control blocks: {len(bin_control_blocks)}")
        log(f"        - Functions with CALLSTR tokens: {len(bin_callstr_tokens)}")
        log(f"        - Mode: {mode_str}")

        if not bin_callgraph:
            log("    [!] Missing callgraph")
            write_binary_components_json(filename, [])
            binary_reports[filename] = []
            continue

        log(f"\n[Phase 1] Dual-Criterion Candidate Filtering")
        log(f"{'-' * 50}")
        p1a = filter_candidates_phase1a(bin_strings, all_oss_unique_str)
        p1b = filter_candidates_phase1b(bin_real_symbols, disc_funcname_index)
        candidate_set = p1a | p1b
        p15: Set[str] = set()
        p15_meta: Dict[str, Dict[str, Any]] = {}
        if mode_str == "Stripped" or not candidate_set:
            rare_control_index = load_rare_control_index_for_binary(
                bin_control_tokens,
                rare_control_shard_dir,
                RARE_CONTROL_INDEX_PATH,
            )
            p15, p15_meta = filter_candidates_phase15_control_recovery(
                bin_control_tokens,
                rare_control_index,
                candidate_set,
            )
            candidate_set |= p15
        p16, p16_meta = filter_candidates_phase16_shared_evidence(
            bin_real_symbols,
            bin_strings,
            funcname_owner_index,
            string_owner_index,
            candidate_set,
        )
        candidate_set |= p16
        bin_identifier_pool = collect_bin_identifier_pool(bin_control_blocks)
        p17, p17_meta = filter_candidates_phase17_namespace(
            bin_strings,
            bin_identifier_pool,
            namespace_owner_index,
            candidate_set,
        )
        candidate_set |= p17

        _cb_db_dir = os.path.join(currentPath, "database")

        recovered_candidate_meta: Dict[str, Dict[str, Any]] = {}
        recovered_candidate_meta.update(p15_meta)
        recovered_candidate_meta.update(p16_meta)
        recovered_candidate_meta.update(p17_meta)
        log(f"    Phase 1a (string): {len(p1a)} candidates")
        log(f"    Phase 1b (symbol): {len(p1b)} candidates")
        log(f"    Phase 1.5 (rare control recovery): {len(p15)} candidates")
        log(f"    Phase 1.6 (shared evidence recovery): {len(p16)} candidates")
        log(f"    Phase 1.7 (namespace substring): {len(p17)} candidates")
        log(f"    Total unique candidates: {len(candidate_set)}")

        if not candidate_set:
            log("    [!] No OSS candidates found")
            write_binary_components_json(filename, [])
            binary_reports[filename] = []
            continue

        # Phase 3 seeds use globally component-unique strings (avoid fork overlaps).
        local_disc_map = {
            oss_name: all_oss_unique_str.get(oss_name, frozenset())
            for oss_name in sorted(candidate_set)
        }

        candidate_names = sorted(candidate_set)
        oss_indices: Dict[str, OssIndex] = {}
        for oss_name in candidate_names:
            local_disc = local_disc_map.get(oss_name, frozenset())
            idx = build_oss_index(oss_name, local_disc)
            if idx:
                oss_indices[oss_name] = idx
                p1a_hit = len(all_oss_unique_str.get(oss_name, frozenset()) & bin_strings)
                recovery_meta = recovered_candidate_meta.get(oss_name, {})
                via = f"{'1a' if oss_name in p1a else ''}{'1b' if oss_name in p1b else ''}{'1.5' if oss_name in p15 else ''}{'1.6' if oss_name in p16 else ''}"
                recovery_suffix = ""
                if recovery_meta:
                    parts = []
                    if "rare_control_score" in recovery_meta:
                        parts.append(f"rare_cb_score={recovery_meta.get('rare_control_score', 0.0):.2f}")
                        parts.append(f"rare_cb_pairs={recovery_meta.get('anchor_pair_count', 0)}")
                    if "shared_evidence_score" in recovery_meta:
                        parts.append(f"shared_score={recovery_meta.get('shared_evidence_score', 0.0):.2f}")
                        parts.append(f"shared_symbols={recovery_meta.get('shared_symbol_count', 0)}")
                        parts.append(f"shared_strings={recovery_meta.get('shared_string_count', 0)}")
                    recovery_suffix = ", " + ", ".join(parts) if parts else ""
                log(
                    f"    - {oss_name}: unique_hit={p1a_hit}, "
                    f"local_disc={len(local_disc)}, funcs={len(idx.funcs)}, "
                    f"via={via}{recovery_suffix}"
                )

        candidate_names = [n for n in candidate_names if n in oss_indices]
        if not candidate_names:
            log("    [!] No usable OSS indices built")
            write_binary_components_json(filename, [])
            binary_reports[filename] = []
            continue

        log(f"\n[Phase 2] Symbol Cluster Matching")
        log(f"{'-' * 50}")
        phase2_components = build_phase2_components(
            candidate_names, oss_indices, bin_real_symbols,
            disc_funcname_index,
            bin_callgraph, bin_reverse_cg, bin_reach_cache, bin_string_profiles,
        )
        phase2_shared_components = build_phase2_shared_symbol_components(
            candidate_names, oss_indices, bin_real_symbols,
            bin_callgraph, bin_reverse_cg, bin_reach_cache, bin_string_profiles,
            recovered_candidate_meta,
        )
        phase2_symbol_set_components = build_phase2_shared_symbol_set_components(
            candidate_names, oss_indices, bin_real_symbols,
            bin_string_profiles,
            recovered_candidate_meta,
        )
        phase2_symbol_set_components = [
            checked
            for component in phase2_symbol_set_components
            for checked in [validate_component(
                component,
                oss_indices[component.oss_name],
                bin_callgraph,
                bin_reverse_cg,
                bin_reach_cache,
                bin_string_profiles,
            )]
            if checked is not None
        ]
        phase2_components = resolve_component_overlaps(
            phase2_components + phase2_shared_components,
            oss_indices, bin_callgraph, bin_reverse_cg, bin_string_profiles,
        )
        log(f"    Components: {len(phase2_components)}")
        for component in phase2_components:
            sg_summary = get_component_string_graph_summary(component)
            log(
                f"    - {component.oss_name}: nodes={len(component.matched_pairs_plain)}, "
                f"supported_edges={component.reachable_edge_count}, "
                f"required_strings={sg_summary['required_caller_count'] + sg_summary['required_callee_count']}"
            )

        log(f"\n[Phase 3] Locally-Discriminative Anchor + ControlBlock/CALLSTR BFS")
        log(f"{'-' * 50}")
        phase3_components, phase3_stats = run_phase3(
            candidate_names, oss_indices,
            bin_callgraph, bin_reverse_cg,
            bin_string_refs, bin_control_tokens, bin_callstr_tokens,
            bin_string_profiles, phase2_components,
            bin_control_blocks=bin_control_blocks,
            cb_db_dir=_cb_db_dir,
            bin_reach_cache=bin_reach_cache,
        )
        direct_count = sum(1 for c in phase3_components if c.phase == "phase3_unified_direct")
        expanded_count = sum(1 for c in phase3_components if c.phase == "phase35_controlblock_callstr")
        log(f"    Direct Matches: {direct_count}")
        log(f"    Expanded Components: {expanded_count}")
        if phase3_stats:
            log(f"    Reject Reasons: {dict(sorted(phase3_stats.items()))}")
        for component in phase3_components[:DEBUG_STRING_PRINT_LIMIT]:
            first_bin = next(iter(component.matched_pairs_plain))
            meta = component.matched_meta.get(first_bin, {})
            log(
                f"    - {component.oss_name}: {first_bin} -> {component.matched_pairs_plain[first_bin]} "
                f"(phase={component.phase}, local_disc={len(meta.get('shared_local_disc_strings', []))}, "
                f"cb_sim={meta.get('control_block_jaccard', 0.0):.2f}, "
                f"callstr_sim={meta.get('callstr_token_jaccard', 0.0):.2f})"
            )

        final_components = resolve_component_overlaps(
            phase2_components + phase3_components,
            oss_indices, bin_callgraph, bin_reverse_cg, bin_string_profiles,
        )
        final_names = {component.oss_name for component in final_components}
        final_components.extend(
            component for component in phase2_symbol_set_components
            if component.oss_name not in final_names
        )
        detected_oss = [r for r in merge_components_by_oss(final_components) if r["graph_size"] >= 2]
        detected_oss = suppress_isolated_matches(detected_oss, bin_callgraph, bin_reverse_cg, oss_indices)
        detected_oss = suppress_weak_shared_symbol_roots(detected_oss, oss_indices)
        detected_oss = suppress_by_match_quality(detected_oss)
        detected_oss = suppress_subcomponent_spillover(
            detected_oss,
            load_component_functions(),
            dependency_children,
            llm_verifier,
            hub_components,
        )
        if llm_verifier and llm_verifier.config.enabled:
            log("\n[LLM-FP] Verifying overlapping detections...")
            detected_oss = llm_suppress_fp(detected_oss, llm_verifier)
        detected_oss = expand_dependency_children(
            detected_oss,
            dependency_children,
            oss_indices,
            all_oss_unique_str,
            disc_funcname_index,
            bin_real_symbols,
            bin_callgraph,
            bin_reverse_cg,
            bin_string_refs,
            bin_control_tokens,
            bin_callstr_tokens,
            bin_string_profiles,
        )
        detected_oss = attach_dependency_children(detected_oss, dependency_children)

        if not detected_oss:
            print("\n    [!] No OSS detected")
            write_binary_components_json(filename, [])
            binary_reports[filename] = []
            continue

        print("\n    Detected OSS components:")
        for oss_info in detected_oss:
            child_suffix = ""
            if oss_info.get("dependency_children"):
                child_suffix = f", Dependency Children = {','.join(oss_info['dependency_children'])}"
            decision_suffix = ""
            if oss_info.get("decision"):
                decision_suffix = f", Decision = {oss_info['decision']}"
            if oss_info.get("introduced_by"):
                decision_suffix += f", Introduced By = {oss_info['introduced_by']}"
            graph_suffix = ""
            if oss_info.get("graph_decisions"):
                graph_suffix = f", Graph Decisions = {','.join(oss_info['graph_decisions'])}"
            print(
                f"        - {oss_info['name']}: Graph Size = {oss_info['graph_size']}, "
                f"Matched Pairs = {len(oss_info['matched_pairs'])}, "
                f"Phases = {','.join(oss_info['phases'])}"
                f"{decision_suffix}"
                f"{graph_suffix}"
                f"{child_suffix}"
            )

        components_path = write_binary_components_json(filename, detected_oss)
        log(f"\n    [*] Wrote component list: {components_path}")

        binary_reports[filename] = [
            (oss_info["name"], oss_info["graph_size"]) for oss_info in detected_oss
        ]

    print(f"\n{'=' * 60}")
    print("[*] Final Report")
    print(f"{'=' * 60}")
    for binary_name, oss_results in binary_reports.items():
        print(f"\n{binary_name}")
        if not oss_results:
            print("    [!] No OSS detected")
            continue
        for oss_name, graph_size in sorted(oss_results, key=lambda item: item[0]):
            print(f"    [+] {oss_name} (graph_size={graph_size})")
    print()


if __name__ == "__main__":
    main()
