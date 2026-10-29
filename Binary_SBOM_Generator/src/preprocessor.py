"""
Source-provenance DB builder.

Builds a compact component DB for the detector:
- source functions are anchored by exact TLSH only
- vendored code is attributed to its origin component, not the parent repo
- a 2nd-pass callee-equality check re-classifies implicit code copies that
  were missed by TLSH / git-submodule detection
"""

import io
import json
import hashlib
import math
import os
import re
import signal
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))

from utils.function_preprocessing import CBMaker


currentPath = os.getcwd()
osscollectorPath = os.path.join(currentPath, "osscollector")

resultPath = os.path.join(osscollectorPath, "repo_functions")
funcCodePath = os.path.join(osscollectorPath, "repo_funcCode")
funcMetaSidecarPath = os.path.join(osscollectorPath, "repo_funcMeta")

finalDBPath = os.path.join(currentPath, "database", "componentDB")
provenancePath = os.path.join(currentPath, "database", "provenance")
functionFeaturesPath = os.path.join(currentPath, "database", "functionFeatures")
rareControlIndexPath = os.path.join(finalDBPath, "rare_control_token_index.json")
startupIndexPath = os.path.join(finalDBPath, "startup_index.json")
rareControlShardDir = os.path.join(finalDBPath, "rare_control_token_index")

componentFeatureDirs = {
	"control_blocks": os.path.join(finalDBPath, "control_blocks"),
	"strings":        os.path.join(finalDBPath, "strings"),
	"symbols":        os.path.join(finalDBPath, "symbols"),
	"callstr_tokens": os.path.join(finalDBPath, "callstr_tokens"),
	"call_graph":     os.path.join(finalDBPath, "call_graph"),
}

for directory in (finalDBPath, provenancePath, functionFeaturesPath, rareControlShardDir, *componentFeatureDirs.values()):
	os.makedirs(directory, exist_ok=True)


FORMAT_PATTERN = re.compile(r"^%[-+0 #]*(\d+|\*)?(\.(\d+|\*))?[hlLzjt]*[diouxXeEfFgGaAcspn%]$")
FORMAT_ONLY_PATTERN = re.compile(r"^[\s%\-+0-9.#hlLzjtdiouxXeEfFgGaAcspn\[\]\(\)\{\}:,'\"\ntr]*$")
PATH_PATTERN = re.compile(r"^([a-zA-Z]:)?[\\/][^\s]+")
GENERATED_SYMBOL_PATTERN = re.compile(r"^(FUN|sub|func|loc|LAB|unk)_[0-9A-Fa-f]+$")

VENDORED_DIR_NAMES = {
	"third_party",
	"thirdparty",
	"3rdparty",
	"third-party",
	"vendor",
	"external",
	"externals",
	"deps",
	"contrib",
	"dependencies",
	"extern",
}

UNSUPPORTED_SOURCE_SYMBOLS = {
	"",
	"_start",
	"entry",
	"main",
	"usage",
	"__libc_start_main",
}

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


class TimeoutException(Exception):
	pass


def timeout_handler(_signum, _frame):
	raise TimeoutException("Processing timeout")


def normalize_text(text):
	return (
		str(text)
		.replace("\\n", "")
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


def is_path_string(value):
	return isinstance(value, str) and bool(PATH_PATTERN.match(value.strip()))


def path_basename_hint(value):
	if not is_path_string(value):
		return ""
	cleaned = value.strip().strip("\"'").replace("\\", "/").rstrip("/")
	basename = cleaned.rsplit("/", 1)[-1].strip()
	if not basename or len(basename) < 4:
		return ""
	if FORMAT_PATTERN.match(basename):
		return ""
	return basename.lower()


def is_discriminative_string(value):
	if not isinstance(value, str):
		return False
	text = value.strip()
	if not text or len(text) < 4:
		return False
	if is_path_string(text):
		return False
	if FORMAT_PATTERN.match(text):
		return False
	if FORMAT_ONLY_PATTERN.match(text) and "%" in text:
		return False
	return True


def normalize_startup_string(value):
	if not is_discriminative_string(value):
		return ""
	return "".join(str(value).strip().lower().split())


def classify_source_symbol_kind(symbol):
	name = str(symbol or "").strip()
	if name in UNSUPPORTED_SOURCE_SYMBOLS:
		return "unsupported"
	if GENERATED_SYMBOL_PATTERN.match(name):
		return "generated"
	return "real"


def normalize_callee_name(value):
	return str(value or "").strip()


def extract_callstr_tokens_from_blocks(blocks, filter_discriminative=False):
	tokens = set()
	for block in blocks:
		if not isinstance(block, dict) or block.get("block_type") != "String":
			continue
		raw_strings = block.get("key_feature_dvector", {}).get("literal_values", [])
		block_content = block.get("block_content_dvector", {})
		caller_values = block_content.get("function_values", ["assign"]) if isinstance(block_content, dict) else ["assign"]
		caller = caller_values[0] if caller_values else "assign"
		for literal in raw_strings:
			if is_path_string(literal):
				continue
			if filter_discriminative and not is_discriminative_string(literal):
				continue
			norm = normalize_text(literal)
			if not norm:
				continue
			if caller == "assign":
				tokens.add(f"ASSIGNSTR:{norm}")
			elif caller == "callfunc":
				tokens.add(f"CALLSTR:{norm}")
			else:
				tokens.add(f"LIBCALLSTR:{caller}:{norm}")
	return tokens


def normalize_feature_token(value):
	return "".join(str(value or "").lower().split())


def collect_scalar_control_tokens(prefix, value, out):
	if isinstance(value, dict):
		for key, child in value.items():
			collect_scalar_control_tokens(f"{prefix}:{key}", child, out)
		return
	if isinstance(value, list):
		for child in value:
			collect_scalar_control_tokens(prefix, child, out)
		return
	token = normalize_feature_token(value)
	if token and len(token) >= 2 and not is_noise_control_token_value(prefix, token):
		out.add(f"{prefix}:{token}")


def is_noise_control_token_value(prefix, value):
	field = str(prefix or "").lower()
	if value in GENERIC_CONTROL_NUMBERS and field.endswith("numbers"):
		return True
	if field.endswith("function_values") and value in GENERIC_CONTROL_FUNCTION_VALUES:
		return True
	if field.endswith("literal_values") and not is_discriminative_string(value):
		return True
	if "param_values" in field:
		generic_param = re.sub(r"\(identifier,[lp]var\)|[;(),]", "", value)
		if not generic_param or len(value) < 16:
			return True
	return False


def control_block_tokens_for_recovery(blocks):
	tokens = set()
	for block in blocks or []:
		if not isinstance(block, dict):
			continue
		key_features = block.get("key_feature_dvector", {})
		if isinstance(key_features, dict):
			for key, value in key_features.items():
				collect_scalar_control_tokens(f"KEY:{key}", value, tokens)
		block_content = block.get("block_content_dvector", {})
		if isinstance(block_content, dict):
			for key, value in block_content.items():
				collect_scalar_control_tokens(f"CONTENT:{key}", value, tokens)
	return tokens


def control_token_type_weight(token):
	lowered = token.lower()
	if "literal_values" in lowered:
		return 1.35
	if "function_values" in lowered:
		return 1.25
	if "param_values" in lowered:
		return 1.1
	if lowered.endswith(":numbers") or ":numbers:" in lowered:
		return 0.8
	return 1.0


def build_rare_control_index_document(component_count, component_df, function_df, postings):
	rare_component_df_cap = max(2, int(math.ceil(component_count * 0.02))) if component_count else 0
	token_weight = {}
	source_index = {}
	for token, df in component_df.items():
		if df > rare_component_df_cap:
			continue
		if function_df[token] > 500:
			continue
		idf = math.log((component_count + 1.0) / (df + 1.0))
		weight = idf * control_token_type_weight(token)
		if weight <= 0.0:
			continue
		token_weight[token] = weight
		source_index[token] = [[component, function_name] for component, function_name in postings[token]]

	return {
		"component_count": component_count,
		"component_df": dict(sorted(component_df.items())),
		"function_df": dict(sorted(function_df.items())),
		"token_weight": dict(sorted(token_weight.items())),
		"source_index": dict(sorted(source_index.items())),
		"policy": {
			"component_df_cap": rare_component_df_cap,
			"max_function_df": 500,
			"noise_filtered": True,
			"usage": "candidate_recovery_only",
		},
	}


def rare_control_token_shard(token):
	digest = hashlib.sha1(str(token).encode("utf-8")).hexdigest()
	return digest[:2]


def write_rare_control_shards(rare_control_index):
	shard_root = Path(rareControlShardDir)
	for path in shard_root.glob("*.json"):
		path.unlink()

	token_weight = rare_control_index.get("token_weight", {})
	source_index = rare_control_index.get("source_index", {})
	shards = defaultdict(dict)
	for token, postings in source_index.items():
		shard = rare_control_token_shard(token)
		shards[shard][token] = {
			"weight": token_weight.get(token, 0.0),
			"postings": postings,
		}
	for shard, tokens in shards.items():
		write_json_file(str(shard_root / f"{shard}.json"), {
			"tokens": tokens,
		})

	write_json_file(str(shard_root / "manifest.json"), {
		"shard_count": len(shards),
		"token_count": len(source_index),
		"shard_mod": 256,
		"hash": "sha1_prefix_2_hex",
	})


HUB_NEIGHBOR_THRESHOLD = 8


def _hub_components(dependency_children):
	"""Components that vendor/share code with many others (benchmark harnesses like
	lzbench/TurboBench/precomp-cpp) rather than being a single distinct origin.

	dependency_children edges are recorded per-file and end up roughly symmetric for
	these aggregator repos, so a plain undirected neighbor count identifies them
	without needing to hardcode names.
	"""
	neighbors = defaultdict(set)
	for parent, children in dependency_children.items():
		for child in children:
			neighbors[parent].add(child)
			neighbors[child].add(parent)
	return {c for c, n in neighbors.items() if len(n) >= HUB_NEIGHBOR_THRESHOLD}


def _unique_owner_map(owners_by_key, hubs):
	"""key -> single owner, tolerant of hub-vendored duplicates.

	A hub only ever copies code from elsewhere, so its presence in another
	component's owner set is not a real collision (Tier 1-3 provenance already
	knows the true origin, but that resolution never reaches the raw per-file
	strings/symbols feature extraction — this recovers it at index-build time).
	A hub itself only earns "unique" credit for keys nobody else holds at all
	(its own harness/glue code), never for code it merely vendors.
	"""
	unique = {}
	for key, owners in owners_by_key.items():
		if len(owners) == 1:
			unique[key] = next(iter(owners))
			continue
		non_hub_owners = owners - hubs
		if len(non_hub_owners) == 1:
			(owner,) = non_hub_owners
			unique[key] = owner
	return unique


def build_startup_index_document(component_summaries, symbol_owners, string_owners, strings_by_component, dependency_children=None):
	hubs = _hub_components(dependency_children or {})

	unique_string_owner = _unique_owner_map(string_owners, hubs)

	all_oss_unique_str = defaultdict(list)
	for string_value, owner in unique_string_owner.items():
		all_oss_unique_str[owner].append(string_value)
	all_oss_unique_str = {
		component: sorted(strings)
		for component, strings in sorted(all_oss_unique_str.items())
	}

	unique_symbol_owner = _unique_owner_map(symbol_owners, hubs)
	disc_funcname_index = defaultdict(list)
	for symbol, owner in unique_symbol_owner.items():
		if len(symbol) >= 5:
			disc_funcname_index[symbol].append(owner)

	return {
		"version": 1,
		"component_count": len(component_summaries),
		"hub_components": sorted(hubs),
		"disc_funcname_index": {
			symbol: sorted(owners)
			for symbol, owners in sorted(disc_funcname_index.items())
		},
		"funcname_owner_index": {
			symbol: sorted(owners)
			for symbol, owners in sorted(symbol_owners.items())
			if len(symbol) >= 3
		},
		"all_oss_unique_str": all_oss_unique_str,
		"string_owner_index": {
			string_value: sorted(owners)
			for string_value, owners in sorted(string_owners.items())
		},
		"policy": {
			"strings": "normalized quality strings from componentDB/strings",
			"symbols": "real source symbols only",
		},
	}


def process_func_file_to_controlblock(func_file_path, output_json_path, timeout_seconds=60):
	old_stdout = sys.stdout
	old_stderr = sys.stderr
	old_handler = None
	try:
		old_handler = signal.signal(signal.SIGALRM, timeout_handler)
		signal.alarm(timeout_seconds)
		language = "cpp" if str(func_file_path).endswith((".cpp", ".cc")) else "c"
		analyzer = CBMaker(language=language)
		sys.stdout = io.StringIO()
		sys.stderr = io.StringIO()
		analyzer.analyze_file(func_file_path, output_json_path)
		signal.alarm(0)
		sys.stdout = old_stdout
		sys.stderr = old_stderr
		if old_handler:
			signal.signal(signal.SIGALRM, old_handler)
		return Path(output_json_path).exists(), None
	except TimeoutException:
		return False, f"Timeout after {timeout_seconds} seconds"
	except Exception as exc:
		return False, str(exc)
	finally:
		signal.alarm(0)
		sys.stdout = old_stdout
		sys.stderr = old_stderr
		if old_handler:
			signal.signal(signal.SIGALRM, old_handler)


def source_language_for_file(file_path):
	return "cpp" if str(file_path).endswith((".cpp", ".cc", ".cxx")) else "c"


def sanitize_version_name(version_name):
	return str(version_name).replace("/", "_").replace("\\", "_")


def parse_hidx_line(line):
	parts = [part.strip() for part in line.strip().split(",")]
	if not parts or not parts[0]:
		return None, []
	func_hash = parts[0]
	occurrences = []
	rest = parts[1:]
	for idx in range(0, len(rest) - 2, 3):
		func_name = rest[idx]
		param_count = rest[idx + 1]
		src_path = rest[idx + 2]
		if src_path.startswith("/"):
			occurrences.append({
				"path": src_path,
				"function_name": func_name,
				"param_count": param_count,
			})
	return func_hash, occurrences


def load_collector_function_meta(repo_name, version_name):
	meta_file = Path(funcMetaSidecarPath) / repo_name / f"fuzzy_{sanitize_version_name(version_name)}.json"
	if not meta_file.is_file():
		return {}
	try:
		return json.loads(meta_file.read_text(encoding="utf-8"))
	except Exception:
		return {}


def load_source_occurrences():
	occurrences = []
	root = Path(resultPath)
	if not root.is_dir():
		return occurrences
	for repo_dir in sorted(path for path in root.iterdir() if path.is_dir()):
		repo_name = repo_dir.name
		for hidx_file in sorted(repo_dir.glob("fuzzy_*.hidx")):
			version_name = hidx_file.name[len("fuzzy_"):-len(".hidx")]
			sidecar = load_collector_function_meta(repo_name, version_name)
			try:
				lines = [line.strip() for line in hidx_file.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()]
			except FileNotFoundError:
				continue
			for line in lines[1:]:
				func_hash, parsed_occurrences = parse_hidx_line(line)
				if not func_hash:
					continue
				sidecar_entry = sidecar.get(func_hash, {})
				sidecar_occurrences = sidecar_entry.get("occurrences") or []
				if sidecar_occurrences:
					for item in sidecar_occurrences:
						occurrence = {
							"repo": item.get("repo") or repo_name,
							"version": str(item.get("version") or version_name),
							"path": item.get("path", ""),
							"function_name": item.get("function_name", ""),
							"param_count": item.get("param_count", ""),
							"tlsh": item.get("tlsh") or func_hash,
							"include_tokens": sorted(set(item.get("include_tokens", []))),
							"path_birth_date": item.get("path_birth_date"),
						}
						for field in ("submodule_path", "submodule_url", "submodule_commit", "submodule_component"):
							if item.get(field):
								occurrence[field] = item.get(field)
						occurrences.append(occurrence)
					continue
				include_tokens = sorted(set(sidecar_entry.get("include_tokens", [])))
				path_birth_dates = sidecar_entry.get("path_birth_dates", {})
				for item in parsed_occurrences:
					occurrences.append({
						"repo": repo_name,
						"version": version_name,
						"path": item["path"],
						"function_name": item["function_name"],
						"param_count": item["param_count"],
						"tlsh": func_hash,
						"include_tokens": include_tokens,
						"path_birth_date": path_birth_dates.get(item["path"]),
					})
	return occurrences


def is_vendored_path(src_path):
	"""True if any path segment is a canonical vendor directory name.

	Conservative whitelist only — generic names like `lib`, `libs`,
	`components` are intentionally excluded. Anything not on the whitelist
	falls through to the file-level TLSH check downstream.
	"""
	parts = [part.lower().replace("-", "_") for part in str(src_path).replace("\\", "/").split("/") if part]
	return any(part in VENDORED_DIR_NAMES for part in parts)


def path_dirname(src_path):
	return os.path.dirname(str(src_path).replace("\\", "/"))


def repo_tail(repo_name):
	return str(repo_name).split("@@")[-1].lower()


def choose_origin_for_file(
	repo_name,
	file_path,
	file_tlshes,
	any_occurrence,
	tlshes_by_component,
	earliest_birth_by_component,
	known_components,
):
	"""Decide a single origin for *all* functions in (repo_name, file_path).

	A file is the structural unit of vendoring: either every function in it
	is the OSS's own code, or every function was copied wholesale from
	another component. Per-function decisions led to unstable mixed-role
	files and to widespread misclassification when generic helper functions
	coincidentally matched another component's TLSH.

	Tier 1 — explicit git submodule.
	         If the submodule points to a component that exists in the DB
	         → vendored to it. If the submodule's target is unknown to the
	         DB the file is still treated as foreign — Tier 3 may re-home
	         it onto a known component, otherwise it is dropped entirely
	         (not attributed back to the parent repo) so unknown bundled
	         code never inflates the parent's own surface.
	Tier 2 — path under a canonical vendor directory whitelist
	         (third_party, vendor, external, deps, contrib, dependencies,
	         extern). Origin is any TLSH-holder; ties broken by earliest
	         birth_date. Lib/libs/components are intentionally excluded —
	         they are too generic to act as a hard signal and instead fall
	         through to Tier 3 which requires structural TLSH evidence.
	Tier 3 — every TLSH in this file is also present in another component.
	         Origin is the holder with the earliest birth_date for this
	         file's TLSHes. This is what catches src/lib/{fmt,plog,...}
	         style vendoring as well as fork-style cross-attribution
	         (e.g. terarkdb → rocksdb).
	Tier 4 — own (only when none of the above triggered AND the file is not
	         a submodule pointing to an unknown component).
	"""
	# Tier 1: declared git submodule
	submodule = any_occurrence.get("submodule_component")
	submodule_to_unknown = False
	if submodule and submodule != repo_name:
		if submodule in known_components:
			return {
				"origin_component": submodule,
				"role": "vendored",
				"origin_decision": "confirmed_git_submodule",
				"evidence": sorted({
					f"git_submodule:{any_occurrence.get('submodule_path', '')}",
					f"observed_path:{file_path}",
				} | (
					{f"submodule_commit:{any_occurrence.get('submodule_commit')}"} if any_occurrence.get("submodule_commit") else set()
				)),
			}
		# Submodule target not present in DB. Fall through to Tier 2/3 so
		# a different known component may still claim the file via TLSH.
		# If nothing claims it, the Tier 4 fallback below drops the file
		# instead of attributing it to the parent repo.
		submodule_to_unknown = True

	# Tier 2: canonical vendor directory
	if is_vendored_path(file_path):
		holders = set()
		for tlsh in file_tlshes:
			holders.update(tlshes_by_component.get(tlsh, set()))
		holders.discard(repo_name)
		if holders:
			origin = _pick_earliest_holder(holders, file_tlshes, earliest_birth_by_component)
			return {
				"origin_component": origin,
				"role": "vendored",
				"origin_decision": "canonical_vendor_directory",
				"evidence": sorted({
					f"vendor_dir_path:{file_path}",
					f"tlsh_match_count:{sum(1 for t in file_tlshes if origin in tlshes_by_component.get(t, set()))}",
				}),
			}
		# Vendor folder but no TLSH evidence → fall through to own.

	# Tier 3: every TLSH in this file appears in another component
	if file_tlshes:
		full_holders = None
		for tlsh in file_tlshes:
			holders_of_t = tlshes_by_component.get(tlsh, set()) - {repo_name}
			if not holders_of_t:
				full_holders = set()
				break
			full_holders = holders_of_t if full_holders is None else (full_holders & holders_of_t)
			if not full_holders:
				break
		if full_holders:
			origin = _pick_earliest_holder(full_holders, file_tlshes, earliest_birth_by_component)
			return {
				"origin_component": origin,
				"role": "vendored",
				"origin_decision": "file_level_tlsh_match",
				"evidence": sorted({
					f"file_path:{file_path}",
					f"file_tlsh_count:{len(file_tlshes)}",
					f"holders:{','.join(sorted(full_holders))}",
				}),
			}

	# Submodule target unknown to DB and no Tier 2/3 home found → drop the
	# file entirely so its functions don't pollute the parent's own surface.
	if submodule_to_unknown:
		return {
			"origin_component": None,
			"role": "skipped",
			"origin_decision": "submodule_to_unknown_component",
			"evidence": sorted({
				f"git_submodule:{any_occurrence.get('submodule_path', '')}",
				f"submodule_component_not_in_db:{submodule}",
				f"observed_path:{file_path}",
			}),
		}

	# Tier 4: own
	return {
		"origin_component": repo_name,
		"role": "own",
		"origin_decision": "component_own_source",
		"evidence": [f"observed_path:{file_path}"],
	}


def _pick_earliest_holder(holders, file_tlshes, earliest_birth_by_component):
	"""Choose the holder with the earliest birth date averaged over the file's
	TLSHes. Falls back to lexicographic order when birth dates are missing."""
	scored = []
	for holder in holders:
		dates = []
		bd_map = earliest_birth_by_component.get(holder, {})
		for tlsh in file_tlshes:
			d = bd_map.get(tlsh)
			if d:
				dates.append(d)
		scored.append((min(dates) if dates else "9999-99-99", holder))
	scored.sort()
	return scored[0][1]


def source_file_for_hash(repo_name, func_hash):
	repo_dir = Path(funcCodePath) / repo_name
	for ext in (".c", ".cpp", ".cc"):
		candidate = repo_dir / f"{func_hash}{ext}"
		if candidate.exists():
			return candidate
	return None


def choose_representative_source_file(func_hash, occurrences, preferred_repo):
	candidates = []
	for occurrence in occurrences:
		repo_name = occurrence.get("repo", "")
		func_file = source_file_for_hash(repo_name, func_hash)
		if func_file is None:
			continue
		candidates.append((
			0 if repo_name == preferred_repo else 1,
			0 if not is_vendored_path(occurrence.get("path", "")) else 1,
			repo_name,
			occurrence.get("path", ""),
			func_file,
			occurrence,
		))
	if not candidates:
		return None, None
	candidates.sort(key=lambda item: item[:4])
	return candidates[0][4], candidates[0][5]


def read_json_file(path, default):
	try:
		return json.loads(Path(path).read_text(encoding="utf-8"))
	except Exception:
		return default


def atomic_write_json(path, document):
	target = Path(path)
	target.parent.mkdir(parents=True, exist_ok=True)
	tmp = target.with_name(f".{target.name}.tmp")
	with open(tmp, "w", encoding="utf-8") as f:
		json.dump(document, f, indent=2, ensure_ascii=False)
	os.replace(tmp, target)


def extract_feature_payload(blocks, occurrences):
	strings = set()
	callees = set()
	for block in blocks:
		if not isinstance(block, dict):
			continue
		if block.get("block_type") == "String":
			for value in block.get("key_feature_dvector", {}).get("literal_values", []):
				if not path_basename_hint(value) and is_discriminative_string(value):
					strings.add(value)
		if block.get("block_type") == "CalleeFunc":
			for value in block.get("key_feature_dvector", {}).get("function_values", []):
				callee = normalize_callee_name(value)
				if callee:
					callees.add(callee)
	symbols = sorted({
		item.get("function_name", "")
		for item in occurrences
		if item.get("function_name")
	})
	return {
		"control_blocks": blocks,
		"strings":        sorted(strings),
		"symbols":        symbols,
		"callstr_tokens": sorted(extract_callstr_tokens_from_blocks(blocks, True)),
		"callees":        sorted(callees),
	}


def feature_summary(payload):
	return {
		"block_count":   len(payload.get("control_blocks", [])),
		"string_count":  len(payload.get("strings", [])),
		"symbol_count":  len(payload.get("symbols", [])),
		"callstr_count": len(payload.get("callstr_tokens", [])),
		"callee_count":  len(payload.get("callees", [])),
	}


def get_or_create_function_feature(func_hash, occurrences, preferred_repo):
	func_file, source_occurrence = choose_representative_source_file(func_hash, occurrences, preferred_repo)
	if func_file is None:
		return None, feature_summary({}), {}, "unknown"
	language = source_language_for_file(func_file)
	feature_dir = Path(functionFeaturesPath) / language
	feature_dir.mkdir(parents=True, exist_ok=True)
	feature_file = feature_dir / f"{func_hash}.json"
	features_ref = os.path.relpath(feature_file, currentPath)

	if feature_file.exists():
		existing = read_json_file(feature_file, {})
		if isinstance(existing, dict) and "features" in existing:
			payload = existing.get("features", {})
			return features_ref, feature_summary(payload), payload, existing.get("language") or language
		if isinstance(existing, list):
			payload = extract_feature_payload(existing, occurrences)
			document = {
				"function_id": func_hash,
				"language": language,
				"source": {
					"repo": source_occurrence.get("repo", ""),
					"path": source_occurrence.get("path", ""),
				},
				"features": payload,
			}
			atomic_write_json(feature_file, document)
			return features_ref, feature_summary(payload), payload, language

	success, _error = process_func_file_to_controlblock(str(func_file), str(feature_file), timeout_seconds=60)
	if not success:
		return None, feature_summary({}), {}, language
	blocks = read_json_file(feature_file, [])
	if not isinstance(blocks, list):
		blocks = []
	payload = extract_feature_payload(blocks, occurrences)
	document = {
		"function_id": func_hash,
		"language": language,
		"source": {
			"repo": source_occurrence.get("repo", ""),
			"path": source_occurrence.get("path", ""),
		},
		"features": payload,
	}
	atomic_write_json(feature_file, document)
	return features_ref, feature_summary(payload), payload, language


def write_json_file(path, document):
	atomic_write_json(path, document)


def cleanup_componentdb_outputs():
	root = Path(finalDBPath)
	for path in root.glob("*.json"):
		if path.name not in {"components.json", "functions.json"}:
			path.unlink()
	for directory in componentFeatureDirs.values():
		for path in Path(directory).glob("*.json"):
			path.unlink()
	for path in Path(rareControlShardDir).glob("*.json"):
		path.unlink()


def sorted_source_occurrences(source_occurrences):
	return sorted(
		source_occurrences,
		key=lambda item: (item["repo"], item["version"], item["path"], item["function_name"]),
	)


def representative_function_name(source_occurrences):
	names = sorted({
		item.get("function_name", "")
		for item in source_occurrences
		if item.get("function_name")
	})
	real_names = [name for name in names if classify_source_symbol_kind(name) == "real"]
	return real_names[0] if real_names else (names[0] if names else "")


def indexed_feature_items(index, value_key, evidence_kind=None):
	items = []
	for value, function_ids in sorted(index.items(), key=lambda item: item[0]):
		if not value:
			continue
		record = {
			value_key: value,
			"function_ids": sorted(function_ids),
		}
		if evidence_kind:
			record["evidence_kind"] = evidence_kind
		items.append(record)
	return items


def edge_children_by_component(dependency_edges):
	children = defaultdict(set)
	for edge in dependency_edges.values():
		children[edge["parent"]].add(edge["child"])
	return children


def refine_shared_copies(all_comp_data, dependency_children):
	"""2nd-pass: re-classify component_own_source functions whose callee set is
	identical (and non-empty) to a function of the same name in another component.

	Uses path_birth_date to determine the true owner:
	- Earlier birth date → owner → keep in symbol_index
	- Later birth date   → copy  → remove from symbol_index
	- Same or unknown    → ambiguous → remove from both

	Exception: a known vendoring hub (a benchmark harness like lzbench/
	TurboBench/precomp-cpp that bundles dozens of other libraries' source
	verbatim) never wins this comparison and never drags its non-hub
	counterpart down via the "ambiguous → remove both" fallback — its
	birth date reflects when it happened to vendor the code, not when the
	code was authored, so only the hub's own copy is ever removed.
	"""
	hubs = _hub_components(dependency_children)

	# func_name → {comp: (frozenset(callees), path_birth_date)}
	func_info: dict = defaultdict(dict)
	for comp, data in all_comp_data.items():
		for item in data["callee_items"]:
			fn = item["function_name"]
			if fn:
				func_info[fn][comp] = (
					frozenset(item["callees"]),
					item.get("path_birth_date"),
				)

	# For each (fn, comp_pair) with identical non-empty callees:
	# keep owner (earlier birth), remove copy (later birth), or remove both if ambiguous
	shared_funcs: dict = defaultdict(set)  # comp → set of function names to remove
	for fn, comp_map in func_info.items():
		if len(comp_map) < 2:
			continue
		comps = list(comp_map.items())
		for i in range(len(comps)):
			c1, (cal1, bd1) = comps[i]
			if not cal1:
				continue
			for j in range(i + 1, len(comps)):
				c2, (cal2, bd2) = comps[j]
				if cal1 != cal2:
					continue
				hub1, hub2 = c1 in hubs, c2 in hubs
				if hub1 and not hub2:
					shared_funcs[c1].add(fn)
					continue
				if hub2 and not hub1:
					shared_funcs[c2].add(fn)
					continue
				# same function — determine owner by birth date
				if bd1 and bd2 and bd1 != bd2:
					# earlier = owner → remove the later one only
					if bd1 < bd2:
						shared_funcs[c2].add(fn)
					else:
						shared_funcs[c1].add(fn)
				else:
					# ambiguous (same date or missing) → remove both
					shared_funcs[c1].add(fn)
					shared_funcs[c2].add(fn)

	# Remove copy symbols from symbol_index
	total_removed = 0
	for comp, names in shared_funcs.items():
		sym_idx = all_comp_data[comp]["symbol_index"]
		for name in names:
			if name in sym_idx:
				del sym_idx[name]
				total_removed += 1
	print(f"[+] refine_shared_copies: removed {total_removed} shared-copy symbols across {len(shared_funcs)} components")


def materialize_component_feature_db(component_functions, dependency_edges):
	cleanup_componentdb_outputs()
	dependency_children = edge_children_by_component(dependency_edges)
	function_records = []
	rare_component_df = defaultdict(int)
	rare_function_df = defaultdict(int)
	rare_postings = defaultdict(list)

	# ── Pass 1: collect all per-component data in memory ──────────────────────
	all_comp_data = {}

	for component, functions_by_hash in sorted(component_functions.items()):
		control_block_items = []
		string_index = defaultdict(set)
		symbol_index = defaultdict(set)
		callee_items = []
		callstr_index = defaultdict(set)
		name_index = defaultdict(set)
		pending_call_edges = []
		control_tokens_seen = set()

		for func_hash, entry in sorted(functions_by_hash.items()):
			source_occurrences = sorted_source_occurrences(entry["source_occurrences"])
			function_name = representative_function_name(source_occurrences)
			_features_ref, summary, payload, language = get_or_create_function_feature(
				func_hash,
				source_occurrences,
				entry["origin_component"],
			)
			function_records.append({
				"function_id":      func_hash,
				"origin_component": entry["origin_component"],
				"function_name":    function_name,
				"param_count":      source_occurrences[0].get("param_count", "") if source_occurrences else "",
				"language":         language,
				"origin_decision":  sorted(entry["origin_decisions"])[0],
				"origin_decisions": sorted(entry["origin_decisions"]),
				"observed_in":      sorted(entry["observed_in"]),
				"role":             "vendored" if entry["roles"] == {"vendored"} else "own",
				"roles":            sorted(entry["roles"]),
				"source_occurrences": source_occurrences,
				"feature_summary":  summary,
			})

			control_block_items.append({
				"function_id":   func_hash,
				"function_name": function_name,
				"control_blocks": payload.get("control_blocks", []),
			})
			recovery_tokens = control_block_tokens_for_recovery(payload.get("control_blocks", []))
			if recovery_tokens:
				control_tokens_seen.update(recovery_tokens)
				for token in sorted(recovery_tokens):
					rare_function_df[token] += 1
					rare_postings[token].append((component, function_name))
			for value in payload.get("strings", []):
				string_index[value].add(func_hash)
			for symbol in payload.get("symbols", []):
				if classify_source_symbol_kind(symbol) != "real":
					continue
				symbol_index[symbol].add(func_hash)
				name_index[symbol].add(func_hash)
			callees = sorted({normalize_callee_name(v) for v in payload.get("callees", []) if normalize_callee_name(v)})
			birth_dates = [o["path_birth_date"] for o in source_occurrences if o.get("path_birth_date")]
			callee_items.append({
				"function_id":    func_hash,
				"function_name":  function_name,
				"callees":        callees,
				"path_birth_date": min(birth_dates) if birth_dates else None,
			})
			for token in payload.get("callstr_tokens", []):
				if token:
					callstr_index[token].add(func_hash)
			pending_call_edges.append((func_hash, function_name, callees))

		call_edges = []
		for caller_id, caller_name, callees in pending_call_edges:
			for callee_name in callees:
				callee_ids = sorted(name_index.get(callee_name, set()))
				if callee_ids:
					call_edges.append({
						"caller_function_id": caller_id,
						"caller_name":        caller_name,
						"callee_name":        callee_name,
						"callee_function_ids": callee_ids,
					})

		for token in control_tokens_seen:
			rare_component_df[token] += 1

		all_comp_data[component] = {
			"control_block_items": control_block_items,
			"string_index":        string_index,
			"symbol_index":        symbol_index,   # mutable — refined in pass 2
			"callee_items":        callee_items,
			"callstr_index":       callstr_index,
			"call_edges":          call_edges,
			"functions_by_hash":   functions_by_hash,
		}

	# ── Pass 2: callee-based shared-copy refinement ───────────────────────────
	refine_shared_copies(all_comp_data, dependency_children)

	# ── Pass 3: write all output files ────────────────────────────────────────
	component_summaries = {}
	startup_symbol_owners = defaultdict(set)
	startup_string_owners = defaultdict(set)
	startup_strings_by_component = defaultdict(set)

	for component, data in sorted(all_comp_data.items()):
		string_index  = data["string_index"]
		symbol_index  = data["symbol_index"]   # already refined
		callstr_index = data["callstr_index"]

		string_items  = indexed_feature_items(string_index, "string", "discriminative_string")
		symbol_items  = indexed_feature_items(symbol_index, "symbol")
		for item in symbol_items:
			item["symbol_kind"] = "real"
			if item.get("symbol"):
				startup_symbol_owners[item["symbol"]].add(component)
		for string_value in string_index:
			ns = normalize_startup_string(string_value)
			if ns:
				startup_strings_by_component[component].add(ns)
				startup_string_owners[ns].add(component)
		callstr_items = indexed_feature_items(callstr_index, "token")

		write_json_file(os.path.join(componentFeatureDirs["control_blocks"], f"{component}.json"), {
			"component": component,
			"items":     data["control_block_items"],
		})
		write_json_file(os.path.join(componentFeatureDirs["strings"], f"{component}.json"), {
			"component": component,
			"items":     string_items,
		})
		write_json_file(os.path.join(componentFeatureDirs["symbols"], f"{component}.json"), {
			"component": component,
			"items":     symbol_items,
		})
		write_json_file(os.path.join(componentFeatureDirs["callstr_tokens"], f"{component}.json"), {
			"component": component,
			"items":     callstr_items,
		})
		write_json_file(os.path.join(componentFeatureDirs["call_graph"], f"{component}.json"), {
			"component": component,
			"edges":     sorted(data["call_edges"], key=lambda e: (e["caller_function_id"], e["callee_name"])),
		})

		component_summaries[component] = {
			"component":                   component,
			"function_count":              len(data["functions_by_hash"]),
			"control_block_function_count": len(data["control_block_items"]),
			"string_count":                len(string_items),
			"symbol_count":                len(symbol_items),
			"callstr_token_count":          len(callstr_items),
			"internal_call_edge_count":     len(data["call_edges"]),
			"dependency_children":          sorted(dependency_children.get(component, set())),
		}

	write_json_file(os.path.join(finalDBPath, "functions.json"), {
		"functions": sorted(function_records, key=lambda r: (r["origin_component"], r["function_id"])),
	})
	write_json_file(os.path.join(finalDBPath, "components.json"), {
		"components": [component_summaries[k] for k in sorted(component_summaries)],
	})
	rare_control_index = build_rare_control_index_document(
		len(component_summaries),
		rare_component_df,
		rare_function_df,
		rare_postings,
	)
	write_json_file(rareControlIndexPath, rare_control_index)
	write_rare_control_shards(rare_control_index)
	write_json_file(startupIndexPath, build_startup_index_document(
		component_summaries,
		startup_symbol_owners,
		startup_string_owners,
		startup_strings_by_component,
		dependency_children,
	))


def write_source_provenance_db():
	print("[+] Building source-provenance component DB...")
	occurrences = load_source_occurrences()
	if not occurrences:
		print("[!] No source occurrences found under osscollector/repo_functions")
		return

	# Cross-component indexes used by the file-level decision:
	#   tlshes_by_component[component] -> set of TLSHes the component holds
	#   tlshes_to_components[tlsh]     -> set of components containing it
	#   earliest_birth_by_component[component][tlsh] -> earliest path_birth_date
	tlshes_by_component: dict = defaultdict(set)
	tlshes_to_components: dict = defaultdict(set)
	earliest_birth_by_component: dict = defaultdict(dict)
	for occurrence in occurrences:
		repo = occurrence["repo"]
		tlsh = occurrence["tlsh"]
		tlshes_by_component[repo].add(tlsh)
		tlshes_to_components[tlsh].add(repo)
		bd = occurrence.get("path_birth_date")
		if bd:
			prev = earliest_birth_by_component[repo].get(tlsh)
			if prev is None or bd < prev:
				earliest_birth_by_component[repo][tlsh] = bd

	# Group occurrences by (repo, path) — the file is the decision unit.
	occurrences_by_file: dict = defaultdict(list)
	for occurrence in occurrences:
		occurrences_by_file[(occurrence["repo"], occurrence["path"])].append(occurrence)

	# Set of components present in our DB (i.e. we have scanned their source).
	# Used to gate the explicit-submodule branch in choose_origin_for_file —
	# submodules whose target is not in this set are never attributed to the
	# parent repo as own code.
	known_components = set(tlshes_by_component.keys())

	function_origin = []
	component_functions = defaultdict(lambda: defaultdict(lambda: {
		"origin_component": "",
		"observed_in": set(),
		"roles": set(),
		"origin_decisions": set(),
		"evidence": set(),
		"source_occurrences": [],
	}))
	dependency_edges = {}

	for (repo_name, file_path), file_occurrences in occurrences_by_file.items():
		file_tlshes = {occ["tlsh"] for occ in file_occurrences}
		any_occurrence = file_occurrences[0]
		decision = choose_origin_for_file(
			repo_name,
			file_path,
			file_tlshes,
			any_occurrence,
			tlshes_to_components,
			earliest_birth_by_component,
			known_components,
		)
		# Apply the file-level decision to every function occurrence in the file.
		for occurrence in file_occurrences:
			record = {
				"function_id": occurrence["tlsh"],
				"observed_repo": occurrence["repo"],
				"version": occurrence["version"],
				"path": occurrence["path"],
				"function_name": occurrence["function_name"],
				"param_count": occurrence["param_count"],
				"include_tokens": occurrence.get("include_tokens", []),
				"path_birth_date": occurrence.get("path_birth_date"),
				"origin_component": decision["origin_component"],
				"role": decision["role"],
				"origin_decision": decision["origin_decision"],
				"evidence": decision["evidence"],
			}
			for field in ("submodule_path", "submodule_url", "submodule_commit", "submodule_component"):
				if occurrence.get(field):
					record[field] = occurrence.get(field)
			function_origin.append(record)

			origin = decision["origin_component"]
			if not origin:
				continue
			bucket = component_functions[origin][occurrence["tlsh"]]
			bucket["origin_component"] = origin
			bucket["observed_in"].add(occurrence["repo"])
			bucket["roles"].add(decision["role"])
			bucket["origin_decisions"].add(decision["origin_decision"])
			bucket["evidence"].update(decision["evidence"])
			source_occurrence = {
				"repo": occurrence["repo"],
				"version": occurrence["version"],
				"path": occurrence["path"],
				"function_name": occurrence["function_name"],
				"param_count": occurrence["param_count"],
			}
			for field in ("submodule_path", "submodule_url", "submodule_commit", "submodule_component"):
				if occurrence.get(field):
					source_occurrence[field] = occurrence.get(field)
			bucket["source_occurrences"].append(source_occurrence)
			if decision["role"] == "vendored" and occurrence["repo"] != origin:
				edge_type = "git_submodule_dependency" if decision["origin_decision"] == "confirmed_git_submodule" else "bundled_source_dependency"
				edge = dependency_edges.setdefault((occurrence["repo"], origin, edge_type), {
					"parent": occurrence["repo"],
					"child": origin,
					"edge_type": edge_type,
					"evidence": set(),
					"subtrees": set(),
					"source_function_ids": set(),
					"origin_decisions": set(),
					"path_evidence": set(),
				})
				edge["evidence"].update(decision["evidence"])
				if occurrence.get("submodule_url"):
					edge["evidence"].add(f"submodule_url:{occurrence.get('submodule_url')}")
				if occurrence.get("submodule_commit"):
					edge["evidence"].add(f"submodule_commit:{occurrence.get('submodule_commit')}")
				subtree = occurrence.get("submodule_path") or path_dirname(occurrence["path"])
				if subtree:
					edge["subtrees"].add(str(subtree).strip("/"))
				edge["source_function_ids"].add(occurrence["tlsh"])
				edge["origin_decisions"].add(decision["origin_decision"])
				if occurrence.get("path"):
					edge["path_evidence"].add(str(occurrence["path"]).lstrip("/"))

	materialize_component_feature_db(component_functions, dependency_edges)

	write_json_file(os.path.join(provenancePath, "function_origin.json"), {"functions": function_origin})
	write_json_file(os.path.join(provenancePath, "dependency_graph.json"), {
		"edges": [
			{"parent": edge["parent"], "child": edge["child"]}
			for edge in sorted(dependency_edges.values(), key=lambda item: (item["parent"], item["child"]))
		]
	})
	stale_git_submodules = Path(provenancePath) / "git_submodules.json"
	if stale_git_submodules.exists():
		stale_git_submodules.unlink()

	print(f"[+] Components written: {len(component_functions)}")
	print(f"[+] Dependency edges written: {len(dependency_edges)}")
	print(f"[+] Rare control-token index written: {rareControlIndexPath}")


# --- namespace unique-token index (inlined from former extract_namespaces.py) ---
NS_SRC_DIR = os.path.join(osscollectorPath, "repo_src")
NS_OUT_DIR = os.path.join(finalDBPath, "namespaces")
NS_OWNER_INDEX_PATH = os.path.join(finalDBPath, "namespace_owner_index.json")
NS_SOURCE_EXTS = {".h", ".hpp", ".hh", ".c", ".cc", ".cpp", ".cxx"}
NS_VENDORED_DIR_NAMES = {
	"third_party", "thirdparty", "3rdparty", "third-party",
	"vendor", "vendored", "external", "externals", "external_libs",
	"deps", "dependencies", "contrib", "extern", "submodule", "submodules",
	"components", "subprojects",
}
NS_EXCLUDED_DIR_NAMES = {
	".git", ".hg", ".svn", "__pycache__", ".cache",
	"build", "cmake-build-debug", "cmake-build-release",
	"test", "tests", "testing", "doc", "docs", "example", "examples", "sample", "samples",
}
# match "namespace X {" or "namespace X::Y::Z {" — capture the full path
NS_RE = re.compile(
	r"\bnamespace\s+([A-Za-z_][A-Za-z_0-9]*(?:\s*::\s*[A-Za-z_][A-Za-z_0-9]*)*)\s*\{"
)
# Reserved / generic tokens that are not OSS-discriminative even when found.
NS_GENERIC = {
	"std", "detail", "internal", "impl", "anonymous", "operators",
	"literals", "string_literals", "chrono_literals", "this_thread", "ranges",
	"filesystem", "experimental", "tr1", "tr2", "pmr",
	"align", "app", "append", "base", "bit", "buffer", "byte", "cache",
	"client", "clear", "com", "common", "compat", "compatibility", "config",
	"console", "consts", "conv", "convert", "core", "crypto", "data", "der",
	"dev", "device", "encoding", "err", "error", "ext", "fields", "file",
	"format", "ghc", "globals", "host", "html", "http", "icu", "info", "init",
	"iter", "iterators", "json", "lib", "length", "lock", "log", "mem",
	"memory", "msg", "net", "network", "node", "os", "out", "parse",
	"parser", "port", "post", "proto", "rand", "result", "server", "service",
	"session", "sign", "ssl", "stream", "string", "system", "tag", "test",
	"text", "thread", "time", "tls", "tool", "type", "types", "util", "utils",
	"view", "write", "xml", "zip",
}

# --- CB-block ANN index (inlined from former index_cb_blocks.py) ---
CB_INTERNAL_BLOCK_TYPES = {"Condition", "Loop", "Else"}


def ns_iter_source_files(repo_root, foreign_short_names):
	"""Walk source files, skipping vendored/excluded and foreign-OSS subdirs."""
	own_short_name = os.path.basename(repo_root).split("@@")[-1].lower()
	for root, dirs, files in os.walk(repo_root):
		keep = []
		for d in dirs:
			if d.startswith("."):
				continue
			dl = d.lower()
			if dl in NS_EXCLUDED_DIR_NAMES or dl in NS_VENDORED_DIR_NAMES:
				continue
			# Skip nested dirs named after a different OSS — vendored copies.
			if dl != own_short_name and dl in foreign_short_names:
				continue
			keep.append(d)
		dirs[:] = keep
		for f in files:
			ext = os.path.splitext(f)[1].lower()
			if ext in NS_SOURCE_EXTS:
				yield os.path.join(root, f)


def ns_extract_for_repo(repo_root, foreign_short_names):
	"""Return the set of top-level namespace names declared in this repo."""
	tokens = set()
	for path in ns_iter_source_files(repo_root, foreign_short_names):
		try:
			with open(path, "r", encoding="utf-8", errors="ignore") as fp:
				content = fp.read()
		except OSError:
			continue
		for match in NS_RE.findall(content):
			joined = "".join(match.split())
			head = joined.split("::", 1)[0]
			if head and head not in NS_GENERIC and len(head) >= 3:
				tokens.add(head)
	return tokens


def build_namespace_index():
	"""Provenance-anchor namespace unique-token index (formerly extract_namespaces.py)."""
	print("[+] Extracting namespace tokens...")
	if not os.path.isdir(NS_SRC_DIR):
		print(f"[!] Source dir not found: {NS_SRC_DIR}", file=sys.stderr)
		return 1
	os.makedirs(NS_OUT_DIR, exist_ok=True)

	all_oss_dirs = [d for d in sorted(os.listdir(NS_SRC_DIR)) if os.path.isdir(os.path.join(NS_SRC_DIR, d))]
	all_short_names = {d.split("@@")[-1].lower() for d in all_oss_dirs if "@@" in d}

	per_oss = {}
	for oss_name in all_oss_dirs:
		repo_path = os.path.join(NS_SRC_DIR, oss_name)
		own = oss_name.split("@@")[-1].lower()
		foreign = all_short_names - {own}
		tokens = ns_extract_for_repo(repo_path, foreign)
		per_oss[oss_name] = tokens
		print(f"  {oss_name}: {len(tokens)} namespace tokens")

	# Global frequency → tokens unique to exactly one OSS.
	token_owners = defaultdict(list)
	for oss_name, tokens in per_oss.items():
		for t in tokens:
			token_owners[t].append(oss_name)

	unique_owner_index = {t: owners[0] for t, owners in token_owners.items() if len(owners) == 1}

	per_oss_unique = defaultdict(list)
	for t, owner in unique_owner_index.items():
		per_oss_unique[owner].append(t)
	for oss_name in per_oss:
		out_path = os.path.join(NS_OUT_DIR, f"{oss_name}.json")
		payload = {
			"oss": oss_name,
			"namespaces": sorted(per_oss[oss_name]),
			"unique_namespaces": sorted(per_oss_unique.get(oss_name, [])),
		}
		with open(out_path, "w", encoding="utf-8") as fp:
			json.dump(payload, fp, indent=2, ensure_ascii=False)

	with open(NS_OWNER_INDEX_PATH, "w", encoding="utf-8") as fp:
		json.dump({
			"unique_owner_index": dict(sorted(unique_owner_index.items())),
			"total_unique_tokens": len(unique_owner_index),
			"total_oss_with_unique_tokens": len(per_oss_unique),
		}, fp, indent=2, ensure_ascii=False)

	print(f"[*] Wrote {len(unique_owner_index)} unique namespace tokens "
	      f"covering {len(per_oss_unique)} OSS components → {NS_OWNER_INDEX_PATH}")
	return 0


def load_cb_records(path, comp_name, cbi):
	"""Extract internal-block records (46-byte vectors) from one component file."""
	try:
		with open(path) as f:
			data = json.load(f)
	except Exception as e:
		print(f"  [!] Failed to read {path}: {e}")
		return []

	records = []
	for item in data.get("items", []):
		func_id = item.get("function_id", "")
		func_name = item.get("function_name", "")
		for block in item.get("control_blocks", []):
			bt = block.get("block_type", "")
			if bt not in CB_INTERNAL_BLOCK_TYPES:
				continue
			vec = cbi.kfv_to_bytes(block.get("key_feature_vector", ""))
			if vec is None:
				continue
			records.append({
				"component":     comp_name,
				"function_id":   func_id,
				"function_name": func_name,
				"block_type":    bt,
				"vector":        vec,
			})
	return records


def build_cb_block_index():
	"""Build the CB-block FAISS index (formerly index_cb_blocks.py).

	The componentDB was just (re)built, so this always rebuilds the index.
	"""
	print("[+] Building CB-block ANN index...")
	import cb_index as cbi  # lazy: keeps faiss optional for the rest of the pipeline

	cb_dir = componentFeatureDirs["control_blocks"]
	db_dir = os.path.join(currentPath, "database")
	if not os.path.isdir(cb_dir):
		print(f"[!] Missing: {cb_dir}")
		return -1

	comp_files = sorted(f for f in os.listdir(cb_dir) if f.endswith(".json"))
	print(f"[*] Indexing {len(comp_files)} components from {cb_dir} ...")

	all_records = []
	for fname in comp_files:
		comp_name = fname[:-5]
		records = load_cb_records(os.path.join(cb_dir, fname), comp_name, cbi)
		all_records.extend(records)
		print(f"    {comp_name}: {len(records)} blocks")

	print(f"\n[*] Building FAISS IndexBinaryFlat ({cbi.CB_VECTOR_DIM}-bit Hamming) ...")
	total = cbi.build_and_save(all_records, db_dir)
	print(f"[+] Done. Indexed {total} blocks → {db_dir}/cb_blocks.{{index,meta.json}}")
	return total


def main():
	# 1) provenance decision + CB/feature extraction into componentDB
	write_source_provenance_db()
	# 2) namespace unique-token index (provenance anchor)
	build_namespace_index()
	# 3) CB-block ANN index over the freshly built componentDB
	build_cb_block_index()


if __name__ == "__main__":
	main()
