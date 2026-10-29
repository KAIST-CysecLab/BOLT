import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class LLMVerifierConfig:
    enabled: bool = False

    # Default model for your A6000 + Ollama setup.
    model: str = "qwen3-coder:30b-a3b-q4_K_M"

    # Accept either:
    #   http://localhost:11434
    #   http://localhost:11434/api/chat
    #   http://localhost:11434/api/generate
    url: str = "http://localhost:11434/api/chat"

    # 30B local models can be slow on first request.
    timeout: float = 120.0

    # Minimum confidence required by detector.py to accept LLM match.
    min_confidence: float = 0.65

    # Number of Phase 4 candidates checked per binary function.
    max_candidate_checks: int = 4

    # Conservative generation options.
    temperature: float = 0.0
    top_p: float = 0.1
    repeat_penalty: float = 1.05

    # Limit packet size to avoid sending huge prompts.
    max_prompt_chars: int = 24000


@dataclass
class LLMVerificationResult:
    verdict: str
    confidence: float
    reason: str = ""
    cited_evidence: List[str] = field(default_factory=list)
    raw_response: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    min_confidence: float = 0.65

    @property
    def accepted(self) -> bool:
        return self.verdict == "match" and self.confidence >= self.min_confidence


class OllamaLLMVerifier:
    """Conservative Ollama verifier for Phase 4 binary/source function alignment.

    This class is designed for detector.py's Phase 4 use case:
    - deterministic evidence first
    - LLM only checks top-k candidate alignments
    - output must be strict JSON
    - unknown is preferred when evidence is weak
    """

    VALID_VERDICTS = {"match", "non_match", "unknown"}

    def __init__(self, config: LLMVerifierConfig):
        self.config = config
        self.url = self._normalize_url(config.url)

    @staticmethod
    def _normalize_url(url: str) -> str:
        base = (url or "").strip().rstrip("/")
        if not base:
            return "http://localhost:11434/api/chat"
        if base.endswith("/api/chat") or base.endswith("/api/generate"):
            return base
        return f"{base}/api/chat"

    def verify_function_match(self, packet: Dict[str, Any]) -> LLMVerificationResult:
        if not self.config.enabled:
            return LLMVerificationResult(
                verdict="unknown",
                confidence=0.0,
                reason="llm_verifier_disabled",
                min_confidence=self.config.min_confidence,
            )

        compact_packet = self._compact_packet(packet)
        prompt = self._build_prompt(compact_packet)
        payload = self._build_payload(prompt)

        request = urllib.request.Request(
            self.url,
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout) as response:
                raw_text = response.read().decode("utf-8", errors="replace")
                raw = json.loads(raw_text)
        except urllib.error.HTTPError as exc:
            body = ""
            try:
                body = exc.read().decode("utf-8", errors="replace")
            except Exception:
                pass
            return LLMVerificationResult(
                verdict="unknown",
                confidence=0.0,
                reason="ollama_http_error",
                error=f"{exc} {body}".strip(),
                min_confidence=self.config.min_confidence,
            )
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            return LLMVerificationResult(
                verdict="unknown",
                confidence=0.0,
                reason="ollama_request_failed",
                error=str(exc),
                min_confidence=self.config.min_confidence,
            )

        content = self._extract_content(raw)
        parsed = self._parse_json_content(content)

        if parsed is None:
            return LLMVerificationResult(
                verdict="unknown",
                confidence=0.0,
                reason="invalid_json_response",
                raw_response=raw,
                min_confidence=self.config.min_confidence,
            )

        verdict = str(parsed.get("verdict", "unknown")).strip().lower()
        if verdict not in self.VALID_VERDICTS:
            verdict = "unknown"

        confidence = self._parse_confidence(parsed.get("confidence"))

        reason = str(parsed.get("reason", "")).strip()
        reason = self._shorten_text(reason, 500)

        cited = parsed.get("cited_evidence", [])
        if isinstance(cited, str):
            cited = [cited]
        elif not isinstance(cited, list):
            cited = [str(cited)]

        cited_evidence = [
            self._shorten_text(str(item), 160)
            for item in cited
            if str(item).strip()
        ]

        # Conservative post-processing:
        # A match with very low confidence becomes unknown.
        if verdict == "match" and confidence < self.config.min_confidence:
            verdict = "unknown"
            if not reason:
                reason = "llm_match_below_confidence_threshold"

        return LLMVerificationResult(
            verdict=verdict,
            confidence=confidence,
            reason=reason,
            cited_evidence=cited_evidence,
            raw_response=raw,
            min_confidence=self.config.min_confidence,
        )

    def _build_payload(self, prompt: str) -> Dict[str, Any]:
        options = {
            "temperature": self.config.temperature,
            "top_p": self.config.top_p,
            "repeat_penalty": self.config.repeat_penalty,
        }

        if self.url.endswith("/api/generate"):
            return {
                "model": self.config.model,
                "prompt": prompt,
                "stream": False,
                "format": "json",
                "options": options,
            }

        return {
            "model": self.config.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a conservative binary/source function verifier. "
                        "Use only the supplied evidence. "
                        "Do not invent strings, constants, calls, control flow, names, or algorithms. "
                        "Return strict JSON only."
                    ),
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
            "stream": False,
            "format": "json",
            "options": options,
        }

    def _build_prompt(self, packet: Dict[str, Any]) -> str:
        packet_json = json.dumps(packet, ensure_ascii=False, sort_keys=True)

        prompt = (
            "Decide whether the binary function and the source function are the same logical function.\n\n"
            "This is a verification task, not a decompilation task.\n"
            "You must be conservative.\n"
            "Use only the supplied evidence packet.\n\n"
            "Hard rules:\n"
            "- Do not invent strings, constants, function calls, library calls, control-flow structures, algorithms, or source names.\n"
            "- Do not rely on source function names alone.\n"
            "- Do not rely on binary function names when they look generated, such as FUN_*, sub_*, fcn_*, nullsub_*, loc_*, lab_*, or address-like names.\n"
            "- Do not treat generic helper behavior as strong evidence.\n"
            "- Prefer unknown over match when evidence is incomplete.\n"
            "- Return non_match if the evidence conflicts.\n\n"
            "Decision rules:\n"
            "- Return match only when multiple independent evidence types agree.\n"
            "- Strong evidence types include rare strings, distinctive constants, distinctive API/libc calls, control-block similarity, call-string similarity, and callgraph neighborhood agreement.\n"
            "- Callgraph context alone is not enough for match.\n"
            "- Names alone are not enough for match.\n"
            "- Generic strings, generic constants, and common libc calls are weak evidence.\n"
            "- Return unknown when the evidence is weak, partial, or mostly generic.\n"
            "- Return non_match when shared evidence is contradicted by callgraph or control-block evidence.\n\n"
            "Confidence guide:\n"
            "- 0.85 to 1.00: strong coherent evidence from several independent feature types.\n"
            "- 0.65 to 0.84: likely match, but some evidence is incomplete.\n"
            "- 0.40 to 0.64: weak or partial evidence; usually unknown.\n"
            "- 0.00 to 0.39: conflicting, generic, or insufficient evidence.\n\n"
            "Return strict JSON only with this schema:\n"
            "{"
            "\"verdict\":\"match|non_match|unknown\","
            "\"confidence\":0.0,"
            "\"reason\":\"short reason\","
            "\"cited_evidence\":[\"evidence keys used\"]"
            "}\n\n"
            "Evidence packet:\n"
            f"{packet_json}"
        )

        if len(prompt) <= self.config.max_prompt_chars:
            return prompt

        # Fallback trimming if packet is unexpectedly large.
        trimmed = self._trim_prompt_packet(packet)
        trimmed_json = json.dumps(trimmed, ensure_ascii=False, sort_keys=True)
        prefix = prompt.split("Evidence packet:\n", 1)[0]
        return prefix + "Evidence packet:\n" + trimmed_json

    @staticmethod
    def _extract_content(raw: Dict[str, Any]) -> str:
        # Ollama /api/chat
        if isinstance(raw.get("message"), dict):
            return str(raw["message"].get("content", ""))

        # Ollama /api/generate
        if "response" in raw:
            return str(raw.get("response", ""))

        return ""

    @staticmethod
    def _parse_json_content(content: str) -> Optional[Dict[str, Any]]:
        content = content.strip()
        if not content:
            return None

        # Direct JSON.
        try:
            parsed = json.loads(content)
            return parsed if isinstance(parsed, dict) else None
        except json.JSONDecodeError:
            pass

        # Remove markdown fences if present.
        content = re.sub(r"^```(?:json)?\s*", "", content)
        content = re.sub(r"\s*```$", "", content).strip()

        try:
            parsed = json.loads(content)
            return parsed if isinstance(parsed, dict) else None
        except json.JSONDecodeError:
            pass

        # Last-resort extraction of first JSON object.
        start = content.find("{")
        end = content.rfind("}")
        if start == -1 or end == -1 or end <= start:
            return None

        try:
            parsed = json.loads(content[start:end + 1])
            return parsed if isinstance(parsed, dict) else None
        except json.JSONDecodeError:
            return None

    @staticmethod
    def _parse_confidence(value: Any) -> float:
        try:
            confidence = float(value)
        except (TypeError, ValueError):
            return 0.0
        return max(0.0, min(1.0, confidence))

    @staticmethod
    def _shorten_text(text: str, max_len: int) -> str:
        text = " ".join(str(text or "").split())
        if len(text) <= max_len:
            return text
        return text[: max_len - 3] + "..."

    def _compact_packet(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        """Keep detector.py packet shape, but remove oversized/noisy fields.

        detector.py currently passes:
        {
          task,
          source_function,
          binary_function,
          source_component,
          positive_evidence,
          missing_or_weak_evidence,
          callgraph_support,
          control_block_support,
          expected_response
        }

        This method also tolerates extra fields if you add them later.
        """

        if not isinstance(packet, dict):
            return {"invalid_packet": str(packet)}

        out: Dict[str, Any] = {}

        # Basic identity fields.
        for key in (
            "task",
            "source_component",
            "source_function",
            "binary_function",
            "positive_evidence",
            "missing_or_weak_evidence",
        ):
            if key in packet:
                out[key] = self._compact_value(packet[key])

        # Callgraph support.
        callgraph = packet.get("callgraph_support", {})
        if isinstance(callgraph, dict):
            out["callgraph_support"] = {
                "direct_relation_count": callgraph.get("direct_relation_count", 0),
                "reachable_or_inlined_relation_count": callgraph.get("reachable_or_inlined_relation_count", 0),
                "matched_context": self._limit_list(callgraph.get("matched_context", []), 8),
            }

        # Control-block support.
        cb = packet.get("control_block_support", {})
        if isinstance(cb, dict):
            out["control_block_support"] = {
                "token_jaccard": cb.get("token_jaccard", 0.0),
                "structural_similarity": cb.get("structural_similarity", 0.0),
                "shared_tokens_sample": self._limit_list(cb.get("shared_tokens_sample", []), 20),
                "source_block_count": cb.get("source_block_count", 0),
                "binary_block_count": cb.get("binary_block_count", 0),
            }

        # Optional fields if detector.py is later extended.
        string_support = packet.get("string_support", {})
        if isinstance(string_support, dict):
            out["string_support"] = {
                "shared_string_count": string_support.get("shared_string_count", 0),
                "shared_strings_sample": self._limit_list(string_support.get("shared_strings_sample", []), 20),
            }

        callstr_support = packet.get("callstr_support", {})
        if isinstance(callstr_support, dict):
            out["callstr_support"] = {
                "token_jaccard": callstr_support.get("token_jaccard", 0.0),
                "shared_tokens_sample": self._limit_list(callstr_support.get("shared_tokens_sample", []), 20),
            }

        # If extra compact evidence exists, keep it.
        for key in ("scores", "existing_scores", "deterministic_scores"):
            if key in packet:
                out[key] = self._compact_value(packet[key])

        return out

    def _trim_prompt_packet(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        """More aggressive size reduction for large prompts."""
        compact = self._compact_packet(packet)

        if isinstance(compact.get("callgraph_support"), dict):
            compact["callgraph_support"]["matched_context"] = self._limit_list(
                compact["callgraph_support"].get("matched_context", []), 4
            )

        if isinstance(compact.get("control_block_support"), dict):
            compact["control_block_support"]["shared_tokens_sample"] = self._limit_list(
                compact["control_block_support"].get("shared_tokens_sample", []), 10
            )

        if isinstance(compact.get("string_support"), dict):
            compact["string_support"]["shared_strings_sample"] = self._limit_list(
                compact["string_support"].get("shared_strings_sample", []), 10
            )

        if isinstance(compact.get("callstr_support"), dict):
            compact["callstr_support"]["shared_tokens_sample"] = self._limit_list(
                compact["callstr_support"].get("shared_tokens_sample", []), 10
            )

        compact["prompt_trimmed"] = True
        return compact

    def _compact_value(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {str(k): self._compact_value(v) for k, v in value.items()}
        if isinstance(value, list):
            return self._limit_list(value, 30)
        if isinstance(value, tuple):
            return self._limit_list(list(value), 30)
        if isinstance(value, set):
            return self._limit_list(sorted(value), 30)
        if isinstance(value, str):
            return self._shorten_text(value, 300)
        return value

    def _limit_list(self, values: Any, limit: int) -> List[Any]:
        if not isinstance(values, list):
            values = list(values) if isinstance(values, (tuple, set)) else []
        out = []
        for item in values[:limit]:
            if isinstance(item, dict):
                out.append({str(k): self._compact_value(v) for k, v in item.items()})
            elif isinstance(item, (list, tuple, set)):
                out.append(self._limit_list(item, limit))
            elif isinstance(item, str):
                out.append(self._shorten_text(item, 300))
            else:
                out.append(item)
        return out

    def verify_spillover(
        self,
        parent_name: str,
        matched_func_names: List[str],
        subcomponent_origins: List[str],
    ) -> bool:
        """Return True if parent's detection is spillover from its subcomponents.

        Called only when every matched function of `parent_name` is ALSO observed
        inside one of `subcomponent_origins`, and none of those subcomponents
        was directly detected. The LLM is asked whether the parent itself is
        truly present in the binary or whether the binary contains only the
        subcomponent code that happens to live under the parent's repo.
        """
        if not self.config.enabled:
            return False

        prompt = (
            "An OSS component was detected in a binary, but every matched function\n"
            "of this component is ALSO observed in one of its known sub-component\n"
            "libraries — and none of those sub-components were detected directly.\n\n"
            f"Parent component: {parent_name}\n"
            f"Known sub-components sharing the matched code: {', '.join(sorted(subcomponent_origins))}\n\n"
            f"Matched function names ({len(matched_func_names)}):\n"
            + "\n".join(f"  {n}" for n in matched_func_names[:40])
            + (f"\n  ... ({len(matched_func_names) - 40} more)" if len(matched_func_names) > 40 else "")
            + "\n\nIs the parent component itself genuinely present in the binary,\n"
              "or is this a spillover where the binary only contains the sub-component\n"
              "code and the parent name is being incorrectly attributed?\n\n"
              "Return strict JSON: "
              '{"verdict": "spillover" or "genuine", "reason": "short reason"}'
        )

        payload = self._build_payload(prompt)
        if "messages" in payload:
            payload["messages"][0]["content"] = (
                "You are a binary software composition analysis expert. "
                "Decide whether a detected parent component is genuine or a "
                "spillover from its sub-component. Return strict JSON only."
            )

        request = urllib.request.Request(
            self.url,
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout) as response:
                raw = json.loads(response.read().decode("utf-8", errors="replace"))
        except Exception as exc:
            print(f"    [LLM-spillover] request failed: {exc}")
            return False

        content = self._extract_content(raw)
        parsed = self._parse_json_content(content)
        if not parsed:
            return False

        verdict = str(parsed.get("verdict", "")).strip().lower()
        reason = str(parsed.get("reason", "")).strip()
        is_spillover = "spillover" in verdict
        tag = "spillover" if is_spillover else "genuine"
        print(f"    [LLM-spillover] {parent_name} → {tag}: {reason}")
        return is_spillover


    def verify_fp(
        self,
        candidate: Dict[str, Any],
        dominant: Dict[str, Any],
        overlap_funcs: List[str],
        unique_funcs: List[str],
    ) -> bool:
        """Return True if candidate is a false positive overshadowed by dominant.

        Shows LLM the overlapping matched functions between candidate and dominant,
        plus the functions unique to candidate, and asks if candidate is genuine.
        """
        if not self.config.enabled:
            return False

        overlap_ratio = len(overlap_funcs) / max(len(overlap_funcs) + len(unique_funcs), 1)
        prompt = (
            "Two OSS components were detected in a binary. They share matched functions.\n\n"
            f"Component A (dominant): {dominant['name']} — {dominant['graph_size']} matched functions\n"
            f"Component B (candidate): {candidate['name']} — {candidate['graph_size']} matched functions\n"
            f"Overlap ratio: {overlap_ratio:.0%} of B's matches also appear in A\n\n"
            f"Functions matched in BOTH A and B ({len(overlap_funcs)}):\n"
            + "\n".join(f"  {f}" for f in overlap_funcs[:40])
            + (f"\n  ... ({len(overlap_funcs) - 40} more)" if len(overlap_funcs) > 40 else "")
            + f"\n\nFunctions matched ONLY in B ({len(unique_funcs)}):\n"
            + ("\n".join(f"  {f}" for f in unique_funcs[:20]) if unique_funcs else "  (none)")
            + "\n\nIs Component B a false positive because it shares code with Component A?\n"
            "Return strict JSON: "
            '{"verdict": "false_positive" or "genuine", "reason": "short reason"}'
        )

        payload = self._build_payload(prompt)
        # Override system prompt for this task
        if "messages" in payload:
            payload["messages"][0]["content"] = (
                "You are a binary software composition analysis expert. "
                "Determine if a component detection is a false positive. "
                "Return strict JSON only."
            )

        request = urllib.request.Request(
            self.url,
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout) as response:
                raw = json.loads(response.read().decode("utf-8", errors="replace"))
        except Exception as exc:
            print(f"    [LLM-FP] request failed: {exc}")
            return False

        content = self._extract_content(raw)
        parsed = self._parse_json_content(content)
        if not parsed:
            return False

        verdict = str(parsed.get("verdict", "")).strip().lower()
        reason = str(parsed.get("reason", "")).strip()
        is_fp = "false_positive" in verdict
        tag = "FP" if is_fp else "genuine"
        print(f"    [LLM-FP] {candidate['name']} → {tag}: {reason}")
        return is_fp