from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

import numpy as np

CB_VECTOR_DIM = 368    # 364-bit key_feature_vector padded to next multiple of 8
CB_DIM_BYTES = CB_VECTOR_DIM // 8  # 46
CB_MAX_HAMMING = 80

INDEX_FILENAME = "cb_blocks.index"
META_FILENAME = "cb_blocks_meta.json"


def kfv_to_bytes(kfv: str) -> Optional[bytes]:
    """Convert 364-char '0'/'1' key_feature_vector string to 46-byte binary."""
    if not kfv or len(kfv) < 8 or not all(c in "01" for c in kfv):
        return None
    padded = kfv.ljust(CB_VECTOR_DIM, "0")[:CB_VECTOR_DIM]
    result = bytearray(CB_DIM_BYTES)
    for i, bit in enumerate(padded):
        if bit == "1":
            result[i // 8] |= 1 << (7 - i % 8)
    return bytes(result)


def _paths(db_dir: str):
    return (
        os.path.join(db_dir, INDEX_FILENAME),
        os.path.join(db_dir, META_FILENAME),
    )


def has_index(db_dir: str) -> bool:
    idx_path, meta_path = _paths(db_dir)
    return os.path.exists(idx_path) and os.path.exists(meta_path)


def build_and_save(records: List[Dict[str, Any]], db_dir: str) -> int:
    """Build IndexBinaryFlat from records and persist to db_dir.

    records: list of {component, function_id, function_name, block_type, vector (bytes, 46)}
    Returns number of vectors indexed.
    """
    import faiss
    if not records:
        return 0

    os.makedirs(db_dir, exist_ok=True)
    index = faiss.IndexBinaryFlat(CB_VECTOR_DIM)
    vecs = np.array([list(r["vector"]) for r in records], dtype=np.uint8)
    index.add(vecs)

    idx_path, meta_path = _paths(db_dir)
    faiss.write_index_binary(index, idx_path)

    meta = [
        {
            "component":     r.get("component", ""),
            "function_id":   r.get("function_id", ""),
            "function_name": r.get("function_name", ""),
            "block_type":    r.get("block_type", ""),
        }
        for r in records
    ]
    with open(meta_path, "w") as f:
        json.dump(meta, f)

    return len(records)


_cache: Dict[str, Any] = {}


def _load(db_dir: str):
    import faiss
    if db_dir not in _cache:
        idx_path, meta_path = _paths(db_dir)
        index = faiss.read_index_binary(idx_path)
        with open(meta_path) as f:
            meta = json.load(f)
        _cache[db_dir] = (index, meta)
    return _cache[db_dir]


def search_batch(
    query_vecs: List[bytes],
    db_dir: str,
    top_k: int = 5,
    max_hamming: int = CB_MAX_HAMMING,
) -> List[List[Dict[str, Any]]]:
    """Batch Hamming search. Returns one hit-list per query vector."""
    if not query_vecs:
        return []
    index, meta = _load(db_dir)
    q = np.array([list(v) for v in query_vecs], dtype=np.uint8)
    distances, indices = index.search(q, top_k)
    out = []
    for dists, idxs in zip(distances, indices):
        hits = []
        for dist, idx in zip(dists, idxs):
            if idx < 0 or dist > max_hamming:
                continue
            m = meta[idx]
            hits.append({
                "component":     m["component"],
                "function_id":   m.get("function_id", ""),
                "function_name": m["function_name"],
                "block_type":    m["block_type"],
                "distance":      int(dist),
            })
        out.append(hits)
    return out
