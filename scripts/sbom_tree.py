#!/usr/bin/env python3
"""Render a dependency tree from a CycloneDX SBOM JSON file.

Usage:
    python scripts/sbom_tree.py out.json
    python scripts/sbom_tree.py out.json --root <name|bom-ref>
    python scripts/sbom_tree.py out.json --depth 3
    python scripts/sbom_tree.py out.json --dot > deps.dot
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Iterable


def load_sbom(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def build_index(sbom: dict) -> tuple[dict[str, str], dict[str, list[str]]]:
    """Return (label_by_ref, children_by_ref)."""
    labels: dict[str, str] = {}

    meta = sbom.get("metadata", {}).get("component")
    if meta and meta.get("bom-ref"):
        labels[meta["bom-ref"]] = _label(meta)

    for c in sbom.get("components", []):
        ref = c.get("bom-ref")
        if ref:
            labels[ref] = _label(c)

    children: dict[str, list[str]] = {}
    for d in sbom.get("dependencies", []):
        ref = d.get("ref")
        if not ref:
            continue
        children[ref] = list(d.get("dependsOn", []))

    return labels, children


def _label(component: dict) -> str:
    name = component.get("name", "?")
    version = component.get("version")
    ctype = component.get("type", "")
    base = f"{name}@{version}" if version else name
    return f"{base} ({ctype})" if ctype else base


def find_roots(children: dict[str, list[str]]) -> list[str]:
    """A root is a ref that appears as a key but is never a child of anything."""
    all_keys = set(children.keys())
    referenced: set[str] = set()
    for kids in children.values():
        referenced.update(kids)
    roots = sorted(all_keys - referenced)
    return roots if roots else sorted(all_keys)


def resolve_root(query: str, labels: dict[str, str], children: dict[str, list[str]]) -> str:
    """Resolve a user-supplied root identifier to a bom-ref."""
    if query in children or query in labels:
        return query
    matches = [ref for ref, lbl in labels.items() if query.lower() in lbl.lower()]
    if not matches:
        raise SystemExit(f"no component matches '{query}'")
    if len(matches) > 1:
        preview = "\n  ".join(labels[m] for m in matches[:10])
        raise SystemExit(
            f"'{query}' matches {len(matches)} components, be more specific:\n  {preview}"
        )
    return matches[0]


def print_tree(
    root: str,
    labels: dict[str, str],
    children: dict[str, list[str]],
    max_depth: int | None,
    out=sys.stdout,
) -> None:
    print(labels.get(root, root), file=out)
    _walk(root, labels, children, prefix="", depth=1, max_depth=max_depth, ancestors={root}, out=out)


def _walk(
    ref: str,
    labels: dict[str, str],
    children: dict[str, list[str]],
    prefix: str,
    depth: int,
    max_depth: int | None,
    ancestors: set[str],
    out,
) -> None:
    if max_depth is not None and depth > max_depth:
        return
    kids = children.get(ref, [])
    last = len(kids) - 1
    for i, child in enumerate(kids):
        connector = "└── " if i == last else "├── "
        label = labels.get(child, child)
        if child in ancestors:
            print(f"{prefix}{connector}{label}  ↻ (cycle)", file=out)
            continue
        print(f"{prefix}{connector}{label}", file=out)
        extension = "    " if i == last else "│   "
        _walk(
            child,
            labels,
            children,
            prefix + extension,
            depth + 1,
            max_depth,
            ancestors | {child},
            out=out,
        )


def emit_dot(
    roots: Iterable[str],
    labels: dict[str, str],
    children: dict[str, list[str]],
    out=sys.stdout,
) -> None:
    print("digraph sbom {", file=out)
    print('  rankdir=LR; node [shape=box, fontname="monospace"];', file=out)
    seen: set[str] = set()
    stack = list(roots)
    edges: list[tuple[str, str]] = []
    while stack:
        ref = stack.pop()
        if ref in seen:
            continue
        seen.add(ref)
        for kid in children.get(ref, []):
            edges.append((ref, kid))
            if kid not in seen:
                stack.append(kid)
    for ref in seen:
        print(f'  "{ref}" [label="{labels.get(ref, ref)}"];', file=out)
    for a, b in edges:
        print(f'  "{a}" -> "{b}";', file=out)
    print("}", file=out)


def main() -> None:
    p = argparse.ArgumentParser(description="Render a CycloneDX SBOM dependency tree.")
    p.add_argument("sbom", help="path to CycloneDX JSON (e.g. out.json)")
    p.add_argument("--root", help="bom-ref or substring of a component name to start from")
    p.add_argument("--depth", type=int, default=None, help="maximum depth to print")
    p.add_argument("--dot", action="store_true", help="emit Graphviz DOT instead of an ASCII tree")
    p.add_argument("--list-roots", action="store_true", help="list root components and exit")
    args = p.parse_args()

    sbom = load_sbom(args.sbom)
    labels, children = build_index(sbom)

    if args.root:
        roots = [resolve_root(args.root, labels, children)]
    else:
        roots = find_roots(children)

    if args.list_roots:
        for r in roots:
            print(f"{labels.get(r, r)}\t{r}")
        return

    if args.dot:
        emit_dot(roots, labels, children)
        return

    for i, root in enumerate(roots):
        if i:
            print()
        print_tree(root, labels, children, args.depth)


if __name__ == "__main__":
    main()
