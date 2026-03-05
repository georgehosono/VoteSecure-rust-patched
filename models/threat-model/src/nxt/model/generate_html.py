#!/usr/bin/env python

# Interactive HTML Visualization Generator for the VoteSecure Threat Model
# Copyright (C) 2025-26 Free & Fair
# Last Revised 13 March 2026 by Daniel M. Zimmerman
#
# Generates a self-contained interactive HTML file combining tree-based views
# (security objectives, attacks, mitigations) with a force-directed graph view.
# No server (or Internet connectivity) is required to use the HTML file;
# all data and JS libraries are embedded inline.

import argparse
import base64
import gzip
import html
import json
import re
import urllib.request
from pathlib import Path

from natsort import natsorted

from nxt.model import model as threat_model, MODEL_VERSION, MODEL_DATE
from nxt.model.projection import get_projection_data
from nxt.schema.types import EdgeType


# =============================================================================
# Constants
# =============================================================================

NODE_COLORS = {
    "property": "#4CAF50",
    "attack": "#F44336",
    "pattern": "#FF9800",
    "mitigation": "#2196F3",
    "context": "#9C27B0",
}

NODE_SHAPES = {
    "property": "diamond",
    "attack": "triangle",
    "pattern": "triangleDown",
    "mitigation": "square",
    "context": "dot",
}

EDGE_COLORS = {
    EdgeType.REFINES: "#666666",
    EdgeType.TARGETS: "#F44336",
    EdgeType.ACHIEVES: "#FF5722",
    EdgeType.REQUIRES: "#795548",
    EdgeType.VARIANT_OF: "#607D8B",
    EdgeType.MITIGATES: "#2196F3",
    EdgeType.OCCURS_IN: "#9C27B0",
}

ARROW_SEP = " → "

VIS_NETWORK_URL = (
    "https://cdn.jsdelivr.net/npm/vis-network@9.1.9/standalone/umd/vis-network.min.js"
)
MARKED_URL = "https://cdn.jsdelivr.net/npm/marked@15.0.7/marked.min.js"
PAKO_URL = "https://cdn.jsdelivr.net/npm/pako@2.1.0/dist/pako.min.js"
CACHE_DIR = Path(__file__).resolve().parent.parent.parent.parent / ".cache"
REFERENCES_BIB = Path(__file__).resolve().parents[3] / "references.bib"


# =============================================================================
# Attack Mitigation Lineage Helpers
# =============================================================================


def _compute_attack_mitigations(model) -> dict[str, list[dict]]:
    """
    Precompute mitigation lines for each attack.

    Returns a dict mapping attack node IDs to lists of mitigation dicts.
    Each dict contains:
    - line: attack-line string with mitigation suffix
    - rationale: mitigation rationale (if provided)
    - style: 'direct', 'inherited', or 'oos'
    """
    attack_mitigations = {}

    for attack in model.attacks:
        node_id = attack.id
        mitigations = []
        _collect_attack_mits(model, attack, [], mitigations)
        for index, mitigation in enumerate(mitigations):
            mitigation["popup_id"] = f"{node_id}-{index}"
        attack_mitigations[node_id] = mitigations

    return attack_mitigations


def _compress_graph_attack_mitigations(
    attack_mitigations: dict[str, list[dict]],
) -> tuple[dict[str, list[dict]], dict[str, list[dict]]]:
    """Deduplicate graph attack-line segment arrays into a shared lookup table."""
    segment_lookup: dict[str, str] = {}
    segment_table: dict[str, list[dict]] = {}
    compressed: dict[str, list[dict]] = {}

    for attack_id, entries in attack_mitigations.items():
        compressed_entries = []
        for entry in entries:
            segments = entry.get("segments") or []
            canonical = json.dumps(
                segments, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            )

            segment_key = segment_lookup.get(canonical)
            if segment_key is None:
                segment_key = f"s{len(segment_table)}"
                segment_lookup[canonical] = segment_key
                segment_table[segment_key] = segments

            compressed_entry = {k: v for k, v in entry.items() if k != "segments"}
            compressed_entry["segment_key"] = segment_key
            compressed_entries.append(compressed_entry)

        compressed[attack_id] = compressed_entries

    return compressed, segment_table


def _graph_ref_segment(
    kind: str, label: str, element_id: str | None = None, is_abstract: bool = False
) -> dict:
    """Build a graph-side reference segment for linked attack lines."""
    normalized_label = _normalize_latex_punctuation(label) if label else label
    return {
        "kind": kind,
        "label": normalized_label,
        "id": element_id,
        "is_abstract": is_abstract,
    }


def _graph_line_text(segments: list[dict]) -> str:
    """Flatten graph-side line segments back to plain text for display."""
    labels = [
        _normalize_latex_punctuation(segment["label"])
        for segment in segments
        if segment.get("label")
    ]
    return ARROW_SEP.join(labels)


def _attack_concrete_lineage(attack) -> list[object]:
    """Return the concrete ancestor chain ending at the given attack."""
    lineage = []
    current = attack
    visited = set()

    while current is not None:
        current_id = getattr(current, "id", None)
        if current_id in visited:
            break
        if current_id is not None:
            visited.add(current_id)
        lineage.append(current)

        parent_attacks = list(getattr(current, "achieves", []))
        if not parent_attacks:
            break
        current = natsorted(parent_attacks, key=lambda p: p.id)[0]

    lineage.reverse()
    return lineage


def _get_attack_display(attack) -> str:
    """Get attack name with context(s) for display."""
    if attack.occurs_in:
        contexts = ", ".join(c.id for c in attack.occurs_in)
        return f"{attack.name} ({contexts})"
    return attack.name


def _collect_attack_mits(
    model, attack, lineage: list[dict], mitigations: list[dict]
) -> None:
    """Recursively collect mitigations from an attack and its descendants."""
    if lineage:
        current_lineage = lineage + [
            _graph_ref_segment("attack", _get_attack_display(attack), attack.id)
        ]
    else:
        current_lineage = [
            _graph_ref_segment("attack", _get_attack_display(node), node.id)
            for node in _attack_concrete_lineage(attack)
        ]

    # Direct mitigations on this attack
    for ma in attack.mitigations:
        rationale = ma.rationale or ""
        rationale_html = (
            _process_tags(_normalize_latex_punctuation(rationale)) if rationale else ""
        )
        mitigation_segment = _graph_ref_segment(
            "mitigation",
            ma.mitigation.name,
            None if ma.mitigation.id == "OOS" else ma.mitigation.id,
        )
        line_segments = current_lineage + [mitigation_segment]
        if ma.mitigation.id == "OOS":
            mitigations.append(
                {
                    "segments": line_segments,
                    "rationale_html": rationale_html,
                    "style": "oos",
                }
            )
        else:
            mitigations.append(
                {
                    "segments": line_segments,
                    "rationale_html": rationale_html,
                    "style": "direct",
                }
            )

    # Pattern mitigations (from variant_of hierarchy)
    if attack.variant_of:
        pattern_mits = _collect_pattern_mits(model, attack.variant_of, [])
        for mitigation_obj, pattern_path, is_oos, rationale in pattern_mits:
            rationale_html = (
                _process_tags(_normalize_latex_punctuation(rationale))
                if rationale
                else ""
            )
            pattern_segments = [
                _graph_ref_segment("attack", pattern.name, pattern.id, True)
                for pattern in pattern_path
            ]
            mitigation_segment = _graph_ref_segment(
                "mitigation",
                mitigation_obj.name,
                None if is_oos else mitigation_obj.id,
            )
            line_segments = current_lineage + pattern_segments + [mitigation_segment]

            if is_oos:
                mitigations.append(
                    {
                        "segments": line_segments,
                        "rationale_html": rationale_html,
                        "style": "oos",
                    }
                )
            else:
                mitigations.append(
                    {
                        "segments": line_segments,
                        "rationale_html": rationale_html,
                        "style": "inherited",
                    }
                )

    # Recurse into children (attacks that achieve this one)
    children = [a for a in model.attacks if attack in a.achieves]
    for child in children:
        _collect_attack_mits(model, child, current_lineage, mitigations)


def _collect_pattern_mits(
    model, pattern, pattern_path: list[object]
) -> list[tuple[object, list[object], bool, str]]:
    """Collect mitigations from a pattern and its refinements."""
    result = []

    for ma in pattern.mitigations:
        is_oos = ma.mitigation.id == "OOS"
        rationale = ma.rationale or ""
        result.append((ma.mitigation, pattern_path.copy(), is_oos, rationale))

    for child_pattern in model.patterns:
        if child_pattern.refines == pattern:
            child_path = pattern_path + [child_pattern]
            result.extend(_collect_pattern_mits(model, child_pattern, child_path))

    return result


# =============================================================================
# JS Library Management
# =============================================================================


def _fetch_js_library(url: str, cache_name: str) -> str:
    """Download a JS library and cache it locally."""
    cache_path = CACHE_DIR / cache_name
    if cache_path.exists():
        return cache_path.read_text(encoding="utf-8")
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    print(f"  Downloading {cache_name} from {url}...")
    content = urllib.request.urlopen(url).read().decode("utf-8")
    cache_path.write_text(content, encoding="utf-8")
    return content


# =============================================================================
# Tag Processing (converts {ref}, {[[cite]]}, {[target][text]} to HTML)
# =============================================================================

# These are populated once in _build_tree_data() before any serialization.
_tag_property_dict = {}
_tag_context_dict = {}
_tag_mitigation_dict = {}
_tag_attack_dict = {}
_tag_citation_dict = {}

_TAG_RE = re.compile(r"(\{.*?\})")
_INLINE_MATH_RE = re.compile(r"(?<!\\)\$(.+?)(?<!\\)\$")


def _lookup_model_reference(identifier: str) -> tuple[str, dict] | None:
    """Return the unique model element matching an identifier, if any."""
    candidates = []
    candidates.extend(
        ("property", p)
        for p in _tag_property_dict.values()
        if p["identifier"] == identifier
    )
    candidates.extend(
        ("context", c)
        for c in _tag_context_dict.values()
        if c["identifier"] == identifier
    )
    candidates.extend(
        ("mitigation", m)
        for m in _tag_mitigation_dict.values()
        if m["identifier"] == identifier
    )
    candidates.extend(
        ("attack", a)
        for a in _tag_attack_dict.values()
        if a["identifier"] == identifier
    )
    return candidates[0] if len(candidates) == 1 else None


def _render_model_ref(kind: str, element: dict, display_text: str | None = None) -> str:
    """Render a typed cross-reference for a model element."""
    if kind == "context":
        label = display_text or element["identifier"]
        title_attr = f' title="{html.escape(element.get("name", label))}"'
        extra_attrs = ""
    else:
        label = display_text or element["auto_identifier"]
        title_attr = ""
        extra_attrs = (
            ' data-ref-abstract="true"'
            if kind == "attack" and element.get("is_abstract")
            else ""
        )

    return (
        f'<a href="#" class="tm-ref" data-ref-kind="{kind}" '
        f'data-ref-id="{html.escape(element["id"])}"{extra_attrs}{title_attr}>'
        f"{html.escape(label)}</a>"
    )


def _resolve_tag(m: re.Match) -> str:
    """Convert a single {}-delimited tag to HTML markup."""
    orig = m.group(1)
    bare = orig[1:-1]  # strip { and }

    # Citation: {[[CiteKey]]}
    if bare.startswith("[[") and bare.endswith("]]"):
        cite_key = bare[2:-2]
        if cite_key:
            cite = _tag_citation_dict.get(cite_key)
            if cite:
                label = html.escape(cite.get("label", cite_key))
                title = html.escape(cite.get("title", cite_key))
                return (
                    f'<span class="tm-cite" title="{title}" '
                    f'data-cite-key="{html.escape(cite_key)}">[{label}]</span>'
                )
            return f'<span class="tm-cite" title="{cite_key}">[{cite_key}]</span>'
        return orig

    # Hyperlink with display text: {[target][text]}
    if bare.startswith("[") and bare.endswith("]") and "][" in bare:
        div = bare.index("][")
        target = bare[1:div]
        text = bare[div + 2 : -1]
        if "[" not in text and "]" not in text:
            resolved = _lookup_model_reference(target)
            if resolved:
                kind, element = resolved
                return _render_model_ref(kind, element, text)
            return (
                f'<a class="tm-ref" href="#{html.escape(target)}">'
                f"{html.escape(text)}</a>"
            )
        return orig

    # Model element reference: {M1}, {C1.1}, {VA}, etc.
    resolved = _lookup_model_reference(bare)
    if resolved:
        kind, element = resolved
        return _render_model_ref(kind, element)

    # Unrecognized — leave as-is
    return orig


def _render_inline_math(text: str) -> str:
    """Render inline LaTeX-style math ($...$) as monospaced HTML."""

    def repl(match: re.Match) -> str:
        expr = match.group(1).strip()
        if not expr:
            return match.group(0)
        return f'<code class="tm-inline-math">{html.escape(expr)}</code>'

    rendered = _INLINE_MATH_RE.sub(repl, text)
    return rendered.replace(r"\$", "$")


def _process_tags(text: str | None) -> str | None:
    """Replace all {}-delimited tags in text with HTML markup."""
    if not text:
        return text
    resolved = _TAG_RE.sub(_resolve_tag, text) if "{" in text else text
    return _render_inline_math(resolved)


def _normalize_latex_punctuation(text: str | None) -> str | None:
    """Normalize LaTeX-ish punctuation for HTML display."""
    if text is None:
        return None
    return text.replace("---", "—").replace("~", " ")


def _clean_bibtex_text(text: str | None) -> str:
    """Best-effort conversion from BibTeX-ish text to readable HTML text."""
    if not text:
        return ""
    cleaned = text.strip()
    if cleaned.startswith("{") and cleaned.endswith("}"):
        cleaned = cleaned[1:-1]
    if cleaned.startswith('"') and cleaned.endswith('"'):
        cleaned = cleaned[1:-1]
    replacements = {
        r"\&": "&",
        r"\%": "%",
        r"\_": "_",
        r"~": " ",
        r"{{": "",
        r"}}": "",
        r"{": "",
        r"}": "",
        r"\'e": "é",
        r"\'E": "É",
        r"\"u": "ü",
        r"\"U": "Ü",
        r"\"o": "ö",
        r"\"O": "Ö",
        r"\"a": "ä",
        r"\"A": "Ä",
        r"\ss": "ß",
    }
    for old, new in replacements.items():
        cleaned = cleaned.replace(old, new)
    cleaned = re.sub(r"\\[a-zA-Z]+\s*", "", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned)
    return _normalize_latex_punctuation(cleaned).strip()


def _split_bibtex_authors(author_field: str) -> list[str]:
    return [
        _clean_bibtex_text(a) for a in re.split(r"\s+and\s+", author_field) if a.strip()
    ]


def _short_author_name(author: str) -> str:
    if not author:
        return "Unknown"
    author = author.strip()
    if "," in author:
        return author.split(",", 1)[0].strip()
    parts = author.split()
    return parts[-1] if parts else author


def _build_citation_label(entry: dict) -> str:
    authors = entry.get("authors", [])
    year = entry.get("year") or "n.d."
    if not authors:
        return year
    if len(authors) == 1:
        author_part = _short_author_name(authors[0])
    elif len(authors) == 2:
        author_part = (
            f"{_short_author_name(authors[0])} & {_short_author_name(authors[1])}"
        )
    else:
        author_part = f"{_short_author_name(authors[0])} et al."
    return f"{author_part} {year}"


def _parse_bibtex_entry(entry_text: str) -> tuple[str, dict] | None:
    match = re.match(r"@(\w+)\s*\{\s*([^,]+),", entry_text, re.DOTALL)
    if not match:
        return None
    entry_type = match.group(1).strip()
    cite_key = match.group(2).strip()
    body = entry_text[match.end() :].rstrip().rstrip("}").strip()

    fields = {}
    i = 0
    while i < len(body):
        while i < len(body) and body[i] in " \t\r\n,":
            i += 1
        if i >= len(body):
            break
        start = i
        while i < len(body) and body[i] not in "=":
            i += 1
        field_name = body[start:i].strip().lower()
        i += 1
        while i < len(body) and body[i].isspace():
            i += 1
        if i >= len(body):
            break
        if body[i] == "{":
            depth = 0
            start = i
            while i < len(body):
                if body[i] == "{":
                    depth += 1
                elif body[i] == "}":
                    depth -= 1
                    if depth == 0:
                        i += 1
                        break
                i += 1
            value = body[start:i]
        elif body[i] == '"':
            start = i
            i += 1
            while i < len(body):
                if body[i] == '"' and body[i - 1] != "\\":
                    i += 1
                    break
                i += 1
            value = body[start:i]
        else:
            start = i
            while i < len(body) and body[i] not in ",\n":
                i += 1
            value = body[start:i]
        fields[field_name] = _clean_bibtex_text(value)
        while i < len(body) and body[i] != ",":
            i += 1
        if i < len(body) and body[i] == ",":
            i += 1

    authors = _split_bibtex_authors(fields.get("author", ""))
    year = fields.get("year")
    if not year and fields.get("date"):
        year = fields["date"][:4]
    entry = {
        "type": entry_type,
        "key": cite_key,
        "title": fields.get("title", cite_key),
        "authors": authors,
        "year": year or "n.d.",
        "venue": fields.get("journal")
        or fields.get("journaltitle")
        or fields.get("booktitle")
        or fields.get("publisher")
        or fields.get("organization")
        or fields.get("institution")
        or fields.get("venue")
        or "",
        "url": fields.get("url", ""),
        "doi": fields.get("doi", ""),
    }
    entry["label"] = _build_citation_label(entry)
    entry["summary"] = ". ".join(
        part
        for part in [", ".join(authors), f"({entry['year']})", entry["title"]]
        if part
    )
    return cite_key, entry


def _load_bibtex_entries() -> dict[str, dict]:
    if not REFERENCES_BIB.exists():
        return {}
    text = REFERENCES_BIB.read_text(encoding="utf-8")
    entries = {}
    current = []
    depth = 0
    in_entry = False
    for line in text.splitlines():
        stripped = line.strip()
        if not in_entry and stripped.startswith("@"):
            in_entry = True
            current = [line]
            depth = line.count("{") - line.count("}")
            if depth <= 0:
                parsed = _parse_bibtex_entry("\n".join(current))
                if parsed:
                    key, entry = parsed
                    entries[key] = entry
                in_entry = False
            continue
        if in_entry:
            current.append(line)
            depth += line.count("{") - line.count("}")
            if depth <= 0:
                parsed = _parse_bibtex_entry("\n".join(current))
                if parsed:
                    key, entry = parsed
                    entries[key] = entry
                in_entry = False
    return entries


def _strip_context_suffix(
    identifier: str | None, context_identifiers: set[str]
) -> str | None:
    """Remove trailing context suffixes like '.BB' or '.TA,AS' from attack identifiers."""
    if not identifier:
        return identifier

    parts = identifier.rsplit(".", 1)
    if len(parts) != 2:
        return identifier

    suffix = parts[1]
    suffix_parts = [s.strip() for s in suffix.split(",") if s.strip()]
    if suffix_parts and all(s in context_identifiers for s in suffix_parts):
        return parts[0]
    return identifier


def _format_context_tab_attack_identifier(
    identifier: str | None, context_identifiers: set[str]
) -> str | None:
    """Format context-tab attack names with arrows but without redundant context suffixes."""
    stripped = _strip_context_suffix(identifier, context_identifiers)
    if not stripped:
        return stripped
    return stripped.replace(".", " → ")


def _process_tags_in_data(obj):
    """Recursively process tags in all string values of a nested data structure."""
    if isinstance(obj, str):
        normalized = _normalize_latex_punctuation(obj)
        return _process_tags(normalized)
    if isinstance(obj, dict):
        return {k: _process_tags_in_data(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_process_tags_in_data(item) for item in obj]
    return obj


def _process_context_refs_in_identifier(identifier: str) -> str:
    """
    Render trailing context suffixes as parenthetical refs.
    E.g., 'ATK7.1 Broken cryptography.TA' ->
    'ATK7.1 Broken cryptography (<span class="tm-ref" title="Trustee Application">TA</span>)'
    """
    if not identifier:
        return identifier

    # Build lookup map once per call
    context_name_by_identifier = {
        str(ctx.get("identifier", "")).strip(): ctx.get("name", "")
        for ctx in _tag_context_dict.values()
    }

    # Detect and transform trailing context suffix only
    parts = identifier.rsplit(".", 1)
    if len(parts) == 2:
        base, suffix = parts
        suffix_parts = [s.strip() for s in suffix.split(",") if s.strip()]

        if suffix_parts and all(s in context_name_by_identifier for s in suffix_parts):
            rendered = []
            for ctx_id in suffix_parts:
                title = context_name_by_identifier.get(ctx_id, ctx_id)
                ctx = next(
                    (
                        c
                        for c in _tag_context_dict.values()
                        if c.get("identifier") == ctx_id
                    ),
                    None,
                )
                if ctx:
                    rendered.append(_render_model_ref("context", ctx, ctx_id))
                else:
                    rendered.append(
                        f'<span class="tm-ref" title="{title}">{ctx_id}</span>'
                    )
            return f"{base.replace('.', ' → ')} ({', '.join(rendered)})"

    return identifier.replace(".", " → ")


# =============================================================================
# Tree View Data Serialization (ported from server.py)
# =============================================================================

_MIT_OUT_OF_SCOPE = {
    "id": None,
    "auto_identifier": "OOS",
    "name": "Out of Scope",
    "description": "Mitigating this attack is outside the scope of the "
    "E2E-VIV cryptographic core library.",
}


def _serialize_property(prop: dict) -> dict:
    return {
        "id": prop["id"],
        "auto_identifier": prop["auto_identifier"],
        "name": prop["name"],
        "description": prop["description"],
        "kind": prop["kind"],
        "children": [_serialize_property(c) for c in prop["children"]],
    }


def _serialize_attack_flat(atk: dict) -> dict:
    mitigations = []
    for m in atk["mitigations"]:
        if m["mitigation"] is None:
            mitigations.append({"id": None, "name": "Out of Scope"})
        else:
            mitigations.append(
                {
                    "id": m["mitigation"]["id"],
                    "name": m["mitigation"]["name"],
                }
            )
    return {
        "id": atk["id"],
        "auto_identifier": atk["auto_identifier"],
        "identifier": _process_context_refs_in_identifier(atk["identifier"]),
        "name": atk["name"],
        "description": atk["description"],
        "is_abstract": atk["is_abstract"],
        "mitigations": mitigations,
    }


def _serialize_attack_tree_node(atk: dict) -> dict:
    children = natsorted(
        [c for c in atk["children"] if not c["is_abstract"]],
        key=lambda a: a["auto_identifier"] or "",
    )
    return {
        "id": atk["id"],
        "auto_identifier": atk["auto_identifier"],
        "identifier": _process_context_refs_in_identifier(atk["identifier"]),
        "is_abstract": atk["is_abstract"],
        "description": atk["description"],
        "children": [_serialize_attack_tree_node(c) for c in children],
    }


def _serialize_abstract_attack_tree_node(atk: dict) -> dict:
    children = natsorted(
        [c for c in atk["children"] if c["is_abstract"]],
        key=lambda a: a["auto_identifier"] or "",
    )
    return {
        "id": atk["id"],
        "auto_identifier": atk["auto_identifier"],
        "identifier": _process_context_refs_in_identifier(atk["identifier"]),
        "description": atk["description"],
        "children": [_serialize_abstract_attack_tree_node(c) for c in children],
    }


def _serialize_mitigation(mit: dict) -> dict:
    return {
        "id": mit["id"],
        "auto_identifier": mit["auto_identifier"],
        "name": mit["name"],
        "description": mit["description"],
    }


def _collect_attacks_for_property(prop: dict) -> list[dict]:
    attacks = list(prop["attacks"])
    for child in prop["children"]:
        attacks.extend(_collect_attacks_for_property(child))
    return attacks


def _attack_display_label(atk: dict) -> str:
    return f"{atk.get('auto_identifier', '')} {atk.get('identifier', '')}".strip()


def _attack_abstract_lineage(atk: dict) -> list[dict]:
    """Return abstract-parent lineage from root pattern to attack/pattern."""
    lineage = [atk]
    current = atk
    visited: set[int] = set()
    while current.get("parents"):
        abstract_parents = [
            p for p in current.get("parents", []) if p.get("is_abstract")
        ]
        if not abstract_parents:
            break
        parent = natsorted(abstract_parents, key=lambda p: p.get("identifier", ""))[0]
        parent_id = parent.get("id")
        if parent_id in visited:
            break
        visited.add(parent_id)
        lineage.append(parent)
        current = parent
    lineage.reverse()
    return lineage


def _attack_pattern_line(atk: dict) -> str:
    """Build a human-readable attack-pattern line, e.g. Parent → Child."""
    labels = [node.get("identifier", "") for node in _attack_abstract_lineage(atk)]
    labels = [label for label in labels if label]
    return ARROW_SEP.join(labels)


def _attack_pattern_segments(atk: dict) -> list[dict]:
    """Build attack-line segments for popup rendering/navigation."""
    segments = []
    for node in _attack_abstract_lineage(atk):
        label = _normalize_latex_punctuation(node.get("identifier", "") or "")
        if not label:
            continue
        segments.append(
            {
                "kind": "attack",
                "label": label,
                "id": node.get("id"),
                "is_abstract": bool(node.get("is_abstract", False)),
            }
        )
    return segments


def _collect_mitigations_for_attack(
    atk: dict,
    include_inherited: bool = True,
    include_descendants: bool = True,
    _visited: set[int] | None = None,
) -> dict:
    """Collect mitigations for an attack from direct, descendant, and inherited sources."""
    if _visited is None:
        _visited = set()
    if atk["id"] in _visited:
        return {}
    _visited.add(atk["id"])

    mitigations = {}

    # Direct mitigations on this attack
    for mit in atk["mitigations"]:
        key = (
            mit["mitigation"]["auto_identifier"]
            if mit["mitigation"] is not None
            else None
        )
        mitigations[key] = {
            "mitigation": mit["mitigation"],
            "rationale": mit.get("rationale", ""),
            "transitive": False,
            "source_attack_id": None,
            "source_attack_label": None,
            "source_attack_is_abstract": None,
            "source_relation": None,
            "source_attack_line": None,
            "source_attack_line_segments": [],
        }

    # Descendant mitigations (pattern tree semantics only)
    if include_descendants and atk.get("is_abstract"):
        for child in atk["children"]:
            child_mits = _collect_mitigations_for_attack(
                child,
                include_inherited=False,
                include_descendants=True,
                _visited=_visited,
            )
            for key, entry in child_mits.items():
                inherited_entry = dict(entry)
                inherited_entry["transitive"] = True
                if not inherited_entry.get("source_attack_id"):
                    inherited_entry["source_attack_id"] = child.get("id")
                    inherited_entry["source_attack_label"] = child.get(
                        "identifier", ""
                    ).replace(".", " → ")
                    inherited_entry["source_attack_is_abstract"] = child.get(
                        "is_abstract", False
                    )
                    inherited_entry["source_relation"] = "descendant"
                    inherited_entry["source_attack_line"] = _attack_pattern_line(child)
                    inherited_entry["source_attack_line_segments"] = (
                        _attack_pattern_segments(child)
                    )
                elif not inherited_entry.get("source_relation"):
                    inherited_entry["source_relation"] = "descendant"
                if key not in mitigations:
                    mitigations[key] = inherited_entry

    # Inherited mitigations from parents / instance-of chain
    if include_inherited:
        inherited_sources = []
        if atk.get("instance_of") is not None:
            inherited_sources.append((atk["instance_of"], True))
        inherited_sources.extend((parent, False) for parent in atk.get("parents", []))

        for source, source_include_descendants in inherited_sources:
            source_mits = _collect_mitigations_for_attack(
                source,
                include_inherited=True,
                include_descendants=source_include_descendants,
                _visited=_visited,
            )
            for key, entry in source_mits.items():
                inherited_entry = dict(entry)
                inherited_entry["transitive"] = True
                if not inherited_entry.get("source_attack_id"):
                    inherited_entry["source_attack_id"] = source.get("id")
                    inherited_entry["source_attack_label"] = source.get(
                        "identifier", ""
                    ).replace(".", " → ")
                    inherited_entry["source_attack_is_abstract"] = source.get(
                        "is_abstract", False
                    )
                    inherited_entry["source_relation"] = "ancestor"
                    inherited_entry["source_attack_line"] = _attack_pattern_line(source)
                    inherited_entry["source_attack_line_segments"] = (
                        _attack_pattern_segments(source)
                    )
                if key not in mitigations:
                    mitigations[key] = inherited_entry

    _visited.remove(atk["id"])
    return mitigations


def _format_mitigations(mits: dict) -> list[dict]:
    if len(mits) > 1 and None in mits:
        del mits[None]
    if None in mits:
        result = _MIT_OUT_OF_SCOPE.copy()
        result["rationale"] = mits[None].get("rationale", "")
        result["transitive"] = mits[None].get("transitive", False)
        result["source_attack_id"] = mits[None].get("source_attack_id")
        result["source_attack_label"] = mits[None].get("source_attack_label")
        result["source_attack_is_abstract"] = mits[None].get(
            "source_attack_is_abstract"
        )
        result["source_relation"] = mits[None].get("source_relation")
        result["source_attack_line"] = mits[None].get("source_attack_line")
        result["source_attack_line_segments"] = mits[None].get(
            "source_attack_line_segments", []
        )
        return [result]
    return [
        {
            "id": m["mitigation"]["id"],
            "auto_identifier": m["mitigation"]["auto_identifier"],
            "name": m["mitigation"]["name"],
            "description": m["mitigation"]["description"],
            "rationale": m["rationale"],
            "transitive": m.get("transitive", False),
            "source_attack_id": m.get("source_attack_id"),
            "source_attack_label": m.get("source_attack_label"),
            "source_attack_is_abstract": m.get("source_attack_is_abstract"),
            "source_relation": m.get("source_relation"),
            "source_attack_line": m.get("source_attack_line"),
            "source_attack_line_segments": m.get("source_attack_line_segments", []),
        }
        for m in mits.values()
    ]


def _compress_tree_attack_mitigations(
    attack_mitigations: dict[str, list[dict]],
) -> tuple[dict[str, list[dict]], dict[str, list[dict]]]:
    """Deduplicate TREE source-attack line segments into a shared lookup table."""
    segment_lookup: dict[str, str] = {}
    segment_table: dict[str, list[dict]] = {}
    compressed: dict[str, list[dict]] = {}

    for attack_id, entries in attack_mitigations.items():
        compressed_entries = []
        for entry in entries:
            segments = entry.get("source_attack_line_segments") or []
            if not segments:
                compressed_entries.append(entry)
                continue

            canonical = json.dumps(
                segments, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            )
            segment_key = segment_lookup.get(canonical)
            if segment_key is None:
                segment_key = f"ts{len(segment_table)}"
                segment_lookup[canonical] = segment_key
                segment_table[segment_key] = segments

            compressed_entry = {
                k: v for k, v in entry.items() if k != "source_attack_line_segments"
            }
            compressed_entry["source_attack_line_segment_key"] = segment_key
            compressed_entries.append(compressed_entry)

        compressed[attack_id] = compressed_entries

    return compressed, segment_table


def _collect_properties_for_attack(atk: dict) -> dict:
    properties = {p["id"]: p for p in atk["properties"]}
    for child in atk["children"]:
        child_props = _collect_properties_for_attack(child)
        properties.update(child_props)
    return properties


def _get_rationale_for_mitigation(attack, mitigation_id, default=None):
    for mtg in attack["mitigations"]:
        if mtg["mitigation"] is not None and mitigation_id == mtg["mitigation"]["id"]:
            return mtg["rationale"]
    return default


def _get_child_attacks_for_mitigation(parent, mitigation_id, rationale, attack_dict):
    result = []
    for child in parent["children"]:
        child_rationale = _get_rationale_for_mitigation(child, mitigation_id, rationale)
        result.append(
            {
                "id": child["id"],
                "auto_identifier": child["auto_identifier"],
                "identifier": _process_context_refs_in_identifier(child["identifier"]),
                "description": child["description"],
                "rationale": child_rationale,
                "is_abstract": child["is_abstract"],
            }
        )
        result.extend(
            _get_child_attacks_for_mitigation(
                child, mitigation_id, child_rationale, attack_dict
            )
        )
        if child["is_abstract"]:
            result.extend(
                _get_instance_attacks_for_mitigation(
                    child, mitigation_id, child_rationale, attack_dict
                )
            )
    return result


def _get_instance_attacks_for_mitigation(
    abstract, mitigation_id, rationale, attack_dict
):
    result = []
    for instance in attack_dict.values():
        if instance["instance_of"] == abstract:
            inst_rationale = _get_rationale_for_mitigation(
                instance, mitigation_id, rationale
            )
            result.append(
                {
                    "id": instance["id"],
                    "auto_identifier": instance["auto_identifier"],
                    "identifier": _process_context_refs_in_identifier(
                        instance["identifier"]
                    ),
                    "description": instance["description"],
                    "rationale": inst_rationale,
                    "is_abstract": instance["is_abstract"],
                }
            )
            result.extend(
                _get_child_attacks_for_mitigation(
                    instance, mitigation_id, inst_rationale, attack_dict
                )
            )
    return result


def _compute_mitigation_attacks(mitigation_id, attack_dict):
    attacks = []
    for atk in attack_dict.values():
        if atk["mitigations"] is not None:
            for mtg in atk["mitigations"]:
                if (
                    mtg["mitigation"] is not None
                    and mitigation_id == mtg["mitigation"]["id"]
                ):
                    attacks.append(
                        {
                            "id": atk["id"],
                            "auto_identifier": atk["auto_identifier"],
                            "identifier": _process_context_refs_in_identifier(
                                atk["identifier"]
                            ),
                            "description": atk["description"],
                            "rationale": mtg["rationale"],
                            "is_abstract": atk["is_abstract"],
                        }
                    )
                    attacks.extend(
                        _get_child_attacks_for_mitigation(
                            atk, mitigation_id, mtg["rationale"], attack_dict
                        )
                    )
                    if atk["is_abstract"]:
                        attacks.extend(
                            _get_instance_attacks_for_mitigation(
                                atk, mitigation_id, mtg["rationale"], attack_dict
                            )
                        )
    return natsorted(attacks, key=lambda a: a["auto_identifier"] or "")


def _build_attack_popup_data(attack_dict: dict) -> dict[str, dict]:
    """Build compact data needed for lazy attack popup rendering."""
    popup_data: dict[str, dict] = {}

    for attack in attack_dict.values():
        attack_id = attack.get("id")
        if not attack_id:
            continue

        is_abstract = bool(attack.get("is_abstract", False))
        auto_identifier = (
            "" if is_abstract else (attack.get("auto_identifier", "") or "")
        )
        graph_node_ref = attack.get("auto_identifier", "") or attack_id

        lineage = _attack_abstract_lineage(attack)
        lineage_ids = [node.get("id") for node in lineage if node.get("id")]

        popup_data[attack_id] = {
            "id": attack_id,
            "is_abstract": is_abstract,
            "auto_identifier": auto_identifier,
            "graph_node_ref": graph_node_ref,
            "identifier": _process_context_refs_in_identifier(
                _normalize_latex_punctuation(attack.get("identifier", "")) or ""
            ),
            "description": _process_tags(
                _normalize_latex_punctuation(attack.get("description", ""))
            ),
            "lineage_ids": lineage_ids,
        }

    return popup_data


def _build_citation_popup_data(citation_dict: dict[str, dict]) -> dict[str, dict]:
    """Build compact data needed for lazy citation popup rendering."""
    popup_data: dict[str, dict] = {}

    for cite_key, cite in citation_dict.items():
        popup_data[cite_key] = {
            "key": cite_key,
            "title": cite.get("title", cite_key),
            "label": cite.get("label", cite_key),
            "authors": cite.get("authors", []),
            "year": cite.get("year", "n.d."),
            "venue": cite.get("venue", ""),
            "doi": cite.get("doi", ""),
            "url": cite.get("url", ""),
        }

    return popup_data


def _build_context_popup_data(context_dict: dict) -> dict[str, dict]:
    """Build compact data needed for lazy context popup rendering."""
    popup_data: dict[str, dict] = {}

    for ctx in context_dict.values():
        context_id = ctx.get("id")
        if not context_id:
            continue
        popup_data[context_id] = {
            "id": context_id,
            "identifier": _normalize_latex_punctuation(ctx.get("identifier", "")) or "",
            "name": _normalize_latex_punctuation(ctx.get("name", "")) or "",
            "kind": _normalize_latex_punctuation(ctx.get("kind", "")) or "",
            "description": _process_tags(
                _normalize_latex_punctuation(ctx.get("description", ""))
            ),
            "graph_node_ref": _normalize_latex_punctuation(ctx.get("identifier", ""))
            or context_id,
        }

    return popup_data


def _build_property_popup_data(property_dict: dict) -> dict[str, dict]:
    """Build compact data needed for lazy property popup rendering."""
    popup_data: dict[str, dict] = {}

    for prop in property_dict.values():
        prop_id = prop.get("id")
        if not prop_id:
            continue

        auto_identifier = str(prop.get("auto_identifier", "") or "")
        raw_name = str(prop.get("name", "") or "").strip()
        display_title = (
            raw_name
            if raw_name and raw_name != auto_identifier
            else "Security objective"
        )

        popup_data[prop_id] = {
            "id": prop_id,
            "auto_identifier": _normalize_latex_punctuation(auto_identifier) or "",
            "title": _normalize_latex_punctuation(display_title) or "",
            "description": _process_tags(
                _normalize_latex_punctuation(prop.get("description", ""))
            ),
            "graph_node_ref": _normalize_latex_punctuation(auto_identifier) or prop_id,
        }

    return popup_data


def _build_mitigation_popup_data(mitigation_dict: dict) -> dict[str, dict]:
    """Build compact data needed for lazy mitigation popup rendering."""
    popup_data: dict[str, dict] = {}

    for mitigation in mitigation_dict.values():
        mitigation_id = mitigation.get("id")
        if not mitigation_id:
            continue

        auto_identifier = str(mitigation.get("auto_identifier", "") or "")
        popup_data[mitigation_id] = {
            "id": mitigation_id,
            "auto_identifier": _normalize_latex_punctuation(auto_identifier) or "",
            "name": _normalize_latex_punctuation(mitigation.get("name", "")) or "",
            "description": _process_tags(
                _normalize_latex_punctuation(mitigation.get("description", ""))
            ),
            "graph_node_ref": _normalize_latex_punctuation(auto_identifier)
            or mitigation_id,
        }

    return popup_data


def _build_tree_data() -> tuple[dict, dict, dict]:
    """Build all pre-computed data needed by the tree views."""
    global \
        _tag_property_dict, \
        _tag_context_dict, \
        _tag_mitigation_dict, \
        _tag_attack_dict, \
        _tag_citation_dict
    property_dict, context_dict, mitigation_dict, attack_dict = get_projection_data()
    citation_dict = _load_bibtex_entries()

    # Populate tag lookup dicts for reference resolution
    _tag_property_dict = property_dict
    _tag_context_dict = context_dict
    _tag_mitigation_dict = mitigation_dict
    _tag_attack_dict = attack_dict
    _tag_citation_dict = citation_dict

    # Property tree (roots with kind=Model)
    property_tree = [
        _serialize_property(p)
        for p in property_dict.values()
        if p["parent"] is None and p["kind"] == "Model"
    ]

    # Attack tree (concrete attacks only; roots = no concrete parents)
    roots = [
        a
        for a in attack_dict.values()
        if not a["is_abstract"]
        and not any(not p["is_abstract"] for p in a.get("parents", []))
    ]
    sorted_roots = natsorted(roots, key=lambda a: a["auto_identifier"] or "")
    attack_tree = [_serialize_attack_tree_node(r) for r in sorted_roots]

    # Attack pattern list (flat) and tree
    sorted_abstract_attacks = natsorted(
        [a for a in attack_dict.values() if a["is_abstract"]],
        key=lambda a: a["auto_identifier"] or "",
    )
    abstract_attack_list = [_serialize_attack_flat(a) for a in sorted_abstract_attacks]
    abstract_roots = [
        a
        for a in attack_dict.values()
        if a["is_abstract"] and not any(p["is_abstract"] for p in a["parents"])
    ]
    sorted_abstract_roots = natsorted(
        abstract_roots, key=lambda a: a["auto_identifier"] or ""
    )
    abstract_attack_tree = [
        _serialize_abstract_attack_tree_node(a) for a in sorted_abstract_roots
    ]

    # Mitigation list (flat, sorted)
    sorted_mits = natsorted(
        mitigation_dict.values(), key=lambda m: m["auto_identifier"] or ""
    )
    mitigation_list = [_serialize_mitigation(m) for m in sorted_mits]

    # Per-property attack lists
    property_attacks = {}
    for prop_id, prop in property_dict.items():
        attacks = _collect_attacks_for_property(prop)
        sorted_attacks = natsorted(attacks, key=lambda a: a["auto_identifier"] or "")
        property_attacks[prop_id] = [a["id"] for a in sorted_attacks]

    # Per-attack mitigation lists
    attack_mitigations = {}
    for atk_id, atk in attack_dict.items():
        mits = _collect_mitigations_for_attack(atk)
        attack_mitigations[atk_id] = _format_mitigations(mits)

    attack_mitigations, source_attack_line_segments = _compress_tree_attack_mitigations(
        attack_mitigations
    )

    # Per-attack property lists
    attack_properties = {}
    for atk_id, atk in attack_dict.items():
        props = _collect_properties_for_attack(atk)
        sorted_props = natsorted(
            list(props.values()), key=lambda p: p.get("auto_identifier", "")
        )
        attack_properties[atk_id] = [p["id"] for p in sorted_props]

    # Per-abstract-attack concrete instantiations
    abstract_attack_instances = {}
    for atk_id, atk in attack_dict.items():
        if not atk["is_abstract"]:
            continue
        instances = [a for a in attack_dict.values() if a.get("instance_of") == atk]
        sorted_instances = natsorted(
            instances, key=lambda a: a["auto_identifier"] or ""
        )
        abstract_attack_instances[atk_id] = [
            _serialize_attack_flat(a) for a in sorted_instances
        ]

    # Per-mitigation attack lists
    mitigation_attacks = {}
    for mit_id in mitigation_dict:
        mitigation_attacks[mit_id] = _compute_mitigation_attacks(mit_id, attack_dict)

    attack_popup_data = _build_attack_popup_data(attack_dict)
    citation_popup_data = _build_citation_popup_data(citation_dict)
    context_popup_data = _build_context_popup_data(context_dict)
    property_popup_data = _build_property_popup_data(property_dict)
    mitigation_popup_data = _build_mitigation_popup_data(mitigation_dict)

    # Build context data grouped by kind
    contexts_by_kind = {}
    context_details = {}
    context_identifiers = {
        str(ctx.get("identifier", "")).strip() for ctx in context_dict.values()
    }
    for ctx_id, ctx in context_dict.items():
        kind = ctx.get("kind", "").lower()
        if kind not in contexts_by_kind:
            contexts_by_kind[kind] = []

        ctx_serial = {
            "id": ctx_id,
            "identifier": ctx.get("identifier", ""),
            "name": ctx.get("name", ""),
            "kind": ctx.get("kind", ""),
            "description": ctx.get("description", ""),
        }
        contexts_by_kind[kind].append(ctx_serial)

        # Collect attacks: find all attacks that occur in this context
        attacks_in_ctx = []
        for atk_id, atk in attack_dict.items():
            attack_ctx = atk.get("context")
            if attack_ctx and attack_ctx.get("id") == ctx_id:
                # Simple serialization without tag processing
                attacks_in_ctx.append(
                    {
                        "id": atk_id,
                        "auto_identifier": _normalize_latex_punctuation(
                            atk.get("auto_identifier", "")
                        ),
                        "identifier": _normalize_latex_punctuation(
                            _format_context_tab_attack_identifier(
                                atk.get("identifier", ""), context_identifiers
                            )
                        ),
                        "description": _normalize_latex_punctuation(
                            atk.get("description", "")
                        ),
                    }
                )
        sorted_attacks = natsorted(
            attacks_in_ctx, key=lambda a: a.get("auto_identifier", "")
        )
        ctx_serial["attacks"] = sorted_attacks

        context_details[ctx_id] = ctx_serial

    # Sort contexts within each kind
    for kind in contexts_by_kind:
        contexts_by_kind[kind] = natsorted(
            contexts_by_kind[kind], key=lambda c: c.get("identifier", "")
        )

    return (
        _process_tags_in_data(
            {
                "propertyTree": property_tree,
                "attackTree": attack_tree,
                "abstractAttackList": abstract_attack_list,
                "abstractAttackTree": abstract_attack_tree,
                "mitigationList": mitigation_list,
                "propertyAttacks": property_attacks,
                "attackMitigations": attack_mitigations,
                "sourceAttackLineSegments": source_attack_line_segments,
                "attackProperties": attack_properties,
                "abstractAttackInstances": abstract_attack_instances,
                "mitigationAttacks": mitigation_attacks,
                "attackPopupData": attack_popup_data,
                "citationPopupData": citation_popup_data,
                "contextPopupData": context_popup_data,
                "propertyPopupData": property_popup_data,
                "mitigationPopupData": mitigation_popup_data,
            }
        ),
        {
            "groupedByKind": contexts_by_kind,
            "contextDetails": context_details,
        },
        context_dict,
    )


# =============================================================================
# Context Popup HTML Generation
# =============================================================================


def _generate_context_popups(context_dict: dict) -> str:
    """Generate HTML for all context popups."""
    popups = []
    for ctx_id, ctx in context_dict.items():
        raw_identifier = _normalize_latex_punctuation(ctx.get("identifier", "")) or ""
        identifier = html.escape(raw_identifier)
        name = html.escape(_normalize_latex_punctuation(ctx.get("name", "")) or "")
        kind = html.escape(_normalize_latex_punctuation(ctx.get("kind", "")) or "")
        description = _process_tags(
            _normalize_latex_punctuation(ctx.get("description", ""))
        )

        popup_html = f"""<div id="context-popup-{identifier}" class="context-popup">
    <div class="context-popup-content">
        <div class="context-popup-header">
            <div>
                <div class="context-popup-identifier">{identifier}</div>
                <h2>{name}</h2>
            </div>
            <div class="context-popup-close-group">
                <button class="context-popup-nav" onclick="closeContextPopup('{raw_identifier}'); tmNavigateToModelRef('context', '{raw_identifier}', false);" title="Open details tab" aria-label="Open details tab">&#8599;</button>
                <button class="context-popup-nav" onclick="closeContextPopup('{raw_identifier}'); tmNavigateToGraphNode('{raw_identifier}');" title="Open in graph tab" aria-label="Open in graph tab">&#9672;</button>
                <button class="context-popup-close" onclick="closeContextPopup('{raw_identifier}')" title="Close popup" aria-label="Close popup">&times;</button>
            </div>
        </div>
        <div class="context-popup-kind">Kind: {kind}</div>
        {f'<div class="context-popup-description">{description}</div>' if description else ""}
    </div>
</div>"""
        popups.append(popup_html)

    return "\n".join(popups)


def _generate_citation_popups(citation_dict: dict[str, dict]) -> str:
    """Generate HTML for all citation popups."""
    popups = []
    for cite_key, cite in citation_dict.items():
        title = html.escape(cite.get("title", cite_key))
        label = html.escape(cite.get("label", cite_key))
        authors = html.escape(", ".join(cite.get("authors", [])))
        year = html.escape(cite.get("year", "n.d."))
        venue = html.escape(cite.get("venue", ""))
        doi = cite.get("doi", "")
        url = cite.get("url", "")
        links = []
        if doi:
            doi_url = f"https://doi.org/{doi}" if not doi.startswith("http") else doi
            links.append(
                f'<a class="tm-ref" href="{html.escape(doi_url)}" target="_blank" rel="noopener noreferrer">DOI</a>'
            )
        if url:
            links.append(
                f'<a class="tm-ref" href="{html.escape(url)}" target="_blank" rel="noopener noreferrer">URL</a>'
            )
        links_html = (
            f'<div class="context-popup-description">{" · ".join(links)}</div>'
            if links
            else ""
        )

        popup_html = f"""<div id="citation-popup-{html.escape(cite_key)}" class="context-popup citation-popup">
    <div class="context-popup-content">
        <div class="context-popup-header">
            <div>
                <div class="context-popup-identifier">[{label}]</div>
                <h2>{title}</h2>
            </div>
            <button class="context-popup-close" onclick="closeCitationPopup('{html.escape(cite_key)}')" title="Close popup" aria-label="Close popup">&times;</button>
        </div>
        <div class="context-popup-kind">{authors}{" · " if authors and year else ""}{year}</div>
        {f'<div class="context-popup-description">{venue}</div>' if venue else ""}
        {links_html}
        <div class="context-popup-description">BibTeX key: <code>{html.escape(cite_key)}</code></div>
    </div>
</div>"""
        popups.append(popup_html)

    return "\n".join(popups)


def _generate_property_popups(property_dict: dict) -> str:
    """Generate HTML for all property popups."""
    popups = []
    for prop in property_dict.values():
        prop_id = prop.get("id", "")
        raw_auto_identifier = str(prop.get("auto_identifier", ""))
        auto_identifier = html.escape(raw_auto_identifier)
        raw_name = str(prop.get("name", "") or "").strip()
        name = html.escape(raw_name)
        title = (
            name
            if raw_name and raw_name != raw_auto_identifier
            else "Security objective"
        )
        description = _process_tags(
            _normalize_latex_punctuation(prop.get("description", ""))
        )

        popup_html = f"""<div id="property-popup-{prop_id}" class="context-popup property-popup">
    <div class="context-popup-content">
        <div class="context-popup-header">
            <div>
                <div class="context-popup-identifier">{auto_identifier}</div>
                <h2>{title}</h2>
            </div>
            <div class="context-popup-close-group">
                <button class="context-popup-nav" onclick="closePropertyPopup('{prop_id}'); tmNavigateToModelRef('property', '{prop_id}', false);" title="Open details tab" aria-label="Open details tab">&#8599;</button>
                <button class="context-popup-nav" onclick="closePropertyPopup('{prop_id}'); tmNavigateToGraphNode('{raw_auto_identifier}');" title="Open in graph tab" aria-label="Open in graph tab">&#9672;</button>
                <button class="context-popup-close" onclick="closePropertyPopup('{prop_id}')" title="Close popup" aria-label="Close popup">&times;</button>
            </div>
        </div>
        {f'<div class="context-popup-description">{description}</div>' if description else ""}
    </div>
</div>"""
        popups.append(popup_html)

    return "\n".join(popups)


def _generate_mitigation_popups(mitigation_dict: dict) -> str:
    """Generate HTML for all mitigation popups."""
    popups = []
    for mitigation in mitigation_dict.values():
        mitigation_id = mitigation.get("id", "")
        raw_auto_identifier = str(mitigation.get("auto_identifier", ""))
        auto_identifier = html.escape(raw_auto_identifier)
        name = html.escape(mitigation.get("name", ""))
        description = _process_tags(
            _normalize_latex_punctuation(mitigation.get("description", ""))
        )

        popup_html = f"""<div id="mitigation-popup-{mitigation_id}" class="context-popup mitigation-popup">
    <div class="context-popup-content">
        <div class="context-popup-header">
            <div>
                <div class="context-popup-identifier">{auto_identifier}</div>
                <h2>{name}</h2>
            </div>
            <div class="context-popup-close-group">
                <button class="context-popup-nav" onclick="closeMitigationPopup('{mitigation_id}'); tmNavigateToModelRef('mitigation', '{mitigation_id}', false);" title="Open details tab" aria-label="Open details tab">&#8599;</button>
                <button class="context-popup-nav" onclick="closeMitigationPopup('{mitigation_id}'); tmNavigateToGraphNode('{raw_auto_identifier}');" title="Open in graph tab" aria-label="Open in graph tab">&#9672;</button>
                <button class="context-popup-close" onclick="closeMitigationPopup('{mitigation_id}')" title="Close popup" aria-label="Close popup">&times;</button>
            </div>
        </div>
        {f'<div class="context-popup-description">{description}</div>' if description else ""}
    </div>
</div>"""
        popups.append(popup_html)

    return "\n".join(popups)


def _generate_attack_popups(attack_dict: dict) -> str:
    """Generate HTML for attack/pattern popups."""
    popups = []
    for attack in attack_dict.values():
        attack_id = attack.get("id")
        raw_auto_identifier = attack.get("auto_identifier", "")
        auto_identifier = (
            "" if attack.get("is_abstract") else html.escape(raw_auto_identifier)
        )
        identifier = _process_context_refs_in_identifier(
            _normalize_latex_punctuation(attack.get("identifier", "")) or ""
        )
        description = _process_tags(
            _normalize_latex_punctuation(attack.get("description", ""))
        )
        kind = "Attack Pattern" if attack.get("is_abstract") else "Concrete Attack"

        lineage = _attack_abstract_lineage(attack)
        lineage_links = []
        lineage_details = []
        for node in lineage:
            node_id = node.get("id") or ""
            node_identifier = _process_context_refs_in_identifier(
                _normalize_latex_punctuation(node.get("identifier", "")) or ""
            )
            node_kind = "Attack Pattern" if node.get("is_abstract") else "Attack"
            node_description = _process_tags(
                _normalize_latex_punctuation(node.get("description", ""))
            )

            if node_id:
                lineage_links.append(
                    '<a href="#" class="tm-attack-ref" data-attack-id="'
                    + html.escape(node_id)
                    + '" data-attack-abstract="'
                    + ("true" if node.get("is_abstract") else "false")
                    + '">'
                    + node_identifier
                    + "</a>"
                )
            else:
                lineage_links.append(node_identifier)

            detail_html = (
                '<li class="attack-line-details-item">'
                + '<div class="attack-line-details-title">'
                + node_identifier
                + "</div>"
                + '<div class="attack-line-details-kind">'
                + node_kind
                + "</div>"
            )
            if node_description:
                detail_html += (
                    '<div class="attack-line-details-description">'
                    + node_description
                    + "</div>"
                )
            detail_html += "</li>"
            lineage_details.append(detail_html)

        lineage_html = ""
        if lineage_links:
            lineage_html = (
                '<div class="context-popup-description"><strong>Attack line</strong>: '
                + ARROW_SEP.join(lineage_links)
                + "</div>"
            )

        lineage_details_html = ""
        if len(lineage_details) > 1:
            lineage_details_html = (
                '<div class="context-popup-description"><strong>Attack line details</strong></div>'
                '<ul class="attack-line-details-list">'
                + "".join(lineage_details)
                + "</ul>"
            )

        popup_html = f"""<div id="attack-popup-{attack_id}" class="context-popup attack-popup">
    <div class="context-popup-content">
        <div class="context-popup-header">
            <div>
                {f'<div class="context-popup-identifier">{auto_identifier}</div>' if auto_identifier else ""}
                <h2>{identifier}</h2>
            </div>
            <div class="context-popup-close-group">
                <button class="context-popup-nav" onclick="closeAttackPopup('{attack_id}'); tmNavigateToModelRef('attack', '{attack_id}', {"true" if attack.get("is_abstract") else "false"});" title="Open details tab" aria-label="Open details tab">&#8599;</button>
                <button class="context-popup-nav" onclick="closeAttackPopup('{attack_id}'); tmNavigateToGraphNode('{raw_auto_identifier}');" title="Open in graph tab" aria-label="Open in graph tab">&#9672;</button>
                <button class="context-popup-close" onclick="closeAttackPopup('{attack_id}')" title="Close popup" aria-label="Close popup">&times;</button>
            </div>
        </div>
        <div class="context-popup-kind">Kind: {kind}</div>
        {lineage_html}
        {f'<div class="context-popup-description">{description}</div>' if description else ""}
        {lineage_details_html}
    </div>
</div>"""
        popups.append(popup_html)
    return "\n".join(popups)


def _graph_line_segment_details(segment: dict) -> tuple[str, str, str]:
    """Return title, kind, description for a graph attack-line segment."""
    kind = segment.get("kind")
    segment_id = segment.get("id")

    if kind == "attack" and segment_id in _tag_attack_dict:
        attack = _tag_attack_dict[segment_id]
        title = " ".join(
            part
            for part in [
                attack.get("auto_identifier", "")
                if not attack.get("is_abstract")
                else "",
                _process_context_refs_in_identifier(
                    _normalize_latex_punctuation(attack.get("identifier", "")) or ""
                ),
            ]
            if part
        )
        line_kind = "Attack Pattern" if attack.get("is_abstract") else "Attack"
        description = (
            _process_tags(_normalize_latex_punctuation(attack.get("description", "")))
            or ""
        )
        return title, line_kind, description

    if kind == "mitigation":
        if segment_id in _tag_mitigation_dict:
            mitigation = _tag_mitigation_dict[segment_id]
            title = " ".join(
                part
                for part in [
                    mitigation.get("auto_identifier", ""),
                    mitigation.get("name", ""),
                ]
                if part
            )
            description = (
                _process_tags(
                    _normalize_latex_punctuation(mitigation.get("description", ""))
                )
                or ""
            )
            return title, "Mitigation", description

        return (
            html.escape(
                _normalize_latex_punctuation(segment.get("label", "Out of Scope"))
                or "Out of Scope"
            ),
            "Out of Scope",
            "Mitigating this attack line is outside the scope of the E2E-VIV cryptographic core library.",
        )

    return (
        html.escape(_normalize_latex_punctuation(segment.get("label", "")) or ""),
        html.escape(kind or "Item"),
        "",
    )


def _graph_line_segment_title_html(segment: dict) -> str:
    """Render a clickable title for a graph attack-line segment when possible."""
    kind = segment.get("kind")
    segment_id = segment.get("id")

    if kind == "attack" and segment_id in _tag_attack_dict:
        attack = _tag_attack_dict[segment_id]
        label = " ".join(
            part
            for part in [
                attack.get("auto_identifier", "")
                if not attack.get("is_abstract")
                else "",
                html.escape(
                    _normalize_latex_punctuation(segment.get("label", ""))
                    or _normalize_latex_punctuation(attack.get("identifier", ""))
                    or ""
                ),
            ]
            if part
        )
        return (
            '<a href="#" class="tm-attack-ref" data-attack-id="'
            + html.escape(segment_id)
            + '" data-attack-abstract="'
            + ("true" if attack.get("is_abstract") else "false")
            + '">'
            + label
            + "</a>"
        )

    if kind == "mitigation" and segment_id in _tag_mitigation_dict:
        mitigation = _tag_mitigation_dict[segment_id]
        label = " ".join(
            part
            for part in [
                mitigation.get("auto_identifier", ""),
                html.escape(mitigation.get("name", "")),
            ]
            if part
        )
        return (
            '<a href="#" class="tm-ref" data-ref-kind="mitigation" data-ref-id="'
            + html.escape(segment_id)
            + '">'
            + label
            + "</a>"
        )

    return html.escape(_normalize_latex_punctuation(segment.get("label", "")) or "")


def _generate_graph_attack_line_popups(
    attack_mitigations: dict[str, list[dict]],
) -> str:
    """Generate dedicated popups for graph attack-line entries."""
    popups = []
    for mitigations in attack_mitigations.values():
        for mitigation in mitigations:
            popup_id = mitigation.get("popup_id")
            if not popup_id:
                continue

            line_text = html.escape(
                _normalize_latex_punctuation(
                    mitigation.get("line")
                    or _graph_line_text(mitigation.get("segments", []))
                    or ""
                )
                or ""
            )
            details = []
            for segment in mitigation.get("segments", []):
                _, kind, description = _graph_line_segment_details(segment)
                title_html = _graph_line_segment_title_html(segment)
                detail_html = (
                    '<li class="attack-line-details-item">'
                    + '<div class="attack-line-details-title">'
                    + title_html
                    + "</div>"
                    + '<div class="attack-line-details-kind">'
                    + html.escape(kind)
                    + "</div>"
                )
                if description:
                    detail_html += (
                        '<div class="attack-line-details-description">'
                        + description
                        + "</div>"
                    )
                detail_html += "</li>"
                details.append(detail_html)

            rationale_html = (
                '<div class="context-popup-description"><strong>Rationale</strong>: '
                + mitigation.get("rationale_html", "")
                + "</div>"
                if mitigation.get("rationale_html")
                else ""
            )

            popup_html = f"""<div id="graph-line-popup-{popup_id}" class="context-popup graph-line-popup">
    <div class="context-popup-content">
        <div class="context-popup-header">
            <div>
                <div class="context-popup-identifier">Attack line</div>
                <h2>{line_text}</h2>
            </div>
            <button class="context-popup-close" onclick="closeGraphLinePopup('{popup_id}')" title="Close popup" aria-label="Close popup">&times;</button>
        </div>
        <div class="context-popup-description"><strong>Components</strong></div>
        <ul class="attack-line-details-list">{"".join(details)}</ul>
        {rationale_html}
    </div>
</div>"""
            popups.append(popup_html)

    return "\n".join(popups)


# =============================================================================
# Graph View Data Serialization
# =============================================================================


def _build_graph_data() -> dict:
    """Build all data needed by the graph view."""
    G = threat_model.graph
    property_dict, context_dict, mitigation_dict, attack_dict = get_projection_data()

    node_display_ids = {}
    for p in property_dict.values():
        node_display_ids[p["id"]] = p.get("auto_identifier", p["id"])
    for c in context_dict.values():
        node_display_ids[c["id"]] = c.get("identifier", c["id"])
    for m in mitigation_dict.values():
        node_display_ids[m["id"]] = m.get("auto_identifier", m["id"])
    for a in attack_dict.values():
        node_display_ids[a["id"]] = a.get("auto_identifier", a["id"])

    def truncate(text: str, max_len: int) -> str:
        return text[:max_len] + "..." if len(text) > max_len else text

    def _process_graph_text(text: str | None) -> str:
        """Normalize punctuation and resolve {tag} markup for graph display."""
        if not text:
            return ""
        return _process_tags(_normalize_latex_punctuation(text)) or ""

    # Nodes
    nodes = []
    for node_id, data in G.nodes(data=True):
        node_type = data.get("node_type", "unknown")
        node_obj = data.get("node")
        display_id = node_display_ids.get(node_id, str(node_id))
        node_name = _normalize_latex_punctuation(getattr(node_obj, "name", "")) or ""

        if node_type == "property":
            label = display_id
            title = f"<b>{display_id}</b><br><br>{_process_graph_text(truncate(node_obj.description, 200))}"
        elif node_type == "attack":
            label = truncate(f"{display_id} {node_name}", 30)
            contexts = (
                ", ".join(c.id for c in node_obj.occurs_in)
                if node_obj.occurs_in
                else "N/A"
            )
            title = (
                f"<b>{node_name}</b><br><br>ID: {display_id}<br>Contexts: {contexts}"
            )
            if node_obj.description:
                title += f"<br><br>{_process_graph_text(truncate(node_obj.description, 300))}"
        elif node_type == "pattern":
            label = truncate(f"{display_id} {node_name}", 30)
            title = f"<b>Pattern: {node_name}</b><br><br>ID: {display_id}"
            if node_obj.description:
                title += f"<br><br>{_process_graph_text(truncate(node_obj.description, 300))}"
        elif node_type == "mitigation":
            label = truncate(f"{display_id} {node_name}", 30)
            title = f"<b>Mitigation: {node_name}</b><br><br>ID: {display_id}"
            if node_obj.description:
                title += f"<br><br>{_process_graph_text(truncate(node_obj.description, 300))}"
        elif node_type == "context":
            label = node_obj.id
            title = f"<b>Context: {node_obj.id}</b><br><br>{node_name}"
        else:
            label = str(node_id)
            title = str(node_id)

        nodes.append(
            {
                "id": node_id,
                "label": label,
                "title": title,
                "color": NODE_COLORS.get(node_type, "#888888"),
                "shape": NODE_SHAPES.get(node_type, "dot"),
                "size": 25 if node_type in ("property", "attack") else 20,
                "group": node_type,
            }
        )

    # Edges
    edges = []
    for source, target, data in G.edges(data=True):
        edge_type = data.get("edge_type", EdgeType.REFINES)
        title = edge_type.value
        if "rationale" in data and data["rationale"]:
            r = data["rationale"]
            if len(r) > 200:
                r = r[:200] + "..."
            title += f"<br><br>{r}"
        edges.append(
            {
                "from": source,
                "to": target,
                "title": title,
                "color": EDGE_COLORS.get(edge_type, "#888888"),
                "arrows": "to",
                "smooth": {"type": "curvedCW", "roundness": 0.1},
            }
        )

    # Adjacency maps for focus mode
    out_edges = {}
    in_edges = {}
    for node in G.nodes():
        out_edges[node] = list(G.successors(node))
        in_edges[node] = list(G.predecessors(node))

    # Node metadata for side panel
    node_labels = {}
    node_descriptions = {}
    attack_patterns = {}
    for node_id, data in G.nodes(data=True):
        node_type = data.get("node_type", "unknown")
        node_obj = data.get("node")
        display_id = node_display_ids.get(node_id, str(node_id))
        node_name = _normalize_latex_punctuation(getattr(node_obj, "name", "")) or ""
        if node_type == "property":
            node_labels[node_id] = display_id
            node_descriptions[node_id] = _process_graph_text(node_obj.description)
        elif node_type in ("attack", "pattern", "mitigation"):
            node_labels[node_id] = f"{display_id} {node_name}"
            node_descriptions[node_id] = _process_graph_text(node_obj.description)
        elif node_type == "context":
            node_labels[node_id] = f"{node_obj.id}: {node_name}"
            node_descriptions[node_id] = _process_graph_text(node_obj.name)
        else:
            node_labels[node_id] = str(node_id)
            node_descriptions[node_id] = ""

        if node_type == "attack" and getattr(node_obj, "variant_of", None):
            attack_patterns[node_id] = node_obj.variant_of.id

    # Attack mitigation lineages for side panel
    attack_mits_raw = _compute_attack_mitigations(threat_model)
    attack_mits, attack_line_segments = _compress_graph_attack_mitigations(
        attack_mits_raw
    )

    return {
        "nodes": nodes,
        "edges": edges,
        "outEdges": out_edges,
        "inEdges": in_edges,
        "nodeLabels": node_labels,
        "nodeDisplayIds": node_display_ids,
        "nodeDescriptions": node_descriptions,
        "attackMitigations": attack_mits,
        "attackLineSegments": attack_line_segments,
        "attackPatterns": attack_patterns,
    }


# =============================================================================
# HTML/CSS/JS Templates
# =============================================================================

CSS = """
/* === Theme Variables === */
:root {
    --bg-primary: #ffffff;
    --bg-secondary: #f8f9fa;
    --bg-tertiary: #e9ecef;
    --bg-highlight: #e6f2f4;
    --text-primary: #212529;
    --text-secondary: #495057;
    --text-muted: #6c757d;
    --text-description: #555;
    --border-color: #ddd;
    --border-subtle: #dee2e6;
    --border-input: #ced4da;
    --tree-line: #000;
    --card-bg: #fff;
    --search-hover: #e9ecef;
    --search-item-border: #eee;
    --badge-bg: #e9ecef;
    --graph-canvas-bg: #ffffff;
    --accent: #0d5460;
    --link-color: #0b5f6d;
    --link-hover: #053844;
    --tooltip-bg: #ffffff;
    --tooltip-text: #212529;
    --tooltip-border: #d0dee2;
    --tooltip-title: #0d5460;
    --tooltip-link: #0b5f6d;
    --tooltip-link-hover: #053844;
}
[data-theme="dark"] {
    --bg-primary: #152d35;
    --bg-secondary: #1e3a44;
    --bg-tertiary: #264a56;
    --bg-highlight: #1a4a54;
    --text-primary: #f0f4f6;
    --text-secondary: #c0ccd0;
    --text-muted: #8a9da4;
    --text-description: #a0b4ba;
    --border-color: #2a4a54;
    --border-subtle: #2a4a54;
    --border-input: #3a5a64;
    --tree-line: #6a8a94;
    --card-bg: #1e3a44;
    --search-hover: #264a56;
    --search-item-border: #2a4a54;
    --badge-bg: #264a56;
    --graph-canvas-bg: #1a2a32;
    --accent: #5ec6da;
    --link-color: #7ad3e4;
    --link-hover: #b2ecf5;
    --tooltip-bg: #2d3436;
    --tooltip-text: #f0f4f6;
    --tooltip-border: #44545a;
    --tooltip-title: #5ec6da;
    --tooltip-link: #7ad3e4;
    --tooltip-link-hover: #b2ecf5;
}

/* === Common === */
html, body {
    margin: 0;
    padding: 0;
    height: 100%;
    overflow: hidden;
    font-family: Arial, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
}
header {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    z-index: 1001;
    box-sizing: border-box;
}
#title-bar {
    background: #053844;
    color: white;
    padding: 8px 16px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 15px;
}
#title-bar .title {
    font-weight: bold;
    font-size: 16px;
}
#title-bar .title-right {
    display: flex;
    align-items: center;
    gap: 12px;
}
#title-bar .version {
    font-size: 12px;
    color: #eba52b;
}
#theme-toggle,
#layout-reset {
    background: none;
    border: 1px solid rgba(255,255,255,0.3);
    border-radius: 4px;
    color: white;
    cursor: pointer;
    width: 26px;
    height: 26px;
    padding: 0;
    font-size: 14px;
    line-height: 1;
    text-align: center;
    transition: background 0.2s;
}
#theme-toggle:hover,
#layout-reset:hover {
    background: rgba(255,255,255,0.15);
}
#layout-reset svg {
    width: 16px;
    height: 16px;
    display: block;
    margin: 0 auto;
}
nav {
    background: #0d5460;
    padding: 6px 16px;
    display: flex;
    justify-content: left;
    box-sizing: border-box;
}
nav a.tab-link {
    text-decoration: none;
    color: rgba(255,255,255,0.8);
    font-weight: bold;
    margin-right: 10px;
    cursor: pointer;
    padding: 5px 12px;
    border-radius: 4px;
}
nav a.tab-link:hover {
    color: white;
    background: rgba(255,255,255,0.1);
    text-decoration: none;
}
nav a.tab-link.active {
    background: #eba52b;
    color: #053844;
    text-decoration: none;
}
.tab-content {
    display: none;
    height: calc(100vh - 74px);
    margin-top: 74px;
}
.tab-content.active {
    display: flex;
}

/* === Tree View Layout (shared by Properties, Attacks, Mitigations tabs) === */
.split-view {
    display: flex;
    flex: 1;
    overflow: hidden;
}
.left-panel {
    flex: 0 0 34%;
    min-width: 260px;
    max-width: 44%;
    overflow-y: auto;
    padding: 20px;
    border-right: 1px solid var(--border-color);
    background: var(--bg-primary);
}
.right-panel {
    flex: 1;
    min-width: 260px;
    display: flex;
    flex-direction: column;
    background: var(--bg-primary);
}
.section {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    padding: 20px;
    border-bottom: 1px solid var(--border-color);
}
.section:last-child {
    border-bottom: none;
}

/* === Resizable Split Panes (tree/detail tabs) === */
.split-view.resizable-split .left-panel {
    border-right: none;
    max-width: none;
}
.split-view.resizable-split .right-panel.resizable-right .section {
    border-bottom: none;
}
.pane-divider {
    position: relative;
    flex: 0 0 auto;
    background: var(--border-color);
    z-index: 2;
}
.pane-divider::before {
    content: "";
    position: absolute;
    inset: 0;
    background: transparent;
    transition: background-color 0.12s ease;
}
.pane-divider:hover::before,
.pane-divider.is-dragging::before {
    background: color-mix(in srgb, var(--accent) 30%, transparent);
}
.pane-divider-vertical {
    width: 8px;
    cursor: col-resize;
}
.pane-divider-horizontal {
    height: 8px;
    cursor: row-resize;
}
body.is-resizing {
    user-select: none;
}

/* === Contexts Tab Layout Overrides === */
#tab-contexts .left-panel {
    flex: 0 0 320px;
    max-width: none;
}
#ctx-list {
    max-width: 100%;
}
#tab-contexts .right-panel {
    min-width: 0;
}
#ctx-details {
    display: flex;
    flex-direction: column;
    flex: 1;
    min-height: 0;
}
#ctx-details .section {
    min-height: 0;
}
#ctx-details .ctx-summary-section {
    flex: 0 0 auto;
    padding: 20px;
    border-bottom: 1px solid var(--border-color);
    overflow-y: auto;
}
#ctx-details .ctx-attacks-section,
#ctx-details .ctx-mitigations-section {
    flex: 1 1 0;
    min-height: 120px;
}
h2 {
    margin: 0 0 10px 0;
}
h3 {
    margin: 0 0 10px 0;
}
p {
    margin: 5px 0;
}

/* === Tree rendering === */
.tree, .tree ul, .tree li {
    position: relative;
}
.tree ul {
    list-style-type: none;
    padding-left: 32px;
}
.tree li::before, .tree li::after {
    content: "";
    position: absolute;
    left: -12px;
}
.tree li::before {
    border-top: 1px solid var(--tree-line);
    top: 9px;
    width: 8px;
    height: 0;
}
.tree li::after {
    border-left: 1px solid var(--tree-line);
    height: 100%;
    width: 0;
    top: 2px;
}
.tree ul > li:last-child::after {
    height: 8px;
}
li.li-mouse-pointer {
    cursor: pointer;
}
div.div-mouse-pointer {
    cursor: pointer;
}

/* === Threat model tags === */
.tm-ref,
.tm-attack-ref,
.tm-graph-line-ref {
    color: var(--link-color);
    text-decoration: underline;
    cursor: pointer;
    white-space: nowrap;
}
.tm-ref:visited,
.tm-attack-ref:visited,
.tm-graph-line-ref:visited {
    color: var(--link-color);
}
.tm-ref:hover,
.tm-ref:focus-visible,
.tm-attack-ref:hover,
.tm-attack-ref:focus-visible,
.tm-graph-line-ref:hover,
.tm-graph-line-ref:focus-visible {
    color: var(--link-hover);
}
.tm-cite {
    font-style: italic;
    color: var(--text-muted);
    cursor: pointer;
    text-decoration: underline;
}

.description {
    margin-top: 5px;
    color: var(--text-description);
    font-size: 0.9em;
    line-height: 1.4em;
    padding-left: 10px;
}
.attack, .mitigation {
    margin-top: 10px;
    padding: 10px;
    border: 1px solid var(--border-color);
    border-radius: 5px;
    background: var(--card-bg);
}
.active-property {
    background-color: var(--bg-highlight);
}
.active-attack {
    background-color: var(--bg-highlight);
}
.active-mitigation {
    background-color: var(--bg-highlight);
}

/* === Contexts View === */
.ctx-kind-section {
    margin-bottom: 10px;
}
.ctx-kind-header {
    padding: 6px 8px;
    font-weight: bold;
    color: var(--text-secondary);
    border-bottom: 1px solid var(--border-color);
    margin-bottom: 3px;
    font-size: 0.9em;
}
.ctx-count {
    font-size: 0.85em;
    color: var(--text-muted);
    font-weight: normal;
}
.ctx-items {
    display: flex;
    flex-direction: column;
}
.ctx-item {
    padding: 6px 8px;
    margin: 2px 0;
    border-left: 3px solid transparent;
    cursor: pointer;
    transition: background-color 0.2s;
    display: block;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}
.ctx-item:hover {
    background-color: var(--bg-hover);
}
.ctx-item.active-context,
.ctx-item.active-context:hover {
    background-color: var(--bg-highlight);
    border-left-color: var(--text-secondary);
}
.ctx-identifier {
    font-weight: bold;
    color: var(--text-secondary);
    margin-right: 8px;
    display: inline-block;
    width: 5ch;
    text-align: right;
}
.ctx-name {
    color: var(--text-primary);
    display: inline-block;
    vertical-align: top;
}
.ctx-kind-badge {
    font-size: 0.75em;
    padding: 2px 4px;
    border-radius: 2px;
    background: var(--card-bg);
    color: var(--text-secondary);
    margin-left: 4px;
}
.active-context {
    background-color: var(--bg-highlight);
    border-left-color: var(--text-secondary);
}
.context-detail {
    padding: 20px;
}
.context-detail h2 {
    margin-top: 0;
}
.ctx-attacks {
    list-style: none;
    padding: 0;
    margin: 0;
}
.ctx-attack-item {
    padding: 6px 10px;
    margin: 2px 0;
    cursor: pointer;
    transition: background-color 0.2s;
    border-left: 3px solid transparent;
}
.ctx-attack-item:hover {
    background: var(--bg-hover);
}
.ctx-attack-item.active-attack {
    background-color: var(--bg-highlight);
    border-left-color: var(--text-secondary);
}
.ctx-attack-id {
    font-weight: bold;
    color: var(--text-secondary);
}

/* === Graph View === */
#tab-graph {
    flex-direction: row;
}
#graph-container {
    display: flex;
    width: 100%;
    height: 100%;
}
#graph-sidePanel {
    width: 280px;
    min-width: 280px;
    height: 100%;
    background: var(--bg-secondary);
    border-right: 1px solid var(--border-subtle);
    box-shadow: 2px 0 10px rgba(0,0,0,0.1);
    z-index: 100;
    font-size: 13px;
    display: flex;
    flex-direction: column;
    box-sizing: border-box;
}
#graph-sidePanel h3 {
    margin: 0;
    padding: 15px;
    background: #053844;
    color: white;
    font-size: 16px;
}
#graph-sidePanel .section {
    padding: 15px;
    border-bottom: 1px solid var(--border-subtle);
    flex: none;
    overflow-y: visible;
}
#graph-legendPanel {
    margin-top: auto;
    background: var(--bg-secondary);
    border-top: 1px solid var(--border-subtle);
}
#graph-legendPanel summary {
    padding: 12px 15px;
    cursor: pointer;
    user-select: none;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--text-secondary);
    list-style: none;
}
#graph-legendPanel summary::-webkit-details-marker {
    display: none;
}
#graph-legendPanel summary::after {
    content: '▾';
    float: right;
    font-size: 12px;
    color: var(--text-muted);
}
#graph-legendPanel:not([open]) summary::after {
    content: '▸';
}
#graph-legendPanel summary:hover {
    background: var(--bg-tertiary);
}
#graph-legendPanel .legend-section {
    padding: 0 15px 15px 15px;
}
.graph-legend-block + .graph-legend-block {
    margin-top: 12px;
}
.graph-legend-title {
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--text-secondary);
    margin-bottom: 8px;
}
.graph-legend-list {
    display: grid;
    grid-template-columns: 1fr;
    gap: 6px;
}
.graph-legend-item {
    display: flex;
    align-items: center;
    gap: 8px;
    min-width: 0;
    color: var(--text-primary);
}
.graph-legend-label {
    font-size: 12px;
    line-height: 1.35;
}
.graph-legend-node-swatch {
    display: inline-block;
    width: 12px;
    height: 12px;
    flex: 0 0 auto;
}
.graph-legend-node-swatch.node-property {
    background: #4CAF50;
    transform: rotate(45deg);
    border-radius: 2px;
}
.graph-legend-node-swatch.node-attack {
    background: #F44336;
    clip-path: polygon(50% 0%, 0% 100%, 100% 100%);
}
.graph-legend-node-swatch.node-pattern {
    background: #FF9800;
    clip-path: polygon(0% 0%, 100% 0%, 50% 100%);
}
.graph-legend-node-swatch.node-mitigation {
    background: #2196F3;
    border-radius: 2px;
}
.graph-legend-node-swatch.node-context {
    background: #9C27B0;
    border-radius: 50%;
}
.graph-legend-status-swatch {
    width: 0;
    height: 16px;
    border-left: 3px solid #28a745;
    flex: 0 0 auto;
    border-radius: 1px;
}
.graph-legend-status-swatch.inherited { border-left-color: var(--text-muted); }
.graph-legend-status-swatch.oos { border-left-color: #ffc107; }
[data-theme="dark"] .graph-legend-status-swatch.oos { border-left-color: #f0d060; }
#graph-searchInput {
    width: 100%;
    padding: 8px 10px;
    border: 1px solid var(--border-input);
    border-radius: 4px;
    font-size: 13px;
    box-sizing: border-box;
    background: var(--card-bg);
    color: var(--text-primary);
}
#graph-searchInput:focus {
    outline: none;
    border-color: #0d5460;
    box-shadow: 0 0 0 2px rgba(13,84,96,0.25);
}
#graph-searchResults {
    max-height: 200px;
    overflow-y: auto;
    margin-top: 8px;
    border: 1px solid var(--border-subtle);
    border-radius: 4px;
    background: var(--card-bg);
    display: none;
}
#graph-searchResults.active {
    display: block;
}
.search-item {
    padding: 8px 10px;
    cursor: pointer;
    border-bottom: 1px solid var(--search-item-border);
    color: var(--text-primary);
}
.search-item:last-child {
    border-bottom: none;
}
.search-item:hover {
    background: var(--search-hover);
}
.search-item .node-type {
    font-size: 10px;
    color: var(--text-muted);
    text-transform: uppercase;
}
#graph-sidePanel label {
    display: flex;
    align-items: center;
    gap: 8px;
    cursor: pointer;
    color: var(--text-secondary);
}
#graph-sidePanel input[type="checkbox"] {
    width: 16px;
    height: 16px;
}
#graph-focusStatus {
    padding: 15px;
    background: var(--bg-tertiary);
    color: var(--text-secondary);
}
#graph-focusStatus.active {
    background: #d4edda;
    color: #155724;
}
[data-theme="dark"] #graph-focusStatus.active {
    background: #1a4a30;
    color: #a3d9a5;
}
#graph-nodeDetails {
    flex: 1;
    padding: 15px;
    overflow-y: auto;
    border-top: 1px solid var(--border-subtle);
    display: none;
}
#graph-nodeDetails.active {
    display: block;
}
#graph-nodeDetails .node-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 8px;
}
#graph-nodeDetails .node-title {
    font-weight: bold;
    font-size: 14px;
    margin-bottom: 5px;
    color: var(--text-primary);
    flex: 1;
}
#graph-copyLinkBtn {
    background: var(--bg-tertiary);
    border: none;
    border-radius: 4px;
    padding: 4px 8px;
    cursor: pointer;
    font-size: 14px;
    transition: background 0.2s;
    color: var(--text-primary);
}
#graph-copyLinkBtn:hover {
    background: var(--border-subtle);
}
#graph-copyLinkBtn.copied {
    background: #28a745;
    color: white;
}
#graph-nodeDetails .node-type-badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 3px;
    font-size: 10px;
    text-transform: uppercase;
    margin-bottom: 10px;
    color: white;
}
#graph-nodeDetails .node-type-badge.property { background: #4CAF50; }
#graph-nodeDetails .node-type-badge.attack { background: #F44336; }
#graph-nodeDetails .node-type-badge.pattern { background: #FF9800; }
#graph-nodeDetails .node-type-badge.mitigation { background: #2196F3; }
#graph-nodeDetails .node-type-badge.context { background: #9C27B0; }
#graph-nodeDetails .node-description {
    font-size: 12px;
    line-height: 1.5;
    color: var(--text-secondary);
}
#graph-nodeDetails .node-pattern {
    margin-top: 10px;
    padding: 8px 10px;
    border-left: 3px solid #607D8B;
    background: var(--bg-secondary);
    border-radius: 4px;
    font-size: 12px;
    line-height: 1.45;
    color: var(--text-secondary);
    display: none;
}
#graph-nodeDetails .node-pattern.active {
    display: block;
}
#graph-nodeDetails .node-id {
    font-family: monospace;
    font-size: 10px;
    color: var(--text-muted);
    background: var(--badge-bg);
    padding: 2px 6px;
    border-radius: 3px;
    display: inline-block;
    margin-bottom: 8px;
}
#graph-nodeMitigations {
    margin-top: 12px;
    display: none;
}
#graph-nodeMitigations.active {
    display: block;
}
#graph-nodeMitigations .mitigations-title {
    font-weight: bold;
    font-size: 12px;
    color: var(--text-secondary);
    margin-bottom: 6px;
    border-top: 1px solid var(--border-subtle);
    padding-top: 10px;
}
#graph-nodeMitigations ul {
    margin: 0;
    padding-left: 0;
    list-style: none;
    font-size: 11px;
    line-height: 1.5;
}
#graph-nodeMitigations li {
    color: var(--text-secondary);
    margin-bottom: 8px;
    padding-left: 4px;
    border-left: 2px solid #28a745;
    position: relative;
}
#graph-nodeMitigations li.inherited {
    color: var(--text-muted);
    border-left-color: var(--text-muted);
}
#graph-nodeMitigations li.oos {
    color: #856404;
    border-left-color: #ffc107;
}
[data-theme="dark"] #graph-nodeMitigations li.oos {
    color: #f0d060;
}
#graph-nodeMitigations .attack-line {
    font-weight: 500;
    cursor: default;
}
#graph-nodeMitigations .attack-line .tm-attack-ref,
#graph-nodeMitigations .attack-line .tm-graph-line-ref {
    white-space: normal;
    overflow-wrap: anywhere;
    line-height: 1.5;
}
.hint {
    color: var(--text-muted);
    font-size: 11px;
    margin-top: 8px;
}
#graph-canvas {
    flex: 1;
    height: 100%;
    position: relative;
    background: var(--graph-canvas-bg);
}
#graph-loading {
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 16px;
    color: var(--text-muted);
    z-index: 10;
    background: var(--graph-canvas-bg);
}
#graph-network {
    width: 100%;
    height: 100%;
}
#graph-customTooltip {
    position: fixed;
    background: var(--tooltip-bg);
    color: var(--tooltip-text);
    padding: 10px 14px;
    border-radius: 6px;
    border: 1px solid var(--tooltip-border);
    font-size: 13px;
    font-family: Arial, sans-serif;
    line-height: 1.5;
    max-width: 400px;
    z-index: 2000;
    box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    pointer-events: none;
    display: block;
    visibility: hidden;
    opacity: 0;
    left: -9999px;
    top: -9999px;
    contain: layout style paint;
}
#graph-customTooltip.visible {
    visibility: visible;
    opacity: 1;
}
#graph-customTooltip b {
    color: var(--tooltip-title);
}
#graph-customTooltip a,
#graph-customTooltip .tm-ref,
#graph-customTooltip .tm-attack-ref {
    color: var(--tooltip-link);
    text-decoration: underline;
}
#graph-customTooltip a:visited,
#graph-customTooltip .tm-ref:visited,
#graph-customTooltip .tm-attack-ref:visited {
    color: var(--tooltip-link);
}
#graph-customTooltip a:hover,
#graph-customTooltip .tm-ref:hover,
#graph-customTooltip .tm-attack-ref:hover,
#graph-customTooltip a:focus-visible,
#graph-customTooltip .tm-ref:focus-visible,
#graph-customTooltip .tm-attack-ref:focus-visible {
    color: var(--tooltip-link-hover);
}
#graph-physicsConfig {
    flex: none;
    margin: 0;
    background: var(--bg-secondary);
    border-top: 1px solid var(--border-subtle);
    border-left: none;
    border-right: none;
    border-bottom: none;
    border-radius: 0;
    font-family: Arial, sans-serif;
    font-size: 12px;
    box-shadow: none;
    max-width: none;
    width: 100%;
    display: none;
}
#graph-physicsConfig.visible {
    display: block;
}
#graph-physicsConfig summary {
    padding: 12px 15px;
    cursor: pointer;
    user-select: none;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--text-secondary);
    background: transparent;
    list-style: none;
}
#graph-physicsConfig summary::-webkit-details-marker {
    display: none;
}
#graph-physicsConfig summary::after {
    content: '▾';
    float: right;
    font-size: 12px;
    color: var(--text-muted);
}
#graph-physicsConfig:not([open]) summary::after {
    content: '▸';
}
#graph-physicsConfig summary:hover {
    background: var(--bg-tertiary);
}
#graph-physicsConfig .config-content {
    padding: 0 15px 15px 15px;
}
#graph-physicsConfig .config-row {
    margin-bottom: 10px;
}
#graph-physicsConfig .config-row:last-child {
    margin-bottom: 0;
}
#graph-physicsConfig label {
    display: block;
    margin-bottom: 4px;
    color: var(--text-secondary);
}
#graph-physicsConfig label span {
    float: right;
    font-family: monospace;
    color: var(--text-muted);
}
#graph-physicsConfig input[type="range"] {
    width: 100%;
    margin: 0;
}
#graph-physicsConfig .config-buttons {
    margin-top: 12px;
    padding-top: 10px;
    border-top: 1px solid var(--border-subtle);
    display: flex;
    gap: 8px;
}
#graph-physicsConfig button {
    flex: 1;
    padding: 6px 10px;
    border: 1px solid var(--border-input);
    border-radius: 4px;
    background: var(--card-bg);
    color: var(--text-primary);
    cursor: pointer;
    font-size: 11px;
}
#graph-physicsConfig button:hover {
    background: var(--bg-tertiary);
}
#graph-physicsConfig button.primary {
    background: #0d5460;
    border-color: #0d5460;
    color: white;
}
#graph-physicsConfig button.primary:hover {
    background: #053844;
}

/* === Context Popups === */
.context-popup {
    display: none;
    position: fixed;
    z-index: 2000;
    left: 0;
    top: 0;
    width: 100%;
    height: 100%;
    background-color: rgba(0, 0, 0, 0.4);
    contain: layout style paint;
}
.context-popup.show {
    display: flex;
    align-items: center;
    justify-content: center;
}
.context-popup-content {
    background-color: var(--card-bg);
    padding: 20px;
    border: 1px solid var(--border-color);
    border-radius: 8px;
    width: 90%;
    max-width: 500px;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.2);
    max-height: 80vh;
    overflow-y: auto;
    contain: layout style paint;
}
.context-popup-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 15px;
}
.context-popup-header h2 {
    margin: 0;
    font-size: 18px;
}
.context-popup-close-group {
    display: flex;
    align-items: center;
    gap: 6px;
}
.context-popup-nav,
.context-popup-close {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 30px;
    height: 30px;
    padding: 0;
    background: var(--bg-secondary);
    border: 1px solid var(--border-subtle);
    border-radius: 4px;
    cursor: pointer;
    color: var(--text-secondary);
    line-height: 1;
    box-sizing: border-box;
    transition: color 0.15s ease, background-color 0.15s ease, border-color 0.15s ease;
}
.context-popup-nav {
    font-size: 15px;
}
.context-popup-nav:hover,
.context-popup-close:hover {
    background: var(--bg-tertiary);
    border-color: var(--accent);
    color: var(--accent);
}
.context-popup-nav:focus-visible,
.context-popup-close:focus-visible {
    outline: 1px solid var(--accent);
    outline-offset: 1px;
    border-radius: 4px;
}
.context-popup-close {
    font-size: 20px;
    font-weight: 400;
}
.context-popup-identifier {
    font-family: monospace;
    font-weight: bold;
    color: var(--text-primary);
    font-size: 14px;
    margin-bottom: 10px;
}
.context-popup-kind {
    display: inline-block;
    padding: 4px 8px;
    background: var(--bg-tertiary);
    border-radius: 4px;
    font-size: 12px;
    color: var(--text-secondary);
    margin-bottom: 15px;
}
.context-popup-description {
    margin-top: 12px;
    line-height: 1.5;
    color: var(--text-primary);
}
.attack-line-details-list {
    list-style: none;
    margin: 8px 0 0 0;
    padding: 0;
}
.attack-line-details-item {
    margin: 0 0 10px 0;
    padding: 8px 10px;
    border-left: 3px solid var(--border-subtle);
    background: var(--bg-secondary);
    border-radius: 4px;
}
.attack-line-details-item:last-child {
    margin-bottom: 0;
}
.attack-line-details-title {
    font-weight: 600;
    margin: 0;
}
.attack-line-details-kind {
    margin: 3px 0 0 0;
    font-size: 11px;
    color: var(--text-muted);
}
.attack-line-details-description {
    margin: 6px 0 0 0;
    line-height: 1.45;
    color: var(--text-primary);
}
.attack-line-details-head {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 8px;
}
.attack-line-details-actions {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    flex-shrink: 0;
}
.attack-line-action {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 24px;
    height: 24px;
    border: 1px solid var(--border-subtle);
    border-radius: 4px;
    background: var(--card-bg);
    color: var(--text-secondary);
    cursor: pointer;
    font-size: 12px;
    line-height: 1;
}
.attack-line-action:hover {
    border-color: var(--accent);
    color: var(--accent);
    background: var(--bg-tertiary);
}
.citation-popup code {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 0.9em;
}
.tm-inline-math {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 0.92em;
    background: var(--bg-tertiary);
    padding: 1px 4px;
    border-radius: 3px;
}
"""

NAV_HTML = """
<header>
  <div id="title-bar">
    <span class="title">VoteSecure Threat Model</span>
    <span class="title-right">
      <span class="version">Version {version} &mdash; {date}</span>
                        <button id="layout-reset" title="Reset pane sizes to defaults" aria-label="Reset pane sizes">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">
                                <path d="M4 9V4h5"/>
                                <path d="M15 4h5v5"/>
                                <path d="M20 15v5h-5"/>
                                <path d="M9 20H4v-5"/>
                                <circle cx="12" cy="12" r="1.8"/>
                            </svg>
                        </button>
      <button id="theme-toggle" title="Toggle dark mode">&#x263E;</button>
    </span>
  </div>
  <nav>
    <a href="#" class="tab-link active" data-tab="contexts">Contexts</a>
    <a href="#" class="tab-link" data-tab="properties">Security Objectives</a>
    <a href="#" class="tab-link" data-tab="patterns">Attack Patterns</a>
    <a href="#" class="tab-link" data-tab="attacks">Attacks</a>
    <a href="#" class="tab-link" data-tab="mitigations">Mitigations</a>
    <a href="#" class="tab-link" data-tab="graph">Graph</a>
  </nav>
</header>
"""

CONTEXTS_HTML = """
<div id="tab-contexts" class="tab-content active">
    <div class="split-view resizable-split" data-split-key="contexts">
    <div class="left-panel">
      <h2>Contexts</h2>
      <div id="ctx-list"></div>
    </div>
        <div class="pane-divider pane-divider-vertical" data-resize="vertical" aria-hidden="true"></div>
        <div class="right-panel resizable-right">
      <div id="ctx-details">
                                <div class="ctx-summary-section">
                    <h3>Context Details</h3>
                    <p>Select a context to view details</p>
                </div>
                                <div class="section ctx-attacks-section">
                    <h3>Attacks in this Context</h3>
                    <div id="ctx-attacks">Select a context to see attacks</div>
                </div>
                                <div class="pane-divider pane-divider-horizontal ctx-details-divider" data-resize="contexts-lower" aria-hidden="true"></div>
                                <div class="section ctx-mitigations-section">
                    <h3>Mitigations</h3>
                    <div id="ctx-mitigations">Select an attack to see mitigations</div>
                </div>
      </div>
    </div>
  </div>
</div>
"""

PROPERTIES_HTML = """
<div id="tab-properties" class="tab-content">
    <div class="split-view resizable-split" data-split-key="properties">
    <div class="left-panel">
      <h2>Security Objectives</h2>
      <div class="tree"><ul id="prop-tree"></ul></div>
    </div>
        <div class="pane-divider pane-divider-vertical" data-resize="vertical" aria-hidden="true"></div>
        <div class="right-panel resizable-right">
      <div class="section">
        <h2>Attacks</h2>
        <div id="prop-attacks">Select a security objective to see attacks</div>
      </div>
            <div class="pane-divider pane-divider-horizontal" data-resize="horizontal" aria-hidden="true"></div>
      <div class="section">
        <h2>Mitigations</h2>
        <div id="prop-mitigations">Select an attack to see mitigations</div>
      </div>
    </div>
  </div>
</div>
"""

ATTACKS_HTML = """
<div id="tab-attacks" class="tab-content">
    <div class="split-view resizable-split" data-split-key="attacks">
    <div class="left-panel">
      <h2>Attacks</h2>
      <div class="tree"><ul id="atk-tree"></ul></div>
    </div>
        <div class="pane-divider pane-divider-vertical" data-resize="vertical" aria-hidden="true"></div>
        <div class="right-panel resizable-right">
      <div class="section">
                <h2 id="atk-upper-heading">Security Objectives</h2>
                <div id="atk-properties"></div>
      </div>
            <div class="pane-divider pane-divider-horizontal" data-resize="horizontal" aria-hidden="true"></div>
      <div class="section">
        <h2>Mitigations</h2>
        <div id="atk-mitigations"></div>
      </div>
    </div>
  </div>
</div>
"""

PATTERNS_HTML = """
<div id="tab-patterns" class="tab-content">
    <div class="split-view resizable-split" data-split-key="patterns">
        <div class="left-panel">
            <h2>Attack Patterns</h2>
            <div class="tree"><ul id="pat-tree"></ul></div>
        </div>
        <div class="pane-divider pane-divider-vertical" data-resize="vertical" aria-hidden="true"></div>
        <div class="right-panel resizable-right">
            <div class="section">
                <h2 id="pat-upper-heading">Instantiations</h2>
                <div id="pat-instances">Select an attack pattern to see concrete instantiations</div>
            </div>
            <div class="pane-divider pane-divider-horizontal" data-resize="horizontal" aria-hidden="true"></div>
            <div class="section">
                <h2>Mitigations</h2>
                <div id="pat-mitigations">Select an instantiation to see mitigations</div>
            </div>
        </div>
    </div>
</div>
"""

MITIGATIONS_HTML = """
<div id="tab-mitigations" class="tab-content">
    <div class="split-view resizable-split" data-split-key="mitigations">
    <div class="left-panel">
      <h2>Mitigations</h2>
      <div class="tree"><ul id="mit-tree"></ul></div>
    </div>
        <div class="pane-divider pane-divider-vertical" data-resize="vertical" aria-hidden="true"></div>
        <div class="right-panel resizable-right">
      <div class="section">
                <h2>Affected Attacks / Patterns</h2>
        <div id="mit-attacks"></div>
      </div>
            <div class="pane-divider pane-divider-horizontal" data-resize="horizontal" aria-hidden="true"></div>
      <div class="section">
        <h2>Security Objectives</h2>
        <div class="tree"><ul id="mit-properties"></ul></div>
      </div>
    </div>
  </div>
</div>
"""

GRAPH_HTML = """
<div id="tab-graph" class="tab-content">
  <div id="graph-container">
    <div id="graph-sidePanel">
      <h3>Threat Model Explorer</h3>
      <div class="section">
        <div class="section-title" style="font-weight:bold;margin-bottom:10px;color:#495057;">Search Nodes</div>
        <input type="text" id="graph-searchInput" placeholder="Type to search...">
        <div id="graph-searchResults"></div>
      </div>
      <div id="graph-focusStatus">Shift+Click to toggle hide mode</div>
      <div id="graph-nodeDetails">
        <div class="node-header">
          <div class="node-title" id="graph-nodeTitle"></div>
          <button id="graph-copyLinkBtn" title="Copy link to this node">&#x1F517;</button>
        </div>
        <div class="node-id" id="graph-nodeId"></div>
        <span class="node-type-badge" id="graph-nodeTypeBadge"></span>
        <div class="node-description" id="graph-nodeDescription"></div>
                <div class="node-pattern" id="graph-nodePattern"></div>
        <div id="graph-nodeMitigations">
          <div class="mitigations-title">Attack Lines</div>
          <ul id="graph-mitigationsList"></ul>
        </div>
      </div>
            <details id="graph-legendPanel" open>
                <summary>Legend</summary>
                <div class="legend-section">
                    <div class="graph-legend-block">
                        <div class="graph-legend-title">Node types</div>
                        <div class="graph-legend-list">
                            <div class="graph-legend-item"><span class="graph-legend-node-swatch node-property"></span><span class="graph-legend-label">Security objective</span></div>
                            <div class="graph-legend-item"><span class="graph-legend-node-swatch node-attack"></span><span class="graph-legend-label">Attack</span></div>
                            <div class="graph-legend-item"><span class="graph-legend-node-swatch node-pattern"></span><span class="graph-legend-label">Attack pattern</span></div>
                            <div class="graph-legend-item"><span class="graph-legend-node-swatch node-mitigation"></span><span class="graph-legend-label">Mitigation</span></div>
                            <div class="graph-legend-item"><span class="graph-legend-node-swatch node-context"></span><span class="graph-legend-label">Context</span></div>
                        </div>
                    </div>
                    <div class="graph-legend-block">
                        <div class="graph-legend-title">Attack-line status</div>
                        <div class="graph-legend-list">
                            <div class="graph-legend-item"><span class="graph-legend-status-swatch"></span><span class="graph-legend-label">Direct mitigation</span></div>
                            <div class="graph-legend-item"><span class="graph-legend-status-swatch inherited"></span><span class="graph-legend-label">Inherited mitigation</span></div>
                            <div class="graph-legend-item"><span class="graph-legend-status-swatch oos"></span><span class="graph-legend-label">Out of scope</span></div>
                        </div>
                    </div>
                </div>
            </details>
            <details id="graph-physicsConfig">
                <summary>Physics settings</summary>
                <div class="config-content">
                    <div class="config-row">
                        <label>Repulsion <span id="graph-gravityValue">-8000</span></label>
                        <input type="range" id="graph-gravitySlider" min="-50000" max="-1000" step="500" value="-8000">
                    </div>
                    <div class="config-row">
                        <label>Central Gravity <span id="graph-centralGravityValue">0.5</span></label>
                        <input type="range" id="graph-centralGravitySlider" min="0" max="5" step="0.1" value="0.5">
                    </div>
                    <div class="config-row">
                        <label>Spring Length <span id="graph-springLengthValue">300</span></label>
                        <input type="range" id="graph-springLengthSlider" min="50" max="1000" step="25" value="300">
                    </div>
                    <div class="config-row">
                        <label>Spring Strength <span id="graph-springStrengthValue">0.03</span></label>
                        <input type="range" id="graph-springStrengthSlider" min="0.01" max="0.2" step="0.01" value="0.03">
                    </div>
                    <div class="config-row">
                        <label>Damping <span id="graph-dampingValue">0.09</span></label>
                        <input type="range" id="graph-dampingSlider" min="0.01" max="0.5" step="0.01" value="0.09">
                    </div>
                    <div class="config-buttons">
                        <button id="graph-resetPhysicsBtn">Reset</button>
                        <button id="graph-togglePhysicsBtn" class="primary">Freeze</button>
                    </div>
                </div>
            </details>
    </div>
    <div id="graph-canvas">
      <div id="graph-loading">Initializing graph&hellip;</div>
      <div id="graph-network"></div>
    </div>
  </div>
</div>
<div id="graph-customTooltip"></div>
"""

# --- JavaScript for tab switching ---
TAB_JS = """
function tmRenderInheritedSource(mit) {
    if (!mit || !mit.transitive) return '';

    var sourceType = mit.source_attack_is_abstract ? 'attack pattern' : 'attack';
    var sourceLabel = mit.source_attack_label || ('related ' + sourceType);
    var sourceLine = mit.source_attack_line || sourceLabel;
    var relation = mit.source_relation || 'ancestor';
    var prefix = relation === 'descendant'
        ? 'Applies via attack line'
        : ('Inherited from ' + sourceType);

    if (mit.source_attack_id !== null && mit.source_attack_id !== undefined) {
        var descendantSegments = relation === 'descendant' ? tmResolveTreeSourceLineSegments(mit) : [];
        if (relation === 'descendant' && descendantSegments.length > 0) {
            var popupId = tmRegisterCustomLinePopupSpec(mit);
            if (popupId) {
                return '<p><em>' + prefix + ' <a href="#" class="tm-custom-line-ref" data-custom-line-popup="' +
                    tmEscapeHtml(popupId) + '">' + tmEscapeHtml(sourceLine) + '</a></em></p>';
            }
        }
        var linkText = relation === 'descendant' ? sourceLine : sourceLabel;
        return '<p><em>' + prefix + ' <a href="#" class="tm-attack-ref" data-attack-id="' +
            mit.source_attack_id + '" data-attack-abstract="' +
            (mit.source_attack_is_abstract ? 'true' : 'false') + '">' + linkText + '</a></em></p>';
    }

    return '<p><em>' + (relation === 'descendant'
        ? 'Applies via attack line '
        : 'Inherited from related ') + sourceType + '</em></p>';
}

function tmRenderMitigationRationale(mit, label) {
    if (!mit || !mit.rationale || mit.rationale === 'None') return '';
    return '<p><strong>' + label + '</strong>: ' + mit.rationale + '</p>';
}

function tmStableHash(text) {
    var s = String(text || '');
    var h = 0;
    for (var i = 0; i < s.length; i++) {
        h = ((h << 5) - h) + s.charCodeAt(i);
        h |= 0;
    }
    return String(Math.abs(h));
}

function tmResolveTreeSourceLineSegments(mit) {
    if (!mit) return [];
    if (mit.source_attack_line_segments && mit.source_attack_line_segments.length > 0) {
        return mit.source_attack_line_segments;
    }
    var key = mit.source_attack_line_segment_key;
    if (!key || !TREE_DATA || !TREE_DATA.sourceAttackLineSegments) return [];
    return TREE_DATA.sourceAttackLineSegments[key] || [];
}

function tmRegisterCustomLinePopupSpec(mit) {
    if (!mit) return null;
    var segments = tmResolveTreeSourceLineSegments(mit);
    if (!segments || segments.length === 0) return null;

    var mitigationToken = mit.id || mit.auto_identifier || mit.name || 'mit';
    var sourceToken = mit.source_attack_id || 'src';
    var lineToken = tmStableHash(mit.source_attack_line || '');
    var popupId = 'src-line-' + sourceToken + '-' + mitigationToken + '-' + lineToken;

    window.tmCustomLinePopupSpecs = window.tmCustomLinePopupSpecs || {};
    if (!window.tmCustomLinePopupSpecs[popupId]) {
        window.tmCustomLinePopupSpecs[popupId] = {
            popupId: popupId,
            line: mit.source_attack_line || '',
            segments: segments,
            rationale_html: '',
            titleLabel: 'Attack line',
            closeHandler: 'closeGraphLinePopup'
        };
    }
    return popupId;
}

function tmEscapeHtml(text) {
    var div = document.createElement('div');
    div.textContent = text == null ? '' : text;
    return div.innerHTML;
}

function tmNormalizeLatexPunctuation(text) {
    if (text == null) return '';
    return String(text).replace(/---/g, '—').replace(/~/g, ' ');
}

function tmResolveLineSegments(lineData) {
    if (!lineData) return [];
    if (lineData.segments && lineData.segments.length > 0) return lineData.segments;
    if (lineData.segment_key && GRAPH_DATA && GRAPH_DATA.attackLineSegments) {
        return GRAPH_DATA.attackLineSegments[lineData.segment_key] || [];
    }
    return [];
}

function tmRenderGraphAttackLine(mit) {
    if (!mit) return '';
    var lineText = '';
    var segments = tmResolveLineSegments(mit);
    if (segments.length > 0) {
        lineText = segments
            .map(function(segment) {
                return tmEscapeHtml(tmNormalizeLatexPunctuation(segment.label || ''));
            })
            .filter(function(label) { return label.length > 0; })
            .join(' → ');
    }
    if (!lineText) {
        lineText = tmEscapeHtml(tmNormalizeLatexPunctuation(mit.line || ''));
    }
    if (!mit.popup_id) return lineText;
    return '<a href="#" class="tm-graph-line-ref" data-graph-line-popup="' +
        tmEscapeHtml(mit.popup_id) + '">' + lineText + '</a>';
}

function tmWriteUrl(selPath) {
    var p = new URLSearchParams(window.location.search);
    if (selPath && selPath.length > 0) {
        p.set('sel', selPath.join(','));
    } else {
        p.delete('sel');
    }
    window.history.replaceState(null, '', window.location.pathname + '?' + p.toString());
}

var tmPreserveSelectionOnNextTabSwitch = false;

function tmFindInTree(tree, id) {
    for (var i = 0; i < tree.length; i++) {
        if (tree[i].id === id) return tree[i];
        if (tree[i].children && tree[i].children.length > 0) {
            var found = tmFindInTree(tree[i].children, id);
            if (found) return found;
        }
    }
    return null;
}

function tmGetAttackIndex() {
    if (window.tmAttackIndex) return window.tmAttackIndex;

    var idx = {};
    function addAttack(node) {
        if (!node || !node.id) return;
        idx[node.id] = {
            id: node.id,
            auto_identifier: node.auto_identifier || '',
            identifier: node.identifier || '',
            description: node.description || '',
            is_abstract: !!node.is_abstract
        };
        (node.children || []).forEach(addAttack);
    }

    (TREE_DATA.attackTree || []).forEach(addAttack);
    (TREE_DATA.abstractAttackList || []).forEach(addAttack);

    window.tmAttackIndex = idx;
    return idx;
}

function tmGetPropertyIndex() {
    if (window.tmPropertyIndex) return window.tmPropertyIndex;

    var idx = {};
    function addProperty(node, parentId) {
        if (!node || !node.id) return;
        idx[node.id] = {
            id: node.id,
            auto_identifier: node.auto_identifier || '',
            name: node.name || '',
            description: node.description || '',
            kind: node.kind || '',
            parent_id: parentId || null,
            child_ids: (node.children || []).map(function(child) { return child.id; })
        };
        (node.children || []).forEach(function(child) { addProperty(child, node.id); });
    }

    (TREE_DATA.propertyTree || []).forEach(function(root) { addProperty(root, null); });

    window.tmPropertyIndex = idx;
    return idx;
}

function tmGetPropertyAttacks(propertyId) {
    var raw = TREE_DATA.propertyAttacks[propertyId] || [];
    if (raw.length === 0) return raw;
    if (typeof raw[0] === 'object') return raw;

    var attackIndex = tmGetAttackIndex();
    return raw.map(function(attackId) { return attackIndex[attackId]; }).filter(Boolean);
}

function tmBuildPropertyTreeFromIds(propertyIds) {
    if (!propertyIds || propertyIds.length === 0) return [];
    if (typeof propertyIds[0] === 'object') return propertyIds;

    var propIndex = tmGetPropertyIndex();
    var include = new Set(propertyIds);

    function buildNode(propId) {
        var base = propIndex[propId];
        if (!base) return null;
        var children = (base.child_ids || [])
            .filter(function(childId) { return include.has(childId); })
            .map(buildNode)
            .filter(Boolean);
        return {
            id: base.id,
            auto_identifier: base.auto_identifier,
            name: base.name,
            description: base.description,
            kind: base.kind,
            children: children,
        };
    }

    var roots = propertyIds.filter(function(propId) {
        var p = propIndex[propId];
        return p && (!p.parent_id || !include.has(p.parent_id));
    });

    return roots.map(buildNode).filter(Boolean);
}

function tmGetAttackPropertiesTree(attackId) {
    var raw = TREE_DATA.attackProperties[attackId] || [];
    return tmBuildPropertyTreeFromIds(raw);
}

function tmRestoreTabSelection(tab) {
    var p = new URLSearchParams(window.location.search);
    var sel = p.get('sel');
    if (!sel) return;
    var ids = sel.split(',');

    if (tab === 'contexts') {
        var ctx = ids[0];
        if (!ctx) return;
        ctxView_selectContext(ctx);
        if (ids[1]) {
            var atkEl = document.querySelector('#ctx-attacks [data-id="' + ids[1] + '"]');
            if (atkEl) ctxView_selectAttack(atkEl, ctx);
        }
    } else if (tab === 'properties') {
        var propId = ids[0];
        if (!propId) return;
        var li = document.querySelector('#prop-tree [data-id="' + propId + '"]');
        if (!li) return;
        propView_loadAttacks(propId);
        document.getElementById('prop-mitigations').innerHTML = 'Select an attack to search for mitigations';
        propView_highlightProperty(li);
        if (li.scrollIntoView) li.scrollIntoView({ block: 'nearest' });
        if (ids[1]) {
            var atkEl = document.querySelector('#prop-attacks [data-id="' + ids[1] + '"]');
            if (atkEl) propView_highlightAttack(atkEl);
        }
    } else if (tab === 'attacks') {
        var atkId = ids[0];
        if (!atkId) return;
        var li = document.querySelector('#atk-tree [data-id="' + atkId + '"]');
        if (!li) return;
        var atkObj = tmFindInTree(TREE_DATA.attackTree, atkId);
        if (!atkObj) return;
        atkView_loadMitigations(atkObj);
        atkView_loadProperties(atkObj);
        atkView_highlightAttack(li);
        if (li.scrollIntoView) li.scrollIntoView({ block: 'nearest' });
    } else if (tab === 'patterns') {
        var patId = ids[0];
        if (!patId) return;
        var li = document.querySelector('#pat-tree [data-id="' + patId + '"]');
        if (!li) return;
        var patObj = tmFindInTree(TREE_DATA.abstractAttackTree, patId);
        if (!patObj) return;
        patView_loadInstances(patObj);
        patView_highlightPattern(li);
        if (li.scrollIntoView) li.scrollIntoView({ block: 'nearest' });
        if (ids[1]) {
            var instEl = document.querySelector('#pat-instances [data-id="' + ids[1] + '"]');
            if (instEl) patView_selectInstance(instEl);
        }
    } else if (tab === 'mitigations') {
        var mitId = ids[0];
        if (!mitId) return;
        var li = document.querySelector('#mit-tree [data-id="' + mitId + '"]');
        if (!li) return;
        mitView_loadAttacks(mitId);
        var propTree = document.getElementById('mit-properties');
        propTree.innerHTML = '';
        var ph = document.createElement('li');
        ph.textContent = 'Select an attack to see impacted security objectives';
        propTree.appendChild(ph);
        mitView_highlightMitigation(li);
        if (li.scrollIntoView) li.scrollIntoView({ block: 'nearest' });
        if (ids[1]) {
            var atkEl = document.querySelector('#mit-attacks [data-id="' + ids[1] + '"]');
            if (atkEl) mitView_highlightAttack(atkEl);
        }
    }
}

function tmCloseAllPopups() {
    document.querySelectorAll('.context-popup.show').forEach(function(popup) {
        popup.classList.remove('show');
    });
}

function tmWriteTabSelection(tab, selPath, push) {
    var p = new URLSearchParams(window.location.search);
    p.set('tab', tab);
    if (selPath && selPath.length > 0) {
        p.set('sel', selPath.join(','));
    } else {
        p.delete('sel');
    }
    var url = window.location.pathname + '?' + p.toString();
    if (push) {
        window.history.pushState(null, '', url);
    } else {
        window.history.replaceState(null, '', url);
    }
}

function tmNavigateToSelection(tab, selPath) {
    tmCloseAllPopups();
    tmWriteTabSelection(tab, selPath, true);

    var activeLink = document.querySelector('.tab-link.active');
    var activeTab = activeLink ? activeLink.dataset.tab : null;
    if (activeTab !== tab) {
        var tabLink = document.querySelector('[data-tab="' + tab + '"]');
        if (tabLink) {
            tmPreserveSelectionOnNextTabSwitch = true;
            tabLink.click();
        }
    }

    tmRestoreTabSelection(tab);
}

function tmNavigateToModelRef(kind, refId, isAbstract) {
    if (!kind || !refId) return;
    if (kind === 'context') {
        tmNavigateToSelection('contexts', [refId]);
    } else if (kind === 'property') {
        tmNavigateToSelection('properties', [refId]);
    } else if (kind === 'mitigation') {
        tmNavigateToSelection('mitigations', [refId]);
    } else if (kind === 'attack') {
        tmNavigateToSelection(isAbstract ? 'patterns' : 'attacks', [refId]);
    }
}

function tmNavigateToGraphNode(nodeRef) {
    if (!nodeRef) return;
    tmCloseAllPopups();

    var p = new URLSearchParams(window.location.search);
    p.set('tab', 'graph');
    p.set('node', nodeRef);
    p.delete('sel');
    window.history.pushState(null, '', window.location.pathname + '?' + p.toString());

    var activeLink = document.querySelector('.tab-link.active');
    var activeTab = activeLink ? activeLink.dataset.tab : null;
    if (activeTab !== 'graph') {
        var graphTabLink = document.querySelector('[data-tab="graph"]');
        if (graphTabLink) graphTabLink.click();
    } else {
        initGraphIfNeeded();
    }

    setTimeout(function() {
        if (typeof window.tmGraphNavigateToNode === 'function') {
            window.tmGraphNavigateToNode(nodeRef);
        }
    }, 0);
}

function tmInitResizableSplitPanes() {
    if (window.tmResizablePanesInitialized) return;
    window.tmResizablePanesInitialized = true;

    function pxClamp(value, min, max) {
        return Math.max(min, Math.min(max, value));
    }

    function setLeftPanelWidth(split, leftPanel, widthPx) {
        leftPanel.style.flex = '0 0 ' + widthPx + 'px';
        leftPanel.style.maxWidth = 'none';
        if (split && split.dataset && split.dataset.splitKey) {
            try {
                localStorage.setItem('tm-split-left-' + split.dataset.splitKey, String(Math.round(widthPx)));
            } catch (_) {}
        }
    }

    function setTopPanelHeight(split, topSection, heightPx) {
        topSection.style.flex = '0 0 ' + heightPx + 'px';
        if (split && split.dataset && split.dataset.splitKey) {
            try {
                localStorage.setItem('tm-split-top-' + split.dataset.splitKey, String(Math.round(heightPx)));
            } catch (_) {}
        }
    }

    document.querySelectorAll('.split-view.resizable-split').forEach(function(split) {
        var leftPanel = split.querySelector(':scope > .left-panel');
        var rightPanel = split.querySelector(':scope > .right-panel.resizable-right');
        var verticalDivider = split.querySelector(':scope > .pane-divider-vertical[data-resize="vertical"]');
        if (!leftPanel || !rightPanel || !verticalDivider) return;

        var savedLeft = null;
        if (split.dataset && split.dataset.splitKey) {
            try {
                var v = localStorage.getItem('tm-split-left-' + split.dataset.splitKey);
                if (v !== null) savedLeft = parseFloat(v);
            } catch (_) {}
        }
        if (!savedLeft || !isFinite(savedLeft)) {
            var initialWidth = split.dataset && split.dataset.splitKey === 'contexts'
                ? 320
                : (split.getBoundingClientRect().width * 0.34);
            savedLeft = initialWidth;
        }

        (function applyInitialLeftWidth() {
            var splitWidth = split.getBoundingClientRect().width;
            if (!splitWidth || splitWidth <= 0) return;
            var dividerWidth = verticalDivider.getBoundingClientRect().width || 8;
            var minLeft = 220;
            var minRight = split.dataset && split.dataset.splitKey === 'contexts' ? 380 : 320;
            var maxLeft = Math.max(minLeft, splitWidth - minRight - dividerWidth);
            setLeftPanelWidth(split, leftPanel, pxClamp(savedLeft, minLeft, maxLeft));
        })();

        verticalDivider.addEventListener('pointerdown', function(ev) {
            ev.preventDefault();
            var splitRect = split.getBoundingClientRect();
            var startX = ev.clientX;
            var startLeft = leftPanel.getBoundingClientRect().width;
            var dividerWidth = verticalDivider.getBoundingClientRect().width || 8;
            var minLeft = 220;
            var minRight = 320;

            verticalDivider.classList.add('is-dragging');
            document.body.classList.add('is-resizing');
            document.body.style.cursor = 'col-resize';
            verticalDivider.setPointerCapture(ev.pointerId);

            function onMove(moveEv) {
                var delta = moveEv.clientX - startX;
                var maxLeft = Math.max(minLeft, splitRect.width - minRight - dividerWidth);
                var next = pxClamp(startLeft + delta, minLeft, maxLeft);
                setLeftPanelWidth(split, leftPanel, next);
            }

            function onEnd(endEv) {
                verticalDivider.classList.remove('is-dragging');
                document.body.classList.remove('is-resizing');
                document.body.style.cursor = '';
                verticalDivider.releasePointerCapture(endEv.pointerId);
                verticalDivider.removeEventListener('pointermove', onMove);
                verticalDivider.removeEventListener('pointerup', onEnd);
                verticalDivider.removeEventListener('pointercancel', onEnd);
            }

            verticalDivider.addEventListener('pointermove', onMove);
            verticalDivider.addEventListener('pointerup', onEnd);
            verticalDivider.addEventListener('pointercancel', onEnd);
        });

        var horizontalDivider = rightPanel.querySelector(':scope > .pane-divider-horizontal[data-resize="horizontal"]');
        var sections = rightPanel.querySelectorAll(':scope > .section');
        if (!horizontalDivider || sections.length < 2) return;

        var topSection = sections[0];
        var bottomSection = sections[1];
        var savedTop = null;
        if (split.dataset && split.dataset.splitKey) {
            try {
                var h = localStorage.getItem('tm-split-top-' + split.dataset.splitKey);
                if (h !== null) savedTop = parseFloat(h);
            } catch (_) {}
        }
        if (!savedTop || !isFinite(savedTop)) {
            savedTop = rightPanel.getBoundingClientRect().height * 0.5;
        }

        (function applyInitialTopHeight() {
            var panelHeight = rightPanel.getBoundingClientRect().height;
            if (!panelHeight || panelHeight <= 0) return;
            var dividerHeight = horizontalDivider.getBoundingClientRect().height || 8;
            var minTop = 140;
            var minBottom = 140;
            var maxTop = Math.max(minTop, panelHeight - minBottom - dividerHeight);
            setTopPanelHeight(split, topSection, pxClamp(savedTop, minTop, maxTop));
            bottomSection.style.flex = '1 1 auto';
        })();

        horizontalDivider.addEventListener('pointerdown', function(ev) {
            ev.preventDefault();
            var panelRect = rightPanel.getBoundingClientRect();
            var startY = ev.clientY;
            var startTop = topSection.getBoundingClientRect().height;
            var dividerHeight = horizontalDivider.getBoundingClientRect().height || 8;
            var minTop = 140;
            var minBottom = 140;

            horizontalDivider.classList.add('is-dragging');
            document.body.classList.add('is-resizing');
            document.body.style.cursor = 'row-resize';
            horizontalDivider.setPointerCapture(ev.pointerId);

            function onMove(moveEv) {
                var delta = moveEv.clientY - startY;
                var maxTop = Math.max(minTop, panelRect.height - minBottom - dividerHeight);
                var next = pxClamp(startTop + delta, minTop, maxTop);
                setTopPanelHeight(split, topSection, next);
                bottomSection.style.flex = '1 1 auto';
            }

            function onEnd(endEv) {
                horizontalDivider.classList.remove('is-dragging');
                document.body.classList.remove('is-resizing');
                document.body.style.cursor = '';
                horizontalDivider.releasePointerCapture(endEv.pointerId);
                horizontalDivider.removeEventListener('pointermove', onMove);
                horizontalDivider.removeEventListener('pointerup', onEnd);
                horizontalDivider.removeEventListener('pointercancel', onEnd);
            }

            horizontalDivider.addEventListener('pointermove', onMove);
            horizontalDivider.addEventListener('pointerup', onEnd);
            horizontalDivider.addEventListener('pointercancel', onEnd);
        });
    });
}

function tmResetResizableSplitPanes() {
    document.querySelectorAll('.split-view.resizable-split').forEach(function(split) {
        var splitKey = split.dataset ? split.dataset.splitKey : null;
        if (splitKey) {
            try {
                localStorage.removeItem('tm-split-left-' + splitKey);
                localStorage.removeItem('tm-split-top-' + splitKey);
            } catch (_) {}
        }

        var leftPanel = split.querySelector(':scope > .left-panel');
        var rightPanel = split.querySelector(':scope > .right-panel.resizable-right');
        var verticalDivider = split.querySelector(':scope > .pane-divider-vertical[data-resize="vertical"]');

        if (leftPanel && verticalDivider) {
            var splitWidth = split.getBoundingClientRect().width;
            if (!splitWidth || splitWidth <= 0) return;
            var dividerWidth = verticalDivider.getBoundingClientRect().width || 8;
            var minLeft = 220;
            var minRight = splitKey === 'contexts' ? 380 : 320;
            var maxLeft = Math.max(minLeft, splitWidth - minRight - dividerWidth);
            var defaultLeft = splitKey === 'contexts' ? 320 : (splitWidth * 0.34);
            var leftWidth = Math.max(minLeft, Math.min(maxLeft, defaultLeft));
            leftPanel.style.flex = '0 0 ' + leftWidth + 'px';
            leftPanel.style.maxWidth = 'none';
        }

        if (rightPanel) {
            var horizontalDivider = rightPanel.querySelector(':scope > .pane-divider-horizontal[data-resize="horizontal"]');
            var sections = rightPanel.querySelectorAll(':scope > .section');
            if (horizontalDivider && sections.length >= 2) {
                var topSection = sections[0];
                var bottomSection = sections[1];
                var panelHeight = rightPanel.getBoundingClientRect().height;
                var dividerHeight = horizontalDivider.getBoundingClientRect().height || 8;
                var minTop = 140;
                var minBottom = 140;
                var maxTop = Math.max(minTop, panelHeight - minBottom - dividerHeight);
                var defaultTop = panelHeight * 0.5;
                var topHeight = Math.max(minTop, Math.min(maxTop, defaultTop));
                topSection.style.flex = '0 0 ' + topHeight + 'px';
                bottomSection.style.flex = '1 1 auto';
            }
        }
    });

    try {
        localStorage.removeItem('tm-split-top-contexts-lower');
    } catch (_) {}

    tmInitContextLowerPaneSplit();
}

function tmRefreshResizableSplitPanes() {
    function pxClamp(value, min, max) {
        return Math.max(min, Math.min(max, value));
    }

    document.querySelectorAll('.split-view.resizable-split').forEach(function(split) {
        var tab = split.closest('.tab-content');
        if (tab && !tab.classList.contains('active')) return;

        var splitKey = split.dataset ? split.dataset.splitKey : null;
        var leftPanel = split.querySelector(':scope > .left-panel');
        var rightPanel = split.querySelector(':scope > .right-panel.resizable-right');
        var verticalDivider = split.querySelector(':scope > .pane-divider-vertical[data-resize="vertical"]');
        if (!leftPanel || !rightPanel || !verticalDivider) return;

        var splitWidth = split.getBoundingClientRect().width;
        if (!splitWidth || splitWidth <= 0) return;
        var dividerWidth = verticalDivider.getBoundingClientRect().width || 8;
        var minLeft = 220;
        var minRight = splitKey === 'contexts' ? 380 : 320;
        var maxLeft = Math.max(minLeft, splitWidth - minRight - dividerWidth);

        var savedLeft = null;
        if (splitKey) {
            try {
                var v = localStorage.getItem('tm-split-left-' + splitKey);
                if (v !== null) savedLeft = parseFloat(v);
            } catch (_) {}
        }
        if (!savedLeft || !isFinite(savedLeft)) {
            savedLeft = splitKey === 'contexts' ? 320 : (splitWidth * 0.34);
        }
        leftPanel.style.flex = '0 0 ' + pxClamp(savedLeft, minLeft, maxLeft) + 'px';
        leftPanel.style.maxWidth = 'none';

        var horizontalDivider = rightPanel.querySelector(':scope > .pane-divider-horizontal[data-resize="horizontal"]');
        var sections = rightPanel.querySelectorAll(':scope > .section');
        if (!horizontalDivider || sections.length < 2) return;

        var panelHeight = rightPanel.getBoundingClientRect().height;
        if (!panelHeight || panelHeight <= 0) return;
        var dividerHeight = horizontalDivider.getBoundingClientRect().height || 8;
        var minTop = 140;
        var minBottom = 140;
        var maxTop = Math.max(minTop, panelHeight - minBottom - dividerHeight);

        var savedTop = null;
        if (splitKey) {
            try {
                var h = localStorage.getItem('tm-split-top-' + splitKey);
                if (h !== null) savedTop = parseFloat(h);
            } catch (_) {}
        }
        if (!savedTop || !isFinite(savedTop)) {
            savedTop = panelHeight * 0.5;
        }

        sections[0].style.flex = '0 0 ' + pxClamp(savedTop, minTop, maxTop) + 'px';
        sections[1].style.flex = '1 1 auto';
    });
}

function initTabs() {
    tmInitResizableSplitPanes();
    tmRefreshResizableSplitPanes();

    document.querySelectorAll('.tab-link').forEach(function(link) {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            var tab = this.dataset.tab;

            // Update active link
            document.querySelectorAll('.tab-link').forEach(function(l) {
                l.classList.remove('active');
            });
            this.classList.add('active');

            // Update active content
            document.querySelectorAll('.tab-content').forEach(function(c) {
                c.classList.remove('active');
            });
            document.getElementById('tab-' + tab).classList.add('active');
            tmRefreshResizableSplitPanes();

            // Update URL to reflect active tab; preserve per-tab state, including graph focus params
            var tabUrlParams = new URLSearchParams(window.location.search);
            tabUrlParams.set('tab', tab);
            if (!tmPreserveSelectionOnNextTabSwitch) {
                tabUrlParams.delete('sel');
            }
            window.history.replaceState(null, '', window.location.pathname + '?' + tabUrlParams.toString());
            tmPreserveSelectionOnNextTabSwitch = false;

            // Show/hide physics config based on tab
            var physicsConfig = document.getElementById('graph-physicsConfig');
            if (tab === 'graph') {
                physicsConfig.classList.add('visible');
                initGraphIfNeeded();
            } else {
                physicsConfig.classList.remove('visible');
            }
        });
    });

    // Initialize tree views on first tab switch
    var ctxInitialized = false, propInitialized = false, atkInitialized = false, patInitialized = false, mitInitialized = false;
    document.querySelectorAll('.tab-link').forEach(function(link) {
        link.addEventListener('click', function() {
            var tab = this.dataset.tab;
            if (tab === 'contexts' && !ctxInitialized) {
                ctxInitialized = true;
                ctxView_loadContexts();
                tmInitContextLowerPaneSplit();
                tmRestoreTabSelection('contexts');
            }
            if (tab === 'properties' && !propInitialized) {
                propInitialized = true;
                propView_loadProperties();
                tmRestoreTabSelection('properties');
            }
            if (tab === 'attacks' && !atkInitialized) {
                atkInitialized = true;
                atkView_loadAttacks();
                tmRestoreTabSelection('attacks');
            }
            if (tab === 'patterns' && !patInitialized) {
                patInitialized = true;
                patView_loadPatterns();
                tmRestoreTabSelection('patterns');
            }
            if (tab === 'mitigations' && !mitInitialized) {
                mitInitialized = true;
                mitView_loadMitigations();
                tmRestoreTabSelection('mitigations');
            }
        });
    });
}
"""

# --- JavaScript for Contexts view ---
CONTEXTS_JS = """
var ctxView_activeContext = null;
var ctxView_activeAttack = null;

function ctxView_loadContexts() {
    var list = document.getElementById('ctx-list');
    list.innerHTML = '';

    if (!CONTEXTS_DATA || !CONTEXTS_DATA.groupedByKind) {
        list.innerHTML = '<p>No contexts available</p>';
        return;
    }

    var groups = CONTEXTS_DATA.groupedByKind;
    var kindOrder = ['subsystem', 'network', 'actor', 'primitive', 'data'];
    var kindLabels = {
        'subsystem': 'Subsystems',
        'network': 'Networks',
        'actor': 'Actors',
        'primitive': 'Primitives',
        'data': 'Data'
    };

    kindOrder.forEach(function(kind) {
        if (!groups[kind] || groups[kind].length === 0) return;

        var section = document.createElement('div');
        section.className = 'ctx-kind-section';

        var header = document.createElement('div');
        header.className = 'ctx-kind-header';
        header.innerHTML = '<strong>' + kindLabels[kind] + '</strong> <span class="ctx-count">(' + groups[kind].length + ')</span>';
        section.appendChild(header);

        var items = document.createElement('div');
        items.className = 'ctx-items';

        groups[kind].forEach(function(context) {
            var item = document.createElement('div');
            item.className = 'ctx-item li-mouse-pointer';
            item.dataset.id = context.id;
            item.innerHTML = '<span class="ctx-identifier">' + context.identifier + '</span>' +
                             '<span class="ctx-name">' + context.name + '</span>';
            item.onclick = function(e) {
                e.stopPropagation();
                ctxView_selectContext(context.id);
            };
            items.appendChild(item);
        });

        section.appendChild(items);
        list.appendChild(section);
    });
}

function ctxView_selectContext(contextId) {
    var details = document.getElementById('ctx-details');
    var context = CONTEXTS_DATA.contextDetails[contextId];

    if (!context) {
        details.innerHTML = '<p>Context not found</p>';
        return;
    }

    // Highlight selected item
    if (ctxView_activeContext) {
        ctxView_activeContext.classList.remove('active-context');
    }
    var contextItem = document.querySelector('[data-id="' + contextId + '"]');
    if (contextItem) {
        contextItem.classList.add('active-context');
        ctxView_activeContext = contextItem;
    }

    // Clear attack selection
    ctxView_activeAttack = null;
    tmWriteUrl([contextId]);

    // Build details HTML with summary + resizable lower panes
    var html = '<div class="ctx-summary-section">' +
               '<h3>' + context.name + '</h3>' +
               '<p style="margin: 5px 0; font-size: 0.9em; color: var(--text-muted);">' +
               context.kind + ' (' + context.identifier + ')</p>';

    if (context.description) {
        html += '<div class="description" style="margin-top: 10px;">' + marked.parse(context.description) + '</div>';
    }

    html += '</div><div class="section ctx-attacks-section"><h3>Attacks in this Context</h3>' +
            '<div id="ctx-attacks">Select a context to see attacks</div>' +
            '</div><div class="pane-divider pane-divider-horizontal ctx-details-divider" data-resize="contexts-lower" aria-hidden="true"></div>' +
            '<div class="section ctx-mitigations-section"><h3>Mitigations</h3>' +
            '<div id="ctx-mitigations">Select an attack to see mitigations</div>' +
            '</div>';

    details.innerHTML = html;
    tmInitContextLowerPaneSplit();
    ctxView_loadAttacks(contextId);
}

function tmInitContextLowerPaneSplit() {
    var details = document.getElementById('ctx-details');
    if (!details) return;

    var topPane = details.querySelector('.ctx-attacks-section');
    var bottomPane = details.querySelector('.ctx-mitigations-section');
    var divider = details.querySelector('.ctx-details-divider[data-resize="contexts-lower"]');
    var summary = details.querySelector('.ctx-summary-section');
    if (!topPane || !bottomPane || !divider || !summary) return;

    function clamp(v, min, max) {
        return Math.max(min, Math.min(max, v));
    }

    function applySavedOrDefault() {
        var detailsHeight = details.getBoundingClientRect().height;
        var summaryHeight = summary.getBoundingClientRect().height;
        var dividerHeight = divider.getBoundingClientRect().height || 8;
        var available = detailsHeight - summaryHeight - dividerHeight;
        if (!available || available <= 0) return;

        var minTop = 120;
        var minBottom = 120;
        var maxTop = Math.max(minTop, available - minBottom);
        var savedTop = null;
        try {
            var raw = localStorage.getItem('tm-split-top-contexts-lower');
            if (raw !== null) savedTop = parseFloat(raw);
        } catch (_) {}
        if (!savedTop || !isFinite(savedTop)) {
            savedTop = available * 0.5;
        }
        var next = clamp(savedTop, minTop, maxTop);
        topPane.style.flex = '0 0 ' + next + 'px';
        bottomPane.style.flex = '1 1 auto';
    }

    applySavedOrDefault();

    if (divider.dataset.tmBound === '1') return;
    divider.dataset.tmBound = '1';

    divider.addEventListener('pointerdown', function(ev) {
        ev.preventDefault();
        var startY = ev.clientY;
        var startTop = topPane.getBoundingClientRect().height;
        var detailsRect = details.getBoundingClientRect();
        var summaryHeight = summary.getBoundingClientRect().height;
        var dividerHeight = divider.getBoundingClientRect().height || 8;
        var available = detailsRect.height - summaryHeight - dividerHeight;
        var minTop = 120;
        var minBottom = 120;
        var maxTop = Math.max(minTop, available - minBottom);

        divider.classList.add('is-dragging');
        document.body.classList.add('is-resizing');
        document.body.style.cursor = 'row-resize';
        divider.setPointerCapture(ev.pointerId);

        function onMove(moveEv) {
            var delta = moveEv.clientY - startY;
            var next = clamp(startTop + delta, minTop, maxTop);
            topPane.style.flex = '0 0 ' + next + 'px';
            bottomPane.style.flex = '1 1 auto';
            try {
                localStorage.setItem('tm-split-top-contexts-lower', String(Math.round(next)));
            } catch (_) {}
        }

        function onEnd(endEv) {
            divider.classList.remove('is-dragging');
            document.body.classList.remove('is-resizing');
            document.body.style.cursor = '';
            divider.releasePointerCapture(endEv.pointerId);
            divider.removeEventListener('pointermove', onMove);
            divider.removeEventListener('pointerup', onEnd);
            divider.removeEventListener('pointercancel', onEnd);
        }

        divider.addEventListener('pointermove', onMove);
        divider.addEventListener('pointerup', onEnd);
        divider.addEventListener('pointercancel', onEnd);
    });
}

function ctxView_loadAttacks(contextId) {
    var context = CONTEXTS_DATA.contextDetails[contextId];
    var div = document.getElementById('ctx-attacks');
    div.innerHTML = '';

    if (!context || !context.attacks || context.attacks.length === 0) {
        div.innerHTML = '<p>No attacks in this context.</p>';
        return;
    }

    context.attacks.forEach(function(attack) {
        var el = document.createElement('div');
        el.classList.add('attack', 'div-mouse-pointer');
        el.dataset.id = attack.id;
        el.innerHTML = '<p><strong>' + attack.auto_identifier + ' ' +
            attack.identifier + '</strong></p><p>' + attack.description + '</p>';
        el.onclick = function() { ctxView_selectAttack(el, contextId); };
        div.appendChild(el);
    });
}

function ctxView_selectAttack(el, contextId) {
    // Highlight selected attack
    if (ctxView_activeAttack) {
        ctxView_activeAttack.classList.remove('active-attack');
    }
    el.classList.add('active-attack');
    ctxView_activeAttack = el;
    tmWriteUrl([contextId, el.dataset.id]);
    ctxView_loadMitigations(el.dataset.id);
}

function ctxView_loadMitigations(attackId) {
    var mitigations = TREE_DATA.attackMitigations[attackId] || [];
    var div = document.getElementById('ctx-mitigations');
    div.innerHTML = '';

    if (mitigations.length === 0) {
        div.innerHTML = '<p>No mitigations found for this attack.</p>';
        return;
    }

    mitigations.forEach(function(mit) {
        var el = document.createElement('div');
        el.classList.add('mitigation');
        var rationale = tmRenderMitigationRationale(mit, 'Mitigation Rationale');
        var inherited = tmRenderInheritedSource(mit);
        el.innerHTML = '<p><strong>' + mit.auto_identifier + ' ' + mit.name +
            '</strong></p><p>' + mit.description + '</p>' + inherited + rationale;
        div.appendChild(el);
    });
}
"""

# --- JavaScript for Properties view ---
PROPERTIES_JS = """
var propView_activeProperty = null;
var propView_activeAttack = null;

function propView_loadProperties() {
    var tree = document.getElementById('prop-tree');
    tree.innerHTML = '';
    propView_renderTree(TREE_DATA.propertyTree, tree);
}

function propView_renderTree(properties, parentElement) {
    properties.forEach(function(property) {
        var li = document.createElement('li');
        li.dataset.id = property.id;
        li.classList.add('li-mouse-pointer');
        li.onclick = function(event) {
            event.stopPropagation();
            propView_loadAttacks(property.id);
            document.getElementById('prop-mitigations').innerHTML =
                'Select an attack to search for mitigations';
            propView_highlightProperty(li);
        };

        var nameSpan = document.createElement('span');
        nameSpan.textContent = property.auto_identifier;
        li.appendChild(nameSpan);

        if (property.description) {
            var descDiv = document.createElement('div');
            descDiv.classList.add('description');
            descDiv.innerHTML = marked.parse(property.description);
            li.appendChild(descDiv);
        }

        if (property.children.length > 0) {
            var ul = document.createElement('ul');
            propView_renderTree(property.children, ul);
            li.appendChild(ul);
        }

        parentElement.appendChild(li);
    });
}

function propView_highlightProperty(el) {
    if (propView_activeProperty) propView_activeProperty.classList.remove('active-property');
    el.classList.add('active-property');
    propView_activeProperty = el;
    tmWriteUrl([el.dataset.id]);
}

function propView_loadAttacks(propertyId) {
    var attacks = tmGetPropertyAttacks(propertyId);
    var div = document.getElementById('prop-attacks');
    div.innerHTML = '';

    if (attacks.length === 0) {
        div.innerHTML = '<p>No attacks found for this security objective.</p>';
        return;
    }

    attacks.forEach(function(attack) {
        var el = document.createElement('div');
        el.classList.add('attack', 'div-mouse-pointer');
        el.dataset.id = attack.id;
        el.innerHTML = '<p><strong>' + attack.auto_identifier + ' ' +
            attack.identifier + '</strong></p><p>' + attack.description + '</p>';
        el.onclick = function() { propView_highlightAttack(el); };
        div.appendChild(el);
    });
}

function propView_highlightAttack(el) {
    if (propView_activeAttack) propView_activeAttack.classList.remove('active-attack');
    el.classList.add('active-attack');
    propView_activeAttack = el;
    tmWriteUrl([propView_activeProperty.dataset.id, el.dataset.id]);
    propView_loadMitigations(el.dataset.id);
}

function propView_loadMitigations(attackId) {
    var mitigations = TREE_DATA.attackMitigations[attackId] || [];
    var div = document.getElementById('prop-mitigations');
    div.innerHTML = '';

    if (mitigations.length === 0) {
        div.innerHTML = '<p>No mitigations found for this attack.</p>';
        return;
    }

    mitigations.forEach(function(mit) {
        var el = document.createElement('div');
        el.classList.add('mitigation');
        var rationale = tmRenderMitigationRationale(mit, 'Mitigation Rationale');
        var inherited = tmRenderInheritedSource(mit);
        el.innerHTML = '<p><strong>' + mit.auto_identifier + ' ' + mit.name +
            '</strong></p><p>' + mit.description + '</p>' + inherited + rationale;
        div.appendChild(el);
    });
}
"""

# --- JavaScript for Attacks view ---
ATTACKS_JS = """
var atkView_activeAttack = null;

function atkView_loadAttacks() {
    var tree = document.getElementById('atk-tree');
    tree.innerHTML = '';
    atkView_renderTree(TREE_DATA.attackTree, tree);
}

function atkView_renderTree(attacks, parentElement) {
    attacks.forEach(function(attack) {
        var li = document.createElement('li');
        li.dataset.id = attack.id;
        li.classList.add('li-mouse-pointer');
        li.onclick = function(event) {
            event.stopPropagation();
            atkView_loadMitigations(attack);
            atkView_loadProperties(attack);
            atkView_highlightAttack(li);
        };

        var nameSpan = document.createElement('span');
        nameSpan.innerHTML = attack.auto_identifier + ' ' + attack.identifier;
        li.appendChild(nameSpan);

        var descDiv = document.createElement('div');
        descDiv.classList.add('description');
        descDiv.innerHTML = attack.description ? marked.parse(attack.description) : ' ';
        li.appendChild(descDiv);

        if (attack.children.length > 0) {
            var ul = document.createElement('ul');
            atkView_renderTree(attack.children, ul);
            li.appendChild(ul);
        }

        parentElement.appendChild(li);
    });
}

function atkView_highlightAttack(el) {
    if (atkView_activeAttack) atkView_activeAttack.classList.remove('active-attack');
    el.classList.add('active-attack');
    atkView_activeAttack = el;
    tmWriteUrl([el.dataset.id]);
}

function atkView_loadProperties(attack) {
    var heading = document.getElementById('atk-upper-heading');
    var container = document.getElementById('atk-properties');
    container.innerHTML = '';

    heading.textContent = 'Security Objectives';
    var properties = tmGetAttackPropertiesTree(attack.id);
    container.innerHTML = '<div class="tree"><ul id="atk-properties-tree"></ul></div>';
    var tree = document.getElementById('atk-properties-tree');
    atkView_renderPropertiesTree(properties, tree);
}

function atkView_renderPropertiesTree(properties, parentElement) {
    if (properties.length === 0) {
        var li = document.createElement('li');
        li.textContent = 'Attack patterns do not impact specific security objectives.';
        parentElement.appendChild(li);
    } else {
        properties.forEach(function(property) {
            var li = document.createElement('li');
            li.dataset.id = property.id;

            var nameSpan = document.createElement('span');
            nameSpan.textContent = property.auto_identifier;
            li.appendChild(nameSpan);

            if (property.description) {
                var descDiv = document.createElement('div');
                descDiv.classList.add('description');
                descDiv.innerHTML = marked.parse(property.description);
                li.appendChild(descDiv);
            }

            if (property.children.length > 0) {
                var ul = document.createElement('ul');
                atkView_renderPropertiesTree(property.children, ul);
                li.appendChild(ul);
            }

            parentElement.appendChild(li);
        });
    }
}

function atkView_loadMitigations(attack) {
    var mitigations = TREE_DATA.attackMitigations[attack.id] || [];
    var div = document.getElementById('atk-mitigations');
    div.innerHTML = '';

    if (mitigations.length === 0) {
        if (attack.children.length > 0) {
            div.innerHTML = '<p>No mitigations found for this attack subtree.</p>';
        } else {
            div.innerHTML = '<p>No mitigations found for this attack.</p>';
        }
        return;
    } else if (attack.children.length > 0) {
        div.innerHTML = '<p>Select a single attack to view mitigations.</p>';
        return;
    }

    mitigations.forEach(function(mit) {
        var el = document.createElement('div');
        el.classList.add('mitigation');
        el.innerHTML = '<p><strong>' + mit.auto_identifier + ' ' + mit.name +
            '</strong></p><p>' + mit.description + '</p>';
        el.innerHTML += tmRenderInheritedSource(mit);
        el.innerHTML += tmRenderMitigationRationale(mit, 'Rationale');
        div.appendChild(el);
    });
}
"""

# --- JavaScript for Attack Patterns view ---
PATTERNS_JS = """
var patView_activePattern = null;
var patView_activeInstance = null;

function patView_labelWithAutoId(autoId, identifier) {
    // Display both the auto-generated ID and the identifier for attack patterns.
    return autoId + ' ' + identifier;
}

function patView_loadPatterns() {
    var tree = document.getElementById('pat-tree');
    tree.innerHTML = '';

    var patterns = TREE_DATA.abstractAttackTree || [];
    if (patterns.length === 0) {
        var li = document.createElement('li');
        li.textContent = 'No attack patterns found.';
        tree.appendChild(li);
        return;
    }

    patView_renderTree(patterns, tree);
}

function patView_renderTree(patterns, parentElement) {
    patterns.forEach(function(pattern) {
        var li = document.createElement('li');
        li.dataset.id = pattern.id;
        li.classList.add('li-mouse-pointer');
        li.onclick = function(event) {
            event.stopPropagation();
            patView_loadInstances(pattern);
            patView_highlightPattern(li);
        };

        var nameSpan = document.createElement('span');
        nameSpan.innerHTML = patView_labelWithAutoId(pattern.auto_identifier, pattern.identifier);
        li.appendChild(nameSpan);

        if (pattern.description) {
            var descDiv = document.createElement('div');
            descDiv.classList.add('description');
            descDiv.innerHTML = marked.parse(pattern.description);
            li.appendChild(descDiv);
        }

        if (pattern.children && pattern.children.length > 0) {
            var ul = document.createElement('ul');
            patView_renderTree(pattern.children, ul);
            li.appendChild(ul);
        }

        parentElement.appendChild(li);
    });
}

function patView_highlightPattern(el) {
    if (patView_activePattern) patView_activePattern.classList.remove('active-attack');
    el.classList.add('active-attack');
    patView_activePattern = el;
    tmWriteUrl([el.dataset.id]);
}

function patView_loadInstances(pattern) {
    var heading = document.getElementById('pat-upper-heading');
    var container = document.getElementById('pat-instances');
    var mitDiv = document.getElementById('pat-mitigations');
    container.innerHTML = '';
    mitDiv.innerHTML = '';
    patView_activeInstance = null;

    heading.innerHTML = 'Instantiations of ' + patView_labelWithAutoId(pattern.auto_identifier, pattern.identifier);
    var instances = TREE_DATA.abstractAttackInstances[pattern.id] || [];
    if (instances.length === 0) {
        container.innerHTML = '<p>No concrete instantiations found for this attack pattern.</p>';
    } else {
        instances.forEach(function(instance) {
            var el = document.createElement('div');
            el.classList.add('attack', 'div-mouse-pointer');
            el.dataset.id = instance.id;
            var desc = instance.description ? '<p>' + instance.description + '</p>' : '';
            el.innerHTML = '<p><strong>' + instance.auto_identifier + ' ' +
                instance.identifier + '</strong></p>' + desc;
            el.onclick = function() { patView_selectInstance(el); };
            container.appendChild(el);
        });
    }

    // Default lower pane to selected pattern subtree mitigations
    patView_loadMitigations(pattern.id);
}

function patView_selectInstance(el) {
    if (patView_activeInstance) patView_activeInstance.classList.remove('active-attack');
    el.classList.add('active-attack');
    patView_activeInstance = el;
    tmWriteUrl([patView_activePattern.dataset.id, el.dataset.id]);
    patView_loadMitigations(el.dataset.id);
}

function patView_loadMitigations(attackId) {
    var mitigations = TREE_DATA.attackMitigations[attackId] || [];
    var div = document.getElementById('pat-mitigations');
    div.innerHTML = '';

    if (mitigations.length === 0) {
        div.innerHTML = '<p>No mitigations found for this attack.</p>';
        return;
    }

    mitigations.forEach(function(mit) {
        var el = document.createElement('div');
        el.classList.add('mitigation');
        var rationale = tmRenderMitigationRationale(mit, 'Rationale');
        var inherited = tmRenderInheritedSource(mit);
        el.innerHTML = '<p><strong>' + mit.auto_identifier + ' ' + mit.name +
            '</strong></p><p>' + mit.description + '</p>' + inherited + rationale;
        div.appendChild(el);
    });
}
"""

# --- JavaScript for Mitigations view ---
MITIGATIONS_JS = """
var mitView_activeMitigation = null;
var mitView_activeAttack = null;

function mitView_loadMitigations() {
    var tree = document.getElementById('mit-tree');
    tree.innerHTML = '';
    mitView_renderMitigations(TREE_DATA.mitigationList, tree);
}

function mitView_renderMitigations(mitigations, parentElement) {
    mitigations.forEach(function(mitigation) {
        var li = document.createElement('li');
        li.dataset.id = mitigation.id;
        li.classList.add('li-mouse-pointer');
        li.onclick = function(event) {
            event.stopPropagation();
            mitView_loadAttacks(mitigation.id);
            var propTree = document.getElementById('mit-properties');
            propTree.innerHTML = '';
            var placeholder = document.createElement('li');
            placeholder.textContent = 'Select an attack to see impacted security objectives';
            propTree.appendChild(placeholder);
            mitView_highlightMitigation(li);
        };

        var nameSpan = document.createElement('span');
        nameSpan.textContent = mitigation.auto_identifier + ' ' + mitigation.name;
        li.appendChild(nameSpan);

        if (mitigation.description) {
            var descDiv = document.createElement('div');
            descDiv.classList.add('description');
            descDiv.innerHTML = marked.parse(mitigation.description);
            li.appendChild(descDiv);
        }

        parentElement.appendChild(li);
    });
}

function mitView_highlightMitigation(el) {
    if (mitView_activeMitigation) mitView_activeMitigation.classList.remove('active-mitigation');
    el.classList.add('active-mitigation');
    mitView_activeMitigation = el;
    tmWriteUrl([el.dataset.id]);
}

function mitView_loadAttacks(mitigationId) {
    var attacks = TREE_DATA.mitigationAttacks[mitigationId] || [];
    var div = document.getElementById('mit-attacks');
    div.innerHTML = '';

    if (attacks.length === 0) {
        div.innerHTML = '<p>No attacks found for this mitigation.</p>';
        return;
    }

    attacks.forEach(function(attack) {
        var el = document.createElement('div');
        el.classList.add('attack', 'div-mouse-pointer');
        el.dataset.id = attack.id;
        var typeLabel = attack.is_abstract ? 'Attack Pattern' : 'Attack';
        var typeBadge = '<span class="ctx-kind-badge">' + typeLabel + '</span>';
        var attackRef = '<a href="#" class="tm-attack-ref" data-attack-id="' + attack.id +
            '" data-attack-abstract="' + (attack.is_abstract ? 'true' : 'false') + '">' +
            attack.auto_identifier + ' ' + attack.identifier + '</a>';
        var desc = attack.description ? '<p>' + attack.description + '</p>' : '';
        var rationale = '';
        if (attack.rationale && attack.rationale !== 'None') {
            rationale = '<p><strong>Mitigation Rationale</strong>: ' + attack.rationale + '</p>';
        }
        el.innerHTML = '<p><strong>' + attackRef + '</strong> ' + typeBadge + '</p>' + desc + rationale;
        el.onclick = function() { mitView_highlightAttack(el); };
        div.appendChild(el);
    });
}

function mitView_highlightAttack(el) {
    if (mitView_activeAttack) mitView_activeAttack.classList.remove('active-attack');
    el.classList.add('active-attack');
    mitView_activeAttack = el;
    tmWriteUrl([mitView_activeMitigation.dataset.id, el.dataset.id]);
    mitView_loadProperties(el.dataset.id);
}

function mitView_loadProperties(attackId) {
    var properties = tmGetAttackPropertiesTree(attackId);
    var tree = document.getElementById('mit-properties');
    tree.innerHTML = '';
    mitView_renderPropertyTree(properties, tree);
}

function mitView_renderPropertyTree(properties, parentElement) {
    if (properties.length === 0) {
        var li = document.createElement('li');
        li.textContent = 'Attack patterns do not impact specific security objectives.';
        parentElement.appendChild(li);
    } else {
        properties.forEach(function(property) {
            var li = document.createElement('li');
            li.dataset.id = property.id;

            var nameSpan = document.createElement('span');
            nameSpan.textContent = property.auto_identifier;
            li.appendChild(nameSpan);

            if (property.description) {
                var descDiv = document.createElement('div');
                descDiv.classList.add('description');
                descDiv.innerHTML = marked.parse(property.description);
                li.appendChild(descDiv);
            }

            if (property.children.length > 0) {
                var ul = document.createElement('ul');
                mitView_renderPropertyTree(property.children, ul);
                li.appendChild(ul);
            }

            parentElement.appendChild(li);
        });
    }
}
"""

# --- JavaScript for Graph view ---
GRAPH_JS = """
var graphInitialized = false;
var graphNetwork = null;

function initGraphIfNeeded() {
    if (graphInitialized) return;
    graphInitialized = true;

    // Escape HTML helper
    function escapeHtml(text) {
        var div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // Data from embedded JSON
    var outEdges = GRAPH_DATA.outEdges;
    var inEdges = GRAPH_DATA.inEdges;
    var nodeLabels = GRAPH_DATA.nodeLabels;
    var nodeDisplayIds = GRAPH_DATA.nodeDisplayIds || {};
    var nodeDescriptions = GRAPH_DATA.nodeDescriptions;
    var attackMitigations = GRAPH_DATA.attackMitigations;
    var attackPatterns = GRAPH_DATA.attackPatterns || {};
    var nodeTypes = {};
    (GRAPH_DATA.nodes || []).forEach(function(node) {
        nodeTypes[node.id] = node.group || 'unknown';
    });
    var displayIdToNodeId = {};
    Object.keys(nodeDisplayIds).forEach(function(nodeId) {
        var displayId = nodeDisplayIds[nodeId];
        if (displayId) displayIdToNodeId[displayId] = nodeId;
    });

    // Create vis.js DataSets
    var nodes = new vis.DataSet(GRAPH_DATA.nodes);
    var edges = new vis.DataSet(GRAPH_DATA.edges);

    // Create network
    var container = document.getElementById('graph-network');
    var network = new vis.Network(container, { nodes: nodes, edges: edges }, {
        physics: {
            barnesHut: {
                gravitationalConstant: -8000,
                centralGravity: 0.5,
                springLength: 300,
                springConstant: 0.03,
                damping: 0.09
            }
        },
        interaction: {
            hover: true,
            tooltipDelay: 999999999
        }
    });
    graphNetwork = network;

    // Disable physics after initial stabilization
    network.once('stabilizationIterationsDone', function() {
        network.setOptions({ physics: { enabled: false } });
        var toggleBtn = document.getElementById('graph-togglePhysicsBtn');
        if (toggleBtn) {
            toggleBtn.textContent = 'Unfreeze';
            toggleBtn.classList.remove('primary');
        }
        var loadingEl = document.getElementById('graph-loading');
        if (loadingEl) loadingEl.style.display = 'none';
        if (typeof updateGraphTheme === 'function') updateGraphTheme();
    });

    // Store original node/edge data for reset
    var originalNodeData = {};
    nodes.forEach(function(node) {
        originalNodeData[node.id] = {
            color: node.color,
            label: node.label,
            font: node.font || {},
            hidden: false
        };
    });
    var originalEdgeData = {};
    edges.forEach(function(edge) {
        originalEdgeData[edge.id] = {
            color: edge.color,
            hidden: false
        };
    });

    // Dark mode color variants (muted for dark backgrounds)
    var darkNodeColors = {
        '#4CAF50': '#2e7d32',
        '#F44336': '#c62828',
        '#FF9800': '#e65100',
        '#2196F3': '#1565c0',
        '#9C27B0': '#7b1fa2'
    };
    var darkEdgeColors = {
        '#666666': '#556666',
        '#F44336': '#b71c1c',
        '#FF5722': '#bf360c',
        '#795548': '#5d4037',
        '#607D8B': '#455a64',
        '#2196F3': '#0d47a1',
        '#9C27B0': '#6a1b9a'
    };

    function isDarkMode() {
        return document.documentElement.getAttribute('data-theme') === 'dark';
    }

    function getThemedColor(lightColor, colorMap) {
        if (isDarkMode() && colorMap[lightColor]) return colorMap[lightColor];
        return lightColor;
    }

    function updateGraphTheme() {
        var dark = isDarkMode();
        var fontColor = dark ? '#f0f4f6' : '#000000';
        var dimColor = dark ? '#2a4a54' : '#e0e0e0';
        var nodeUpdates = [];
        nodes.forEach(function(node) {
            var orig = originalNodeData[node.id];
            if (!orig) return;
            var currentColor = node.color;
            // Check if dimmed by focus mode
            if (currentColor === '#e0e0e0' || currentColor === '#2a4a54') {
                nodeUpdates.push({ id: node.id, color: dimColor, font: { color: dimColor } });
            } else {
                var newColor = dark ? (darkNodeColors[orig.color] || orig.color) : orig.color;
                nodeUpdates.push({ id: node.id, color: newColor, font: { color: fontColor } });
            }
        });
        nodes.update(nodeUpdates);

        var edgeUpdates = [];
        edges.forEach(function(edge) {
            var orig = originalEdgeData[edge.id];
            if (!orig) return;
            var currentColor = edge.color;
            if (currentColor === '#e0e0e0' || currentColor === '#2a4a54') {
                edgeUpdates.push({ id: edge.id, color: dimColor });
            } else {
                var newColor = dark ? (darkEdgeColors[orig.color] || orig.color) : orig.color;
                edgeUpdates.push({ id: edge.id, color: newColor });
            }
        });
        edges.update(edgeUpdates);
    }

    // Watch for theme changes
    var themeObserver = new MutationObserver(function(mutations) {
        mutations.forEach(function(m) {
            if (m.attributeName === 'data-theme') updateGraphTheme();
        });
    });
    themeObserver.observe(document.documentElement, { attributes: true });

    var currentFocusNode = null;
    var hideUnreachableMode = false;
    var applyFocus;

    // --- Node details side panel ---
    var nodeDetails = document.getElementById('graph-nodeDetails');
    var nodeTitle = document.getElementById('graph-nodeTitle');
    var nodeIdElem = document.getElementById('graph-nodeId');
    var nodeTypeBadge = document.getElementById('graph-nodeTypeBadge');
    var nodeDescription = document.getElementById('graph-nodeDescription');
    var nodePattern = document.getElementById('graph-nodePattern');
    var nodeMitigations = document.getElementById('graph-nodeMitigations');
    var mitigationsList = document.getElementById('graph-mitigationsList');
    var copyLinkBtn = document.getElementById('graph-copyLinkBtn');
    var statusDiv = document.getElementById('graph-focusStatus');
    var legendPanel = document.getElementById('graph-legendPanel');

    copyLinkBtn.addEventListener('click', function() {
        if (currentFocusNode) {
            var cpParams = new URLSearchParams();
            cpParams.set('tab', 'graph');
            cpParams.set('node', nodeDisplayIds[currentFocusNode] || currentFocusNode);
            if (hideUnreachableMode) cpParams.set('hide', 'true');
            var url = window.location.origin + window.location.pathname + '?' + cpParams.toString();
            navigator.clipboard.writeText(url).then(function() {
                copyLinkBtn.textContent = '\\u2713';
                copyLinkBtn.classList.add('copied');
                setTimeout(function() {
                    copyLinkBtn.textContent = '\\uD83D\\uDD17';
                    copyLinkBtn.classList.remove('copied');
                }, 1500);
            });
        }
    });

    function updateUrl(nodeId) {
        var urlP = new URLSearchParams(window.location.search);
        urlP.set('tab', 'graph');
        if (nodeId) {
            urlP.set('node', nodeDisplayIds[nodeId] || nodeId);
            if (hideUnreachableMode) { urlP.set('hide', 'true'); } else { urlP.delete('hide'); }
        } else {
            urlP.delete('node');
            urlP.delete('hide');
        }
        window.history.replaceState(null, '', window.location.pathname + '?' + urlP.toString());
    }

    function showNodeDetails(nodeId) {
        var label = nodeLabels[nodeId] || nodeId;
        var type = nodeTypes[nodeId] || 'unknown';
        var desc = nodeDescriptions[nodeId] || '';
        var displayId = nodeDisplayIds[nodeId] || nodeId;
        var patternId = attackPatterns[nodeId];

        nodeTitle.textContent = label;
        nodeIdElem.textContent = displayId;
        nodeTypeBadge.textContent = type;
        nodeTypeBadge.className = 'node-type-badge ' + type;
        nodeDescription.innerHTML = desc;

        if (type === 'attack' && patternId && nodeLabels[patternId]) {
            nodePattern.innerHTML = '<strong>Instantiation of</strong>: ' +
                '<a href="#" class="tm-attack-ref" data-attack-id="' +
                escapeHtml(patternId) + '" data-attack-abstract="true">' +
                escapeHtml(nodeLabels[patternId]) + '</a>';
            nodePattern.classList.add('active');
        } else {
            nodePattern.innerHTML = '';
            nodePattern.classList.remove('active');
        }

        nodeDetails.classList.add('active');
        if (legendPanel) legendPanel.removeAttribute('open');

        if (type === 'attack' && attackMitigations[nodeId]) {
            var mits = attackMitigations[nodeId];
            if (mits.length > 0) {
                mitigationsList.innerHTML = mits.map(function(mit) {
                    return '<li class="' + mit.style +
                        '"><div class="attack-line">' + tmRenderGraphAttackLine(mit) +
                        '</div></li>';
                }).join('');

                nodeMitigations.classList.add('active');
            } else {
                mitigationsList.innerHTML = '<li>No mitigations</li>';
                nodeMitigations.classList.add('active');
            }
        } else {
            nodeMitigations.classList.remove('active');
        }
    }

    function hideNodeDetails() {
        nodeDetails.classList.remove('active');
        nodePattern.innerHTML = '';
        nodePattern.classList.remove('active');
        nodeMitigations.classList.remove('active');
        if (legendPanel) legendPanel.setAttribute('open', '');
    }

    // --- Reachability ---
    function forwardReachable(startNode) {
        var visited = new Set();
        var queue = [startNode];
        while (queue.length > 0) {
            var node = queue.shift();
            if (visited.has(node)) continue;
            visited.add(node);
            var successors = outEdges[node] || [];
            for (var i = 0; i < successors.length; i++) {
                if (!visited.has(successors[i])) queue.push(successors[i]);
            }
        }
        return visited;
    }

    function backwardReachable(startNode) {
        var visited = new Set();
        var queue = [startNode];
        while (queue.length > 0) {
            var node = queue.shift();
            if (visited.has(node)) continue;
            visited.add(node);
            var predecessors = inEdges[node] || [];
            for (var i = 0; i < predecessors.length; i++) {
                if (!visited.has(predecessors[i])) queue.push(predecessors[i]);
            }
        }
        return visited;
    }

    function resetGraph() {
        currentFocusNode = null;
        statusDiv.textContent = 'Shift+Click to toggle hide mode';
        statusDiv.classList.remove('active');
        hideNodeDetails();
        updateUrl(null);

        var dark = isDarkMode();
        var fontColor = dark ? '#f0f4f6' : '#000000';
        var nodeUpdates = [];
        nodes.forEach(function(node) {
            var orig = originalNodeData[node.id];
            nodeUpdates.push({
                id: node.id,
                color: getThemedColor(orig.color, darkNodeColors),
                label: orig.label,
                font: { color: fontColor },
                hidden: false
            });
        });
        nodes.update(nodeUpdates);

        var edgeUpdates = [];
        edges.forEach(function(edge) {
            var orig = originalEdgeData[edge.id];
            edgeUpdates.push({
                id: edge.id,
                color: getThemedColor(orig.color, darkEdgeColors),
                hidden: false
            });
        });
        edges.update(edgeUpdates);
    }

    applyFocus = function(selectedNode, hideMode) {
        currentFocusNode = selectedNode;
        showNodeDetails(selectedNode);
        updateUrl(selectedNode);

        var forwardSet = forwardReachable(selectedNode);
        var backwardSet = backwardReachable(selectedNode);
        var reachableSet = new Set([...forwardSet, ...backwardSet]);

        statusDiv.textContent = 'Focused: ' + reachableSet.size + ' of ' +
            Object.keys(originalNodeData).length + ' nodes';
        statusDiv.classList.add('active');

        var dark = isDarkMode();
        var fontColor = dark ? '#f0f4f6' : '#000000';
        var dimColor = dark ? '#2a4a54' : '#e0e0e0';
        var nodeUpdates = [];
        nodes.forEach(function(node) {
            var orig = originalNodeData[node.id];
            var themedColor = getThemedColor(orig.color, darkNodeColors);
            if (node.id === selectedNode) {
                nodeUpdates.push({
                    id: node.id, color: themedColor, label: orig.label,
                    font: { color: fontColor, bold: true }, hidden: false
                });
            } else if (reachableSet.has(node.id)) {
                nodeUpdates.push({
                    id: node.id, color: themedColor, label: orig.label,
                    font: { color: fontColor }, hidden: false
                });
            } else {
                if (hideMode) {
                    nodeUpdates.push({ id: node.id, hidden: true });
                } else {
                    nodeUpdates.push({
                        id: node.id, color: dimColor, label: '',
                        font: { color: dimColor }, hidden: false
                    });
                }
            }
        });
        nodes.update(nodeUpdates);

        var edgeUpdates = [];
        edges.forEach(function(edge) {
            var fromR = reachableSet.has(edge.from);
            var toR = reachableSet.has(edge.to);
            if (fromR && toR) {
                edgeUpdates.push({
                    id: edge.id, color: getThemedColor(originalEdgeData[edge.id].color, darkEdgeColors), hidden: false
                });
            } else {
                if (hideMode) {
                    edgeUpdates.push({ id: edge.id, hidden: true });
                } else {
                    edgeUpdates.push({ id: edge.id, color: dimColor, hidden: false });
                }
            }
        });
        edges.update(edgeUpdates);

        if (hideMode) {
            network.fit({ animation: { duration: 500, easingFunction: 'easeInOutQuad' } });
        }
    };

    function graphResolveNodeRef(nodeRef) {
        if (!nodeRef) return null;
        return displayIdToNodeId[nodeRef] || (nodeLabels[nodeRef] ? nodeRef : null);
    }

    window.tmGraphNavigateToNode = function(nodeRef) {
        var canonicalId = graphResolveNodeRef(nodeRef);
        if (!canonicalId) return;

        if (hideUnreachableMode) hideUnreachableMode = false;
        network.selectNodes([canonicalId]);
        network.focus(canonicalId, {
            scale: 1.2,
            animation: { duration: 500, easingFunction: 'easeInOutQuad' }
        });
        applyFocus(canonicalId, hideUnreachableMode);
    };

    // --- Click handler ---
    network.on('click', function(params) {
        if (params.nodes.length === 0) {
            resetGraph();
            return;
        }
        var selectedNode = params.nodes[0];
        if (params.event.srcEvent.shiftKey) {
            hideUnreachableMode = !hideUnreachableMode;
        }
        applyFocus(selectedNode, hideUnreachableMode);
    });

    // --- Search ---
    var searchInput = document.getElementById('graph-searchInput');
    var searchResults = document.getElementById('graph-searchResults');

    var nodeList = [];
    for (var nid in nodeLabels) {
        nodeList.push({ id: nid, label: nodeLabels[nid], type: nodeTypes[nid] });
    }

    searchInput.addEventListener('input', function() {
        var query = this.value.toLowerCase().trim();
        if (query.length < 2) {
            searchResults.classList.remove('active');
            searchResults.innerHTML = '';
            return;
        }
        var matches = nodeList.filter(function(n) {
            return n.label.toLowerCase().includes(query);
        }).slice(0, 20);

        if (matches.length === 0) {
            searchResults.innerHTML = '<div class="search-item">No matches found</div>';
        } else {
            searchResults.innerHTML = matches.map(function(n) {
                return '<div class="search-item" data-id="' + n.id + '">' +
                    '<div>' + n.label + '</div>' +
                    '<div class="node-type">' + n.type + '</div></div>';
            }).join('');
        }
        searchResults.classList.add('active');
    });

    searchResults.addEventListener('click', function(e) {
        var item = e.target.closest('.search-item');
        if (item && item.dataset.id) {
            var nodeId = item.dataset.id;
            network.selectNodes([nodeId]);
            applyFocus(nodeId, hideUnreachableMode);
            searchInput.value = '';
            searchResults.classList.remove('active');
            searchResults.innerHTML = '';
        }
    });

    document.addEventListener('click', function(e) {
        if (!searchInput.contains(e.target) && !searchResults.contains(e.target)) {
            searchResults.classList.remove('active');
        }
    });

    // --- Custom tooltips ---
    var tooltip = document.getElementById('graph-customTooltip');
    var nodeTitles = {};
    nodes.forEach(function(node) { nodeTitles[node.id] = node.title || ''; });
    var edgeTitles = {};
    edges.forEach(function(edge) { edgeTitles[edge.id] = edge.title || ''; });

    var mouseX = 0, mouseY = 0;
    document.addEventListener('mousemove', function(e) {
        mouseX = e.clientX;
        mouseY = e.clientY;
    });

    function showTooltip(htmlContent, x, y) {
        tooltip.innerHTML = htmlContent;
        tooltip.classList.remove('visible');
        tooltip.style.left = '0px';
        tooltip.style.top = '0px';
        var left = x + 15;
        var top = y + 15;
        if (left + tooltip.offsetWidth > window.innerWidth - 10) left = x - tooltip.offsetWidth - 10;
        if (top + tooltip.offsetHeight > window.innerHeight - 10) top = y - tooltip.offsetHeight - 10;
        tooltip.style.left = left + 'px';
        tooltip.style.top = top + 'px';
        tooltip.classList.add('visible');
    }

    function hideTooltip() {
        tooltip.classList.remove('visible');
        tooltip.style.left = '-9999px';
        tooltip.style.top = '-9999px';
    }

    network.on('hoverNode', function(p) {
        if (nodeTitles[p.node]) showTooltip(nodeTitles[p.node], mouseX, mouseY);
    });
    network.on('blurNode', hideTooltip);
    network.on('hoverEdge', function(p) {
        if (edgeTitles[p.edge]) showTooltip(edgeTitles[p.edge], mouseX, mouseY);
    });
    network.on('blurEdge', hideTooltip);

    // --- Physics config ---
    var defaultPhysics = {
        gravity: -8000, centralGravity: 0.5,
        springLength: 300, springStrength: 0.03, damping: 0.09
    };

    var gravitySlider = document.getElementById('graph-gravitySlider');
    var centralGravitySlider = document.getElementById('graph-centralGravitySlider');
    var springLengthSlider = document.getElementById('graph-springLengthSlider');
    var springStrengthSlider = document.getElementById('graph-springStrengthSlider');
    var dampingSlider = document.getElementById('graph-dampingSlider');

    var gravityValue = document.getElementById('graph-gravityValue');
    var centralGravityValue = document.getElementById('graph-centralGravityValue');
    var springLengthValue = document.getElementById('graph-springLengthValue');
    var springStrengthValue = document.getElementById('graph-springStrengthValue');
    var dampingValue = document.getElementById('graph-dampingValue');

    var togglePhysicsBtn = document.getElementById('graph-togglePhysicsBtn');
    var physicsEnabled = false;

    function updatePhysics() {
        physicsEnabled = true;
        togglePhysicsBtn.textContent = 'Freeze';
        togglePhysicsBtn.classList.add('primary');
        network.setOptions({
            physics: {
                enabled: true,
                barnesHut: {
                    gravitationalConstant: parseFloat(gravitySlider.value),
                    centralGravity: parseFloat(centralGravitySlider.value),
                    springLength: parseFloat(springLengthSlider.value),
                    springConstant: parseFloat(springStrengthSlider.value),
                    damping: parseFloat(dampingSlider.value)
                }
            }
        });
    }

    function updateDisplay() {
        gravityValue.textContent = gravitySlider.value;
        centralGravityValue.textContent = centralGravitySlider.value;
        springLengthValue.textContent = springLengthSlider.value;
        springStrengthValue.textContent = springStrengthSlider.value;
        dampingValue.textContent = dampingSlider.value;
    }

    [gravitySlider, centralGravitySlider, springLengthSlider,
     springStrengthSlider, dampingSlider].forEach(function(s) {
        s.addEventListener('input', function() { updateDisplay(); updatePhysics(); });
    });

    document.getElementById('graph-resetPhysicsBtn').addEventListener('click', function() {
        gravitySlider.value = defaultPhysics.gravity;
        centralGravitySlider.value = defaultPhysics.centralGravity;
        springLengthSlider.value = defaultPhysics.springLength;
        springStrengthSlider.value = defaultPhysics.springStrength;
        dampingSlider.value = defaultPhysics.damping;
        updateDisplay();
        updatePhysics();
    });

    togglePhysicsBtn.addEventListener('click', function() {
        physicsEnabled = !physicsEnabled;
        network.setOptions({ physics: { enabled: physicsEnabled } });
        if (physicsEnabled) {
            togglePhysicsBtn.textContent = 'Freeze';
            togglePhysicsBtn.classList.add('primary');
        } else {
            togglePhysicsBtn.textContent = 'Unfreeze';
            togglePhysicsBtn.classList.remove('primary');
        }
    });

    // --- URL parameter handling ---
    var params = new URLSearchParams(window.location.search);
    var urlNodeId = params.get('node');
    var urlHideMode = params.get('hide') === 'true';
    // Resolve display ID (e.g. "M11") → canonical node ID; fall back to raw if already canonical
    var urlCanonicalId = urlNodeId
        ? (displayIdToNodeId[urlNodeId] || (nodeLabels[urlNodeId] ? urlNodeId : null))
        : null;

    if (urlCanonicalId) {
        if (legendPanel) legendPanel.removeAttribute('open');
        if (urlHideMode) hideUnreachableMode = true;
        network.focus(urlCanonicalId, {
            scale: 1.2,
            animation: { duration: 800, easingFunction: 'easeInOutQuad' }
        });
        setTimeout(function() {
            applyFocus(urlCanonicalId, hideUnreachableMode);
        }, 100);
    }

    // Fit after a short delay to ensure container is visible
    setTimeout(function() {
        network.redraw();
        network.fit();
    }, 100);
}
"""


# =============================================================================
# HTML Assembly
# =============================================================================


def _assemble_html(
    vis_js: str,
    marked_js: str,
    pako_js: str,
    tree_data: dict,
    graph_data: dict,
    context_dict: dict,
    contexts_data: dict,
) -> str:
    """Assemble the complete HTML document."""
    tree_json = json.dumps(tree_data, ensure_ascii=False, separators=(",", ":"))
    graph_json = json.dumps(graph_data, ensure_ascii=False, separators=(",", ":"))
    contexts_json = json.dumps(contexts_data, ensure_ascii=False, separators=(",", ":"))

    tree_gzip_b64 = base64.b64encode(
        gzip.compress(tree_json.encode("utf-8"), compresslevel=9, mtime=0)
    ).decode("ascii")
    graph_gzip_b64 = base64.b64encode(
        gzip.compress(graph_json.encode("utf-8"), compresslevel=9, mtime=0)
    ).decode("ascii")
    contexts_gzip_b64 = base64.b64encode(
        gzip.compress(contexts_json.encode("utf-8"), compresslevel=9, mtime=0)
    ).decode("ascii")
    marked_gzip_b64 = base64.b64encode(
        gzip.compress(marked_js.encode("utf-8"), compresslevel=9, mtime=0)
    ).decode("ascii")
    vis_gzip_b64 = base64.b64encode(
        gzip.compress(vis_js.encode("utf-8"), compresslevel=9, mtime=0)
    ).decode("ascii")

    nav_html = NAV_HTML.format(version=MODEL_VERSION, date=MODEL_DATE)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VoteSecure Threat Model v{MODEL_VERSION}</title>
<style>
{CSS}
</style>
</head>
<body>
{nav_html}
{CONTEXTS_HTML}
{PROPERTIES_HTML}
{ATTACKS_HTML}
{PATTERNS_HTML}
{MITIGATIONS_HTML}
{GRAPH_HTML}
<script>{pako_js}</script>
<script>
var TREE_DATA = null;
var GRAPH_DATA = null;
var CONTEXTS_DATA = null;

var TM_COMPRESSED_TREE_DATA = "{tree_gzip_b64}";
var TM_COMPRESSED_GRAPH_DATA = "{graph_gzip_b64}";
var TM_COMPRESSED_CONTEXTS_DATA = "{contexts_gzip_b64}";
var TM_COMPRESSED_MARKED_JS = "{marked_gzip_b64}";
var TM_COMPRESSED_VIS_JS = "{vis_gzip_b64}";

function tmBase64ToBytes(b64) {{
    var binary = atob(b64);
    var len = binary.length;
    var bytes = new Uint8Array(len);
    for (var i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
}}

async function tmGunzipUtf8FromBase64(b64) {{
    var bytes = tmBase64ToBytes(b64);

    if (typeof DecompressionStream !== 'undefined') {{
        var stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'));
        var buffer = await new Response(stream).arrayBuffer();
        return new TextDecoder().decode(buffer);
    }}

    if (window.pako && typeof window.pako.ungzip === 'function') {{
        return new TextDecoder().decode(window.pako.ungzip(bytes));
    }}

    throw new Error('No gzip decompressor available (requires DecompressionStream or pako).');
}}

function tmInstallInlineScript(source, label) {{
    var script = document.createElement('script');
    script.type = 'text/javascript';
    script.setAttribute('data-tm-embedded', label || 'inline');
    script.text = source;
    document.head.appendChild(script);
}}

async function tmLoadEmbeddedData() {{
    var treeText = await tmGunzipUtf8FromBase64(TM_COMPRESSED_TREE_DATA);
    var graphText = await tmGunzipUtf8FromBase64(TM_COMPRESSED_GRAPH_DATA);
    var contextsText = await tmGunzipUtf8FromBase64(TM_COMPRESSED_CONTEXTS_DATA);
    var markedText = await tmGunzipUtf8FromBase64(TM_COMPRESSED_MARKED_JS);
    var visText = await tmGunzipUtf8FromBase64(TM_COMPRESSED_VIS_JS);

    TREE_DATA = JSON.parse(treeText);
    GRAPH_DATA = JSON.parse(graphText);
    CONTEXTS_DATA = JSON.parse(contextsText);

    tmInstallInlineScript(markedText, 'marked');
    tmInstallInlineScript(visText, 'vis-network');
}}

var TM_DATA_READY = tmLoadEmbeddedData();
</script>
<script>
{TAB_JS}
{CONTEXTS_JS}
{PROPERTIES_JS}
{ATTACKS_JS}
{PATTERNS_JS}
{MITIGATIONS_JS}
{GRAPH_JS}

// Context popup management
function tmStabilizeGraphViewport() {{
    if (!graphNetwork) return;
    var activeLink = document.querySelector('.tab-link.active');
    if (!activeLink || activeLink.dataset.tab !== 'graph') return;

    var scale = graphNetwork.getScale();
    var pos = graphNetwork.getViewPosition();
    requestAnimationFrame(function() {{
        graphNetwork.moveTo({{
            position: pos,
            scale: scale,
            animation: false,
        }});
    }});
}}

function showContextPopup(contextId) {{
    var popup = document.getElementById('context-popup-' + contextId);
    if (!popup) {{
        var contextData = TREE_DATA && TREE_DATA.contextPopupData
            ? TREE_DATA.contextPopupData[contextId]
            : null;
        if (!contextData) return false;

        var closeOnclick = 'closeContextPopup(&#39;' + tmEscapeHtml(contextId) + '&#39;)';
        var detailsOnclick = closeOnclick + '; tmNavigateToModelRef(&#39;context&#39;, &#39;' +
            tmEscapeHtml(contextId) + '&#39;, false);';
        var graphRef = contextData.graph_node_ref || contextId;
        var graphOnclick = closeOnclick + '; tmNavigateToGraphNode(&#39;' +
            tmEscapeHtml(graphRef) + '&#39;);';

        var popupMarkup = '' +
            '<div id="context-popup-' + tmEscapeHtml(contextId) + '" class="context-popup">' +
                '<div class="context-popup-content">' +
                    '<div class="context-popup-header">' +
                        '<div>' +
                            '<div class="context-popup-identifier">' + tmEscapeHtml(contextData.identifier || contextId) + '</div>' +
                            '<h2>' + tmEscapeHtml(contextData.name || '') + '</h2>' +
                        '</div>' +
                        '<div class="context-popup-close-group">' +
                            '<button class="context-popup-nav" onclick="' + detailsOnclick + '" title="Open details tab" aria-label="Open details tab">&#8599;</button>' +
                            '<button class="context-popup-nav" onclick="' + graphOnclick + '" title="Open in graph tab" aria-label="Open in graph tab">&#9672;</button>' +
                            '<button class="context-popup-close" onclick="' + closeOnclick + '" title="Close popup" aria-label="Close popup">&times;</button>' +
                        '</div>' +
                    '</div>' +
                    '<div class="context-popup-kind">Kind: ' + tmEscapeHtml(contextData.kind || '') + '</div>' +
                    (contextData.description ? '<div class="context-popup-description">' + contextData.description + '</div>' : '') +
                '</div>' +
            '</div>';

        document.body.insertAdjacentHTML('beforeend', popupMarkup);
        popup = document.getElementById('context-popup-' + contextId);
    }}

    if (popup) {{
        popup.classList.add('show');
        tmStabilizeGraphViewport();
        return true;
    }}
    return false;
}}

function closeContextPopup(contextId) {{
    var popup = document.getElementById('context-popup-' + contextId);
    if (popup) {{
        popup.classList.remove('show');
        tmStabilizeGraphViewport();
    }}
}}

function showPropertyPopup(propertyId) {{
    var popup = document.getElementById('property-popup-' + propertyId);
    if (!popup) {{
        var propertyData = TREE_DATA && TREE_DATA.propertyPopupData
            ? TREE_DATA.propertyPopupData[propertyId]
            : null;
        if (!propertyData) return false;

        var closeOnclick = 'closePropertyPopup(&#39;' + tmEscapeHtml(propertyId) + '&#39;)';
        var detailsOnclick = closeOnclick + '; tmNavigateToModelRef(&#39;property&#39;, &#39;' +
            tmEscapeHtml(propertyId) + '&#39;, false);';
        var graphRef = propertyData.graph_node_ref || propertyId;
        var graphOnclick = closeOnclick + '; tmNavigateToGraphNode(&#39;' +
            tmEscapeHtml(graphRef) + '&#39;);';

        var popupMarkup = '' +
            '<div id="property-popup-' + tmEscapeHtml(propertyId) + '" class="context-popup property-popup">' +
                '<div class="context-popup-content">' +
                    '<div class="context-popup-header">' +
                        '<div>' +
                            '<div class="context-popup-identifier">' + tmEscapeHtml(propertyData.auto_identifier || '') + '</div>' +
                            '<h2>' + tmEscapeHtml(propertyData.title || 'Security objective') + '</h2>' +
                        '</div>' +
                        '<div class="context-popup-close-group">' +
                            '<button class="context-popup-nav" onclick="' + detailsOnclick + '" title="Open details tab" aria-label="Open details tab">&#8599;</button>' +
                            '<button class="context-popup-nav" onclick="' + graphOnclick + '" title="Open in graph tab" aria-label="Open in graph tab">&#9672;</button>' +
                            '<button class="context-popup-close" onclick="' + closeOnclick + '" title="Close popup" aria-label="Close popup">&times;</button>' +
                        '</div>' +
                    '</div>' +
                    (propertyData.description ? '<div class="context-popup-description">' + propertyData.description + '</div>' : '') +
                '</div>' +
            '</div>';

        document.body.insertAdjacentHTML('beforeend', popupMarkup);
        popup = document.getElementById('property-popup-' + propertyId);
    }}

    if (popup) {{
        popup.classList.add('show');
        tmStabilizeGraphViewport();
        return true;
    }}
    return false;
}}

function closePropertyPopup(propertyId) {{
    var popup = document.getElementById('property-popup-' + propertyId);
    if (popup) {{
        popup.classList.remove('show');
        tmStabilizeGraphViewport();
    }}
}}

function showMitigationPopup(mitigationId) {{
    var popup = document.getElementById('mitigation-popup-' + mitigationId);
    if (!popup) {{
        var mitigationData = TREE_DATA && TREE_DATA.mitigationPopupData
            ? TREE_DATA.mitigationPopupData[mitigationId]
            : null;
        if (!mitigationData) return false;

        var closeOnclick = 'closeMitigationPopup(&#39;' + tmEscapeHtml(mitigationId) + '&#39;)';
        var detailsOnclick = closeOnclick + '; tmNavigateToModelRef(&#39;mitigation&#39;, &#39;' +
            tmEscapeHtml(mitigationId) + '&#39;, false);';
        var graphRef = mitigationData.graph_node_ref || mitigationId;
        var graphOnclick = closeOnclick + '; tmNavigateToGraphNode(&#39;' +
            tmEscapeHtml(graphRef) + '&#39;);';

        var popupMarkup = '' +
            '<div id="mitigation-popup-' + tmEscapeHtml(mitigationId) + '" class="context-popup mitigation-popup">' +
                '<div class="context-popup-content">' +
                    '<div class="context-popup-header">' +
                        '<div>' +
                            '<div class="context-popup-identifier">' + tmEscapeHtml(mitigationData.auto_identifier || '') + '</div>' +
                            '<h2>' + tmEscapeHtml(mitigationData.name || '') + '</h2>' +
                        '</div>' +
                        '<div class="context-popup-close-group">' +
                            '<button class="context-popup-nav" onclick="' + detailsOnclick + '" title="Open details tab" aria-label="Open details tab">&#8599;</button>' +
                            '<button class="context-popup-nav" onclick="' + graphOnclick + '" title="Open in graph tab" aria-label="Open in graph tab">&#9672;</button>' +
                            '<button class="context-popup-close" onclick="' + closeOnclick + '" title="Close popup" aria-label="Close popup">&times;</button>' +
                        '</div>' +
                    '</div>' +
                    (mitigationData.description ? '<div class="context-popup-description">' + mitigationData.description + '</div>' : '') +
                '</div>' +
            '</div>';

        document.body.insertAdjacentHTML('beforeend', popupMarkup);
        popup = document.getElementById('mitigation-popup-' + mitigationId);
    }}

    if (popup) {{
        popup.classList.add('show');
        tmStabilizeGraphViewport();
        return true;
    }}
    return false;
}}

function closeMitigationPopup(mitigationId) {{
    var popup = document.getElementById('mitigation-popup-' + mitigationId);
    if (popup) {{
        popup.classList.remove('show');
        tmStabilizeGraphViewport();
    }}
}}

function showCitationPopup(citeKey) {{
    var popup = document.getElementById('citation-popup-' + citeKey);
    if (!popup) {{
        var citeData = TREE_DATA && TREE_DATA.citationPopupData
            ? TREE_DATA.citationPopupData[citeKey]
            : null;
        if (!citeData) return false;

        var title = tmEscapeHtml(citeData.title || citeKey);
        var label = tmEscapeHtml(citeData.label || citeKey);
        var authors = tmEscapeHtml((citeData.authors || []).join(', '));
        var year = tmEscapeHtml(citeData.year || 'n.d.');
        var venue = tmEscapeHtml(citeData.venue || '');

        var links = [];
        if (citeData.doi) {{
            var doi = String(citeData.doi);
            var doiUrl = doi.indexOf('http') === 0 ? doi : ('https://doi.org/' + doi);
            links.push('<a class="tm-ref" href="' + tmEscapeHtml(doiUrl) + '" target="_blank" rel="noopener noreferrer">DOI</a>');
        }}
        if (citeData.url) {{
            links.push('<a class="tm-ref" href="' + tmEscapeHtml(String(citeData.url)) + '" target="_blank" rel="noopener noreferrer">URL</a>');
        }}
        var linksHtml = links.length
            ? '<div class="context-popup-description">' + links.join(' · ') + '</div>'
            : '';
        var metaHtml = authors + ((authors && year) ? ' · ' : '') + year;
        var closeOnclick = 'closeCitationPopup(&#39;' + tmEscapeHtml(citeKey) + '&#39;)';

        var popupMarkup = '' +
            '<div id="citation-popup-' + tmEscapeHtml(citeKey) + '" class="context-popup citation-popup">' +
                '<div class="context-popup-content">' +
                    '<div class="context-popup-header">' +
                        '<div>' +
                            '<div class="context-popup-identifier">[' + label + ']</div>' +
                            '<h2>' + title + '</h2>' +
                        '</div>' +
                        '<button class="context-popup-close" onclick="' + closeOnclick + '" title="Close popup" aria-label="Close popup">&times;</button>' +
                    '</div>' +
                    '<div class="context-popup-kind">' + metaHtml + '</div>' +
                    (venue ? '<div class="context-popup-description">' + venue + '</div>' : '') +
                    linksHtml +
                    '<div class="context-popup-description">BibTeX key: <code>' + tmEscapeHtml(citeKey) + '</code></div>' +
                '</div>' +
            '</div>';

        document.body.insertAdjacentHTML('beforeend', popupMarkup);
        popup = document.getElementById('citation-popup-' + citeKey);
    }}

    if (popup) {{
        popup.classList.add('show');
        tmStabilizeGraphViewport();
        return true;
    }}
    return false;
}}

function closeCitationPopup(citeKey) {{
    var popup = document.getElementById('citation-popup-' + citeKey);
    if (popup) {{
        popup.classList.remove('show');
        tmStabilizeGraphViewport();
    }}
}}

function showAttackPopupById(attackId) {{
    var popup = document.getElementById('attack-popup-' + attackId);
    if (!popup) {{
        var attackData = TREE_DATA && TREE_DATA.attackPopupData
            ? TREE_DATA.attackPopupData[attackId]
            : null;
        if (!attackData) return false;

        var kind = attackData.is_abstract ? 'Attack Pattern' : 'Concrete Attack';
        var autoIdHtml = attackData.auto_identifier
            ? '<div class="context-popup-identifier">' + tmEscapeHtml(attackData.auto_identifier) + '</div>'
            : '';

        var lineageIds = attackData.lineage_ids || [];
        var lineageLinks = lineageIds.map(function(lineageId) {{
            var node = TREE_DATA.attackPopupData[lineageId];
            if (!node) return '';
            return '<a href="#" class="tm-attack-ref" data-attack-id="' + tmEscapeHtml(lineageId) +
                '" data-attack-abstract="' + (node.is_abstract ? 'true' : 'false') + '">' +
                (node.identifier || '') + '</a>';
        }}).filter(function(x) {{ return x; }});

        var lineageHtml = lineageLinks.length > 0
            ? '<div class="context-popup-description"><strong>Attack line</strong>: ' + lineageLinks.join(' → ') + '</div>'
            : '';

        var lineageDetails = lineageIds.map(function(lineageId) {{
            var node = TREE_DATA.attackPopupData[lineageId];
            if (!node) return '';
            var nodeKind = node.is_abstract ? 'Attack Pattern' : 'Attack';
            var titleHtml = '<a href="#" class="tm-attack-ref" data-attack-id="' + tmEscapeHtml(lineageId) +
                '" data-attack-abstract="' + (node.is_abstract ? 'true' : 'false') + '">' +
                (node.identifier || '') + '</a>';
            return '<li class="attack-line-details-item">' +
                '<div class="attack-line-details-title">' + titleHtml + '</div>' +
                '<div class="attack-line-details-kind">' + tmEscapeHtml(nodeKind) + '</div>' +
                (node.description ? '<div class="attack-line-details-description">' + node.description + '</div>' : '') +
                '</li>';
        }}).filter(function(x) {{ return x; }});

        var lineageDetailsHtml = lineageDetails.length > 1
            ? '<div class="context-popup-description"><strong>Attack line details</strong></div>' +
              '<ul class="attack-line-details-list">' + lineageDetails.join('') + '</ul>'
            : '';

        var graphRef = attackData.graph_node_ref || attackId;
        var detailsOnclick = 'closeAttackPopup(&#39;' + tmEscapeHtml(attackId) + '&#39;); ' +
            'tmNavigateToModelRef(&#39;attack&#39;, &#39;' + tmEscapeHtml(attackId) + '&#39;, ' +
            (attackData.is_abstract ? 'true' : 'false') + ');';
        var graphOnclick = 'closeAttackPopup(&#39;' + tmEscapeHtml(attackId) + '&#39;); ' +
            'tmNavigateToGraphNode(&#39;' + tmEscapeHtml(graphRef) + '&#39;);';
        var closeOnclick = 'closeAttackPopup(&#39;' + tmEscapeHtml(attackId) + '&#39;)';
        var popupMarkup = '' +
            '<div id="attack-popup-' + tmEscapeHtml(attackId) + '" class="context-popup attack-popup">' +
                '<div class="context-popup-content">' +
                    '<div class="context-popup-header">' +
                        '<div>' + autoIdHtml + '<h2>' + (attackData.identifier || '') + '</h2></div>' +
                        '<div class="context-popup-close-group">' +
                            '<button class="context-popup-nav" onclick="' + detailsOnclick + '" title="Open details tab" aria-label="Open details tab">&#8599;</button>' +
                            '<button class="context-popup-nav" onclick="' + graphOnclick + '" title="Open in graph tab" aria-label="Open in graph tab">&#9672;</button>' +
                            '<button class="context-popup-close" onclick="' + closeOnclick + '" title="Close popup" aria-label="Close popup">&times;</button>' +
                        '</div>' +
                    '</div>' +
                    '<div class="context-popup-kind">Kind: ' + tmEscapeHtml(kind) + '</div>' +
                    lineageHtml +
                    (attackData.description ? '<div class="context-popup-description">' + attackData.description + '</div>' : '') +
                    lineageDetailsHtml +
                '</div>' +
            '</div>';

        document.body.insertAdjacentHTML('beforeend', popupMarkup);
        popup = document.getElementById('attack-popup-' + attackId);
    }}

    if (popup) {{
        popup.classList.add('show');
        tmStabilizeGraphViewport();
        return true;
    }}
    return false;
}}

function closeAttackPopup(attackId) {{
    var popup = document.getElementById('attack-popup-' + attackId);
    if (popup) {{
        popup.classList.remove('show');
        tmStabilizeGraphViewport();
    }}
}}

function tmLineSegmentIsAbstract(segment, nodeTypes) {{
    if (!segment) return false;
    if (segment.kind === 'pattern') return true;
    if (segment.is_abstract === true) return true;
    return !!(segment.id && nodeTypes[segment.id] === 'pattern');
}}

function tmLineTextFromSegments(lineData) {{
    var segments = tmResolveLineSegments(lineData);
    if (!segments || segments.length === 0) return '';
    return segments
        .map(function(segment) {{ return tmNormalizeLatexPunctuation((segment && segment.label) || ''); }})
        .filter(function(label) {{ return label.length > 0; }})
        .join(' → ');
}}

function tmGraphLineSegmentTitle(segment, graphMeta) {{
    if (!segment) return '';
    var nodeDisplayIds = graphMeta.nodeDisplayIds || {{}};
    var nodeLabels = graphMeta.nodeLabels || {{}};
    var nodeTypes = graphMeta.nodeTypes || {{}};
    var normalizedLabel = tmNormalizeLatexPunctuation(segment.label || '').trim();

    if ((segment.kind === 'attack' || segment.kind === 'pattern') && segment.id) {{
        var attackDisplay = nodeDisplayIds[segment.id] || '';
        var attackText = (
            attackDisplay
                ? (tmEscapeHtml(attackDisplay) + ' ' + tmEscapeHtml(normalizedLabel))
                : tmEscapeHtml(normalizedLabel)
        ).trim();
        var isAbstract = tmLineSegmentIsAbstract(segment, nodeTypes);
        return '<a href="#" class="tm-attack-ref" data-attack-id="' +
            tmEscapeHtml(segment.id) + '" data-attack-abstract="' +
            (isAbstract ? 'true' : 'false') + '">' + attackText + '</a>';
    }}

    if (segment.kind === 'mitigation' && segment.id) {{
        var mitDisplay = nodeDisplayIds[segment.id] || '';
        var mitName = tmNormalizeLatexPunctuation(nodeLabels[segment.id] || segment.label || '');
        if (mitDisplay && mitName.indexOf(mitDisplay + ' ') === 0) {{
            mitName = mitName.slice((mitDisplay + ' ').length);
        }}
        var mitText = (
            mitDisplay
                ? (tmEscapeHtml(mitDisplay) + ' ' + tmEscapeHtml(mitName))
                : tmEscapeHtml(normalizedLabel)
        ).trim();
        return '<a href="#" class="tm-ref" data-ref-kind="mitigation" data-ref-id="' +
            tmEscapeHtml(segment.id) + '">' + mitText + '</a>';
    }}

    return tmEscapeHtml(normalizedLabel);
}}

function tmGraphLineSegmentRefInfo(segment, graphMeta) {{
    if (!segment || !segment.id) return null;

    var kind = null;
    var isAbstract = false;
    if (segment.kind === 'attack' || segment.kind === 'pattern') {{
        kind = 'attack';
        isAbstract = tmLineSegmentIsAbstract(segment, graphMeta.nodeTypes || {{}});
    }} else if (segment.kind === 'mitigation') {{
        kind = 'mitigation';
    }} else if (segment.kind === 'property') {{
        kind = 'property';
    }} else if (segment.kind === 'context') {{
        kind = 'context';
    }}

    if (!kind) return null;
    return {{
        kind: kind,
        refId: segment.id,
        isAbstract: isAbstract,
        graphNodeRef: segment.id,
    }};
}}

function tmGraphLineSegmentKind(segment, graphMeta) {{
    if (!segment) return 'Item';
    if (segment.kind === 'attack' || segment.kind === 'pattern') {{
        return tmLineSegmentIsAbstract(segment, graphMeta.nodeTypes || {{}})
            ? 'Attack Pattern'
            : 'Attack';
    }}
    if (segment.kind === 'mitigation') return segment.id ? 'Mitigation' : 'Out of Scope';
    return segment.kind || 'Item';
}}

function tmGraphLineSegmentDescription(segment, graphMeta) {{
    if (!segment) return '';
    var nodeDescriptions = graphMeta.nodeDescriptions || {{}};
    if (segment.id && nodeDescriptions[segment.id]) return nodeDescriptions[segment.id];
    if (segment.kind === 'mitigation' && !segment.id) {{
        return 'Mitigating this attack line is outside the scope of the E2E-VIV cryptographic core library.';
    }}
    return '';
}}

function tmBuildLinePopupMarkup(popupId, lineData, options) {{
    var opts = options || {{}};
    var graphMeta = opts.graphMeta || {{}};
    var popupDomId = opts.popupDomId || ('graph-line-popup-' + popupId);
    var titleLabel = opts.titleLabel || 'Attack line';
    var closeHandler = opts.closeHandler || 'closeGraphLinePopup';

    var details = tmResolveLineSegments(lineData).map(function(segment) {{
        var titleHtml = tmGraphLineSegmentTitle(segment, graphMeta);
        var kindText = tmEscapeHtml(tmGraphLineSegmentKind(segment, graphMeta));
        var descriptionHtml = tmGraphLineSegmentDescription(segment, graphMeta);
        var refInfo = tmGraphLineSegmentRefInfo(segment, graphMeta);
        var actionsHtml = '';
        if (refInfo) {{
            actionsHtml = '' +
                '<span class="attack-line-details-actions">' +
                '<button class="attack-line-action" data-line-action="tab" data-ref-kind="' + tmEscapeHtml(refInfo.kind) +
                    '" data-ref-id="' + tmEscapeHtml(refInfo.refId) + '" data-ref-abstract="' +
                    (refInfo.isAbstract ? 'true' : 'false') + '" title="Open details tab" aria-label="Open details tab">&#8599;</button>' +
                '<button class="attack-line-action" data-line-action="graph" data-graph-node="' + tmEscapeHtml(refInfo.graphNodeRef) +
                    '" title="Open in graph tab" aria-label="Open in graph tab">&#9672;</button>' +
                '</span>';
        }}
        return '<li class="attack-line-details-item">' +
            '<div class="attack-line-details-head">' +
                '<div class="attack-line-details-title">' + titleHtml + '</div>' +
                actionsHtml +
            '</div>' +
            '<div class="attack-line-details-kind">' + kindText + '</div>' +
            (descriptionHtml ? '<div class="attack-line-details-description">' + descriptionHtml + '</div>' : '') +
            '</li>';
    }}).join('');

    var lineText = tmEscapeHtml(tmNormalizeLatexPunctuation(
        (lineData && lineData.line) || tmLineTextFromSegments(lineData) || ''
    ));
    var rationaleHtml = (lineData && lineData.rationale_html)
        ? '<div class="context-popup-description"><strong>Rationale</strong>: ' + lineData.rationale_html + '</div>'
        : '';

    return '' +
        '<div id="' + tmEscapeHtml(popupDomId) + '" class="context-popup graph-line-popup">' +
        '<div class="context-popup-content">' +
        '<div class="context-popup-header">' +
        '<div><div class="context-popup-identifier">' + tmEscapeHtml(titleLabel) + '</div><h2>' + lineText + '</h2></div>' +
        '<button class="context-popup-close" onclick="' + closeHandler + '(&#39;' + tmEscapeHtml(popupId) + '&#39;)" title="Close popup" aria-label="Close popup">&times;</button>' +
        '</div>' +
        '<div class="context-popup-description"><strong>Components</strong></div>' +
        '<ul class="attack-line-details-list">' + details + '</ul>' +
        rationaleHtml +
        '</div></div>';
}}

function showCustomLinePopup(spec) {{
    if (!spec || !spec.popupId) return;
    var popupId = spec.popupId;
    var popupDomId = spec.popupDomId || ('graph-line-popup-' + popupId);
    var popup = document.getElementById(popupDomId);

    if (!popup) {{
        var popupNodeTypes = {{}};
        ((GRAPH_DATA && GRAPH_DATA.nodes) || []).forEach(function(node) {{
            popupNodeTypes[node.id] = node.group || 'unknown';
        }});
        var graphMeta = {{
            nodeDisplayIds: (GRAPH_DATA && GRAPH_DATA.nodeDisplayIds) || {{}},
            nodeLabels: (GRAPH_DATA && GRAPH_DATA.nodeLabels) || {{}},
            nodeTypes: popupNodeTypes,
            nodeDescriptions: (GRAPH_DATA && GRAPH_DATA.nodeDescriptions) || {{}}
        }};

        var popupMarkup = tmBuildLinePopupMarkup(popupId, spec, {{
            graphMeta: graphMeta,
            popupDomId: popupDomId,
            titleLabel: spec.titleLabel || 'Attack line',
            closeHandler: spec.closeHandler || 'closeGraphLinePopup'
        }});

        document.body.insertAdjacentHTML('beforeend', popupMarkup);
        popup = document.getElementById(popupDomId);
    }}

    if (popup) {{
        popup.classList.add('show');
        tmStabilizeGraphViewport();
    }}
}}

function showCustomLinePopupById(popupId) {{
    if (!popupId) return;
    var specs = window.tmCustomLinePopupSpecs || {{}};
    var spec = specs[popupId];
    if (spec) showCustomLinePopup(spec);
}}

function showGraphLinePopup(popupId) {{
    if (!popupId) return;

    var cached = window.tmGraphLineMitigationCache && window.tmGraphLineMitigationCache[popupId];
    var mitigation = cached;

    if (!mitigation) {{
        var all = (GRAPH_DATA && GRAPH_DATA.attackMitigations) || {{}};
        for (var attackId in all) {{
            if (!Object.prototype.hasOwnProperty.call(all, attackId)) continue;
            var entries = all[attackId] || [];
            for (var i = 0; i < entries.length; i++) {{
                if (entries[i] && entries[i].popup_id === popupId) {{
                    mitigation = entries[i];
                    window.tmGraphLineMitigationCache = window.tmGraphLineMitigationCache || {{}};
                    window.tmGraphLineMitigationCache[popupId] = mitigation;
                    break;
                }}
            }}
            if (mitigation) break;
        }}
    }}

    if (!mitigation) return;

    showCustomLinePopup({{
        popupId: popupId,
        line: mitigation.line,
        segments: mitigation.segments || [],
        rationale_html: mitigation.rationale_html || '',
        titleLabel: 'Attack line',
        closeHandler: 'closeGraphLinePopup'
    }});
}}

function closeGraphLinePopup(popupId) {{
    var popup = document.getElementById('graph-line-popup-' + popupId);
    if (popup) {{
        popup.classList.remove('show');
        tmStabilizeGraphViewport();
    }}
}}

window.tmShowCustomLinePopup = showCustomLinePopup;

document.addEventListener("DOMContentLoaded", async function() {{
    try {{
        await TM_DATA_READY;
    }} catch (err) {{
        console.error('Failed to initialize embedded data:', err);
        document.body.innerHTML = '<div style="padding:20px;font-family:Arial,sans-serif;color:#b00020;">Failed to initialize embedded data payloads. Please use a modern browser with DecompressionStream support.</div>';
        return;
    }}

    initTabs();
    // Load the first tab (contexts) on page load
    ctxView_loadContexts();
    tmInitContextLowerPaneSplit();
    // Restore context selection if the contexts tab is active on load
    var initTab = new URLSearchParams(window.location.search).get('tab');
    if (!initTab || initTab === 'contexts') tmRestoreTabSelection('contexts');

    // Theme toggle
    var toggle = document.getElementById('theme-toggle');
    var html = document.documentElement;
    var urlParams = new URLSearchParams(window.location.search);
    var urlTheme = urlParams.get('theme');
    if (urlTheme) {{
        localStorage.setItem('tm-theme', urlTheme);
        urlParams.delete('theme');
        var newUrl = window.location.pathname;
        var remaining = urlParams.toString();
        if (remaining) newUrl += '?' + remaining;
        window.history.replaceState(null, '', newUrl);
    }}
    var stored = urlTheme || localStorage.getItem('tm-theme');
    if (stored === 'dark' || (!stored && window.matchMedia('(prefers-color-scheme: dark)').matches)) {{
        html.setAttribute('data-theme', 'dark');
        toggle.textContent = '\\u2600';
    }}
    toggle.addEventListener('click', function() {{
        var isDark = html.getAttribute('data-theme') === 'dark';
        if (isDark) {{
            html.removeAttribute('data-theme');
            toggle.textContent = '\\u263E';
            localStorage.setItem('tm-theme', 'light');
        }} else {{
            html.setAttribute('data-theme', 'dark');
            toggle.textContent = '\\u2600';
            localStorage.setItem('tm-theme', 'dark');
        }}
    }});

    var layoutReset = document.getElementById('layout-reset');
    if (layoutReset) {{
        layoutReset.addEventListener('click', function() {{
            tmResetResizableSplitPanes();
        }});
    }}

    // Handle clicks on context reference links
    document.addEventListener('click', function(e) {{
        if (e.target.classList.contains('tm-cite')) {{
            e.stopPropagation();
            var citeKey = e.target.dataset.citeKey;
            if (citeKey) showCitationPopup(citeKey);
            return;
        }}
        var lineAction = e.target.closest('.attack-line-action');
        if (lineAction) {{
            e.preventDefault();
            e.stopPropagation();
            var actionKind = lineAction.dataset.lineAction;
            if (actionKind === 'tab') {{
                var navKind = lineAction.dataset.refKind;
                var navId = lineAction.dataset.refId;
                var navAbstract = lineAction.dataset.refAbstract === 'true';
                if (navKind && navId) tmNavigateToModelRef(navKind, navId, navAbstract);
                return;
            }}
            if (actionKind === 'graph') {{
                var nodeRef = lineAction.dataset.graphNode;
                if (nodeRef) tmNavigateToGraphNode(nodeRef);
                return;
            }}
        }}
        if (e.target.classList.contains('tm-custom-line-ref')) {{
            e.preventDefault();
            e.stopPropagation();
            var customPopupId = e.target.dataset.customLinePopup;
            if (customPopupId) showCustomLinePopupById(customPopupId);
            return;
        }}
        if (e.target.classList.contains('tm-graph-line-ref')) {{
            e.preventDefault();
            e.stopPropagation();
            var popupId = e.target.dataset.graphLinePopup;
            if (popupId) showGraphLinePopup(popupId);
            return;
        }}
        if (e.target.classList.contains('tm-attack-ref')) {{
            e.preventDefault();
            e.stopPropagation();
            var attackId = e.target.dataset.attackId;
            var isAbstract = e.target.dataset.attackAbstract === 'true';
            if (attackId) {{
                // Outside a popup: show the popup; inside a popup: navigate to the view
                if (!e.target.closest('.context-popup')) {{
                    if (showAttackPopupById(attackId)) return;
                }}
                tmNavigateToModelRef('attack', attackId, isAbstract);
            }}
            return;
        }}
        if (e.target.classList.contains('tm-ref')) {{
            if (e.target.tagName === 'A' && e.target.href && !e.target.dataset.refKind) return;
            e.preventDefault();
            e.stopPropagation();
            var refKind = e.target.dataset.refKind;
            var refId = e.target.dataset.refId;
            var refIsAbstract = e.target.dataset.refAbstract === 'true';
            if (refKind && refId) {{
                // Outside a popup: show popup if available; inside a popup: navigate
                if (!e.target.closest('.context-popup')) {{
                    if (refKind === 'attack') {{
                        if (showAttackPopupById(refId)) return;
                    }}
                    else if (refKind === 'context') {{ if (showContextPopup(refId)) return; }}
                    else if (refKind === 'property') {{ if (showPropertyPopup(refId)) return; }}
                    else if (refKind === 'mitigation') {{ if (showMitigationPopup(refId)) return; }}
                }}
                tmNavigateToModelRef(refKind, refId, refIsAbstract);
            }}
        }}
    }}, true);

    // Close popup when clicking outside of it
    document.addEventListener('click', function(e) {{
        if (e.target.classList.contains('context-popup')) {{
            e.target.classList.remove('show');
        }}
    }});

    // Restore active tab from URL; backward-compat: bare ?node= without ?tab= implies graph
    var params = new URLSearchParams(window.location.search);
    var urlTab = params.get('tab') || (params.get('node') ? 'graph' : null);
    if (urlTab && urlTab !== 'contexts') {{
        var tabLink = document.querySelector('[data-tab="' + urlTab + '"]');
        if (tabLink) {{
            tmPreserveSelectionOnNextTabSwitch = true;
            tabLink.click();
        }}
    }}

    // Back/forward button support: restore tab and selection from URL history state
    window.addEventListener('popstate', function() {{
        var bParams = new URLSearchParams(window.location.search);
        var bTab = bParams.get('tab') || (bParams.get('node') ? 'graph' : 'contexts');
        var activeLink = document.querySelector('.tab-link.active');
        var activeTab = activeLink ? activeLink.dataset.tab : null;
        if (activeTab !== bTab) {{
            var bTabLink = document.querySelector('[data-tab="' + bTab + '"]');
            if (bTabLink) {{
                tmPreserveSelectionOnNextTabSwitch = true;
                bTabLink.click();
            }}
        }} else {{
            tmRestoreTabSelection(bTab);
        }}
    }});
}});
</script>
</body>
</html>"""


# =============================================================================
# Main
# =============================================================================


def generate_html(output_path: str) -> None:
    """Generate the unified HTML visualization."""
    print("Fetching JS libraries...")
    vis_js = _fetch_js_library(VIS_NETWORK_URL, "vis-network.min.js")
    marked_js = _fetch_js_library(MARKED_URL, "marked.min.js")
    pako_js = _fetch_js_library(PAKO_URL, "pako.min.js")

    print("Building tree view data...")
    tree_data, contexts_data, context_dict = _build_tree_data()

    print("Building graph view data...")
    graph_data = _build_graph_data()

    print("Assembling HTML...")
    html = _assemble_html(
        vis_js, marked_js, pako_js, tree_data, graph_data, context_dict, contexts_data
    )

    Path(output_path).write_text(html, encoding="utf-8")
    size_kb = len(html.encode("utf-8")) / 1024
    print(f"Generated: {output_path} ({size_kb:.0f} KB)")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate interactive threat model HTML visualization"
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default="threat-model.html",
        help="Output HTML file path",
    )
    args = parser.parse_args()
    generate_html(args.output)


if __name__ == "__main__":
    main()
