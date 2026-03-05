# Shared projection layer for generator consumers (HTML/LaTeX)
#
# Builds deterministic, generator-friendly dictionaries from the native
# threat-model objects while preserving stable numbering/link semantics.

from __future__ import annotations

from natsort import natsorted

from . import model as threat_model, patterns

PROPERTY_PREFIX = {
    "CONFIDENTIALITY": "P",
    "CORRECTNESS": "C",
    "VERIFIABILITY": "V",
    "DISPUTE_FREENESS": "D",
    "AVAILABILITY": "A",
}

# Attack classification abbreviations
ATTACK_PATTERN_PREFIX = "APTN"  # Attack Pattern
ATTACK_PREFIX = "ATK"  # Concrete Attack (instance)


def _is_out_of_scope_mitigation(mitigation) -> bool:
    return getattr(mitigation, "name", "") == "Out of scope"


def _build_property_dict(model) -> dict[str, dict]:
    property_dict: dict[str, dict] = {}

    for prop in model.properties:
        property_dict[prop.id] = {
            "id": prop.id,
            "name": prop.id,
            "description": prop.description,
            "kind": "Model",
            "identifier": prop.id,
            "parent": None,
            "children": [],
            "related_properties": [],
            "attacks": [],
        }

    for prop in model.properties:
        if prop.refines:
            property_dict[prop.id]["parent"] = property_dict[prop.refines.id]
            property_dict[prop.refines.id]["children"].append(property_dict[prop.id])

    return property_dict


def _build_context_dict(model) -> dict[str, dict]:
    context_dict: dict[str, dict] = {}

    for ctx in model.contexts:
        kind_str = ctx.kind.value if hasattr(ctx.kind, "value") else str(ctx.kind)
        context_dict[ctx.id] = {
            "id": ctx.id,
            "name": ctx.name,
            "kind": kind_str,
            "description": getattr(ctx, "description", None),
            "identifier": ctx.id,
        }

    return context_dict


def _build_mitigation_dict(model) -> dict[str, dict]:
    mitigation_dict: dict[str, dict] = {}

    for mit in model.mitigations:
        if _is_out_of_scope_mitigation(mit):
            continue
        scope_str = mit.scope.value if hasattr(mit.scope, "value") else str(mit.scope)
        mitigation_dict[mit.id] = {
            "id": mit.id,
            "name": mit.name,
            "description": mit.description,
            "identifier": mit.id,
            "auto_identifier": mit.id,
            "scope": scope_str,
            "attacks": [],
        }

    return mitigation_dict


def _build_attack_dict(
    model, property_dict, context_dict, mitigation_dict
) -> dict[str, dict]:
    attack_dict: dict[str, dict] = {}

    # Patterns first (abstract)
    for pattern in patterns.ALL:
        attack_dict[pattern.id] = {
            "id": pattern.id,
            "identifier": pattern.name,
            "name": pattern.name,
            "description": getattr(pattern, "description", ""),
            "is_abstract": 1,
            "instance_of": None,
            "context": None,
            "likelihood": None,
            "impact": None,
            "properties": [],
            "mitigations": [],
            "children": [],
            "parents": [],
        }

        if getattr(pattern, "mitigations", None):
            for ma in pattern.mitigations:
                if _is_out_of_scope_mitigation(ma.mitigation):
                    attack_dict[pattern.id]["mitigations"].append(
                        {"mitigation": None, "rationale": ma.rationale}
                    )
                elif ma.mitigation.id in mitigation_dict:
                    mit_ref = mitigation_dict[ma.mitigation.id]
                    attack_dict[pattern.id]["mitigations"].append(
                        {"mitigation": mit_ref, "rationale": ma.rationale}
                    )
                    mit_ref["attacks"].append(attack_dict[pattern.id])

    # Concrete attacks
    for attack in model.attacks:
        ctx_ref = None
        if attack.occurs_in:
            first_ctx = attack.occurs_in[0]
            ctx_ref = context_dict.get(first_ctx.id)

        identifier_parts = [attack.name]
        if attack.achieves:
            identifier_parts.insert(0, attack.achieves[0].name)
        if attack.occurs_in:
            ctx_ids = ",".join(c.id for c in attack.occurs_in)
            identifier_parts.append(ctx_ids)
        qualified_identifier = ".".join(identifier_parts)

        attack_dict[attack.id] = {
            "id": attack.id,
            "identifier": qualified_identifier,
            "name": attack.name,
            "description": getattr(attack, "description", "") or "",
            "is_abstract": 0,
            "instance_of": None,
            "context": ctx_ref,
            "likelihood": None,
            "impact": None,
            "properties": [],
            "mitigations": [],
            "children": [],
            "parents": [],
        }

        for prop in attack.targets:
            if prop.id in property_dict:
                prop_ref = property_dict[prop.id]
                attack_dict[attack.id]["properties"].append(prop_ref)
                prop_ref["attacks"].append(attack_dict[attack.id])

        for ma in attack.mitigations:
            if _is_out_of_scope_mitigation(ma.mitigation):
                attack_dict[attack.id]["mitigations"].append(
                    {"mitigation": None, "rationale": ma.rationale}
                )
            elif ma.mitigation.id in mitigation_dict:
                mit_ref = mitigation_dict[ma.mitigation.id]
                attack_dict[attack.id]["mitigations"].append(
                    {"mitigation": mit_ref, "rationale": ma.rationale}
                )
                mit_ref["attacks"].append(attack_dict[attack.id])

    # Link concrete attack relationships
    for attack in model.attacks:
        if attack.variant_of and attack.variant_of.id in attack_dict:
            attack_dict[attack.id]["instance_of"] = attack_dict[attack.variant_of.id]

        for parent in attack.achieves:
            if parent.id in attack_dict:
                attack_dict[attack.id]["parents"].append(attack_dict[parent.id])
                attack_dict[parent.id]["children"].append(attack_dict[attack.id])

    # Link pattern hierarchy (refines)
    for pattern in patterns.ALL:
        if pattern.refines and pattern.refines.id in attack_dict:
            attack_dict[pattern.id]["parents"].append(attack_dict[pattern.refines.id])
            attack_dict[pattern.refines.id]["children"].append(attack_dict[pattern.id])

    return attack_dict


def _get_property_prefix(identifier: str) -> str | None:
    return PROPERTY_PREFIX.get(identifier)


def _gen_attack_ids(roots: list[dict], prefix: str | None = None) -> None:
    roots = natsorted(roots, key=lambda value: value["identifier"])

    index = 1
    abs_index = 1

    for root in roots:
        if root["is_abstract"]:
            effective_index = abs_index
            abs_index += 1
        else:
            effective_index = index
            index += 1

        if prefix is None:
            attack_prefix = (
                ATTACK_PATTERN_PREFIX if root["is_abstract"] == 1 else ATTACK_PREFIX
            )
            root["auto_identifier"] = f"{attack_prefix}{effective_index}"
        else:
            root["auto_identifier"] = f"{prefix}.{effective_index}"

        if root["children"]:
            _gen_attack_ids(root["children"], root["auto_identifier"])


def _gen_property_ids(
    roots: list[dict], prefix: str | None = None, top: bool = False
) -> None:
    roots = natsorted(roots, key=lambda value: value["identifier"])

    for index, root in enumerate(roots):
        identifier = root["identifier"]

        property_prefix = None
        if prefix is None and root["kind"] == "Model":
            property_prefix = _get_property_prefix(identifier)

        if property_prefix is None or top:
            root["auto_identifier"] = identifier
        else:
            root["auto_identifier"] = f"{property_prefix}.{(index + 1)}"

        if root["children"]:
            _gen_property_ids(root["children"], root["auto_identifier"])


def _gen_context_ids(ctxs: list[dict], prefix: str) -> None:
    ctxs = natsorted(ctxs, key=lambda value: value["name"])

    for index, ctx in enumerate(ctxs):
        ctx["auto_identifier"] = f"{prefix}{(index + 1)}"


def _gen_mitigation_ids(mitigations: list[dict], prefix: str) -> None:
    mitigations = natsorted(mitigations, key=lambda value: value["name"])

    for index, mit in enumerate(mitigations):
        mit["auto_identifier"] = f"{prefix}{(index + 1)}"


def get_projection_data() -> tuple[dict, dict, dict, dict]:
    """Return generator-friendly projection dictionaries built from native model objects."""
    model = threat_model

    property_dict = _build_property_dict(model)
    context_dict = _build_context_dict(model)
    mitigation_dict = _build_mitigation_dict(model)
    attack_dict = _build_attack_dict(
        model, property_dict, context_dict, mitigation_dict
    )

    attack_roots = [a for a in attack_dict.values() if not a["parents"]]
    _gen_attack_ids(attack_roots)

    property_roots = [p for p in property_dict.values() if p["parent"] is None]
    _gen_property_ids(property_roots, top=True)

    _gen_context_ids(list(context_dict.values()), "CX")
    _gen_mitigation_ids(list(mitigation_dict.values()), "M")

    return property_dict, context_dict, mitigation_dict, attack_dict
