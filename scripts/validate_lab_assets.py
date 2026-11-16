#!/usr/bin/env python3
"""Offline structural checks for the lab's committed configuration assets."""

import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SVG_FILES = (
    "banner-animated.svg",
    "architecture-flow.svg",
    "threat-response-loop.svg",
    "terminal-simulation.svg",
)


def parse_xml(path: Path, expected_root: str) -> ET.Element:
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        raise ValueError(f"invalid XML in {path}: {exc}") from exc
    actual_root = root.tag.rsplit("}", 1)[-1]
    if actual_root != expected_root:
        raise ValueError(
            f"{path} must have a <{expected_root}> root, found <{actual_root}>"
        )
    return root


def validate_local_rules(path: Path) -> int:
    root = parse_xml(path, "group")
    rule_ids = [rule.get("id") for rule in root.iter("rule")]
    if not rule_ids:
        raise ValueError(f"no <rule> entries found in {path}")
    if any(not rule_id or not rule_id.isdecimal() for rule_id in rule_ids):
        raise ValueError(f"every rule in {path} must have a numeric id")

    seen = set()
    duplicates = set()
    for rule_id in rule_ids:
        if rule_id in seen:
            duplicates.add(rule_id)
        seen.add(rule_id)
    if duplicates:
        raise ValueError(
            f"duplicate rule ids in {path}: {', '.join(sorted(duplicates))}"
        )
    return len(rule_ids)


def validate_shuffle_workflow(path: Path) -> tuple[int, int]:
    try:
        workflow = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(workflow, dict):
        raise ValueError(f"{path} must contain a JSON object")

    triggers = workflow.get("triggers")
    actions = workflow.get("actions")
    branches = workflow.get("branches")
    if not isinstance(triggers, list) or not isinstance(actions, list):
        raise ValueError(f"{path} must contain trigger and action lists")
    if not isinstance(branches, list):
        raise ValueError(f"{path} must contain a branch list")
    if not triggers or not actions or not branches:
        raise ValueError(f"{path} must contain triggers, actions, and branches")

    nodes = triggers + actions
    node_ids = []
    for node in nodes:
        if not isinstance(node, dict):
            raise ValueError(f"every trigger and action in {path} must be an object")
        node_id = node.get("id")
        if not isinstance(node_id, str) or not node_id.strip():
            raise ValueError(f"every trigger and action in {path} needs a non-empty id")
        node_ids.append(node_id)
    if len(node_ids) != len(set(node_ids)):
        raise ValueError(f"trigger and action ids must be unique in {path}")

    known_ids = set(node_ids)
    seen_edges = set()
    connected_ids = set()
    for branch in branches:
        if not isinstance(branch, dict):
            raise ValueError(f"every branch in {path} must be an object")
        source = branch.get("source")
        destination = branch.get("destination")
        if (
            not isinstance(source, str)
            or not isinstance(destination, str)
            or source not in known_ids
            or destination not in known_ids
        ):
            raise ValueError(
                f"branch in {path} references an unknown node: "
                f"{source!r} -> {destination!r}"
            )
        edge = (source, destination)
        if edge in seen_edges:
            raise ValueError(f"duplicate branch in {path}: {source} -> {destination}")
        seen_edges.add(edge)
        connected_ids.update(edge)
    disconnected = known_ids - connected_ids
    if disconnected:
        raise ValueError(
            f"Shuffle nodes in {path} are not connected by any branch: "
            f"{', '.join(sorted(disconnected))}"
        )
    return len(nodes), len(branches)


def validate_lab_assets(root: Path = ROOT) -> dict[str, int]:
    parse_xml(root / "configs" / "ossec.conf", "ossec_config")
    rule_count = validate_local_rules(root / "configs" / "rules" / "local_rules.xml")
    workflow_nodes, workflow_branches = validate_shuffle_workflow(
        root / "configs" / "shuffle" / "soc_automated_response_workflow.json"
    )

    svg_dir = root / "assets" / "animations"
    for name in SVG_FILES:
        parse_xml(svg_dir / name, "svg")

    return {
        "local_rules": rule_count,
        "shuffle_nodes": workflow_nodes,
        "shuffle_branches": workflow_branches,
        "svgs": len(SVG_FILES),
    }


def main() -> int:
    try:
        summary = validate_lab_assets()
    except ValueError as exc:
        print(f"Validation failed: {exc}", file=sys.stderr)
        return 1

    print(
        "Lab assets valid: "
        f"{summary['local_rules']} Wazuh rules, "
        f"{summary['shuffle_nodes']} Shuffle nodes with "
        f"{summary['shuffle_branches']} valid branches, "
        f"{summary['svgs']} SVG files."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
