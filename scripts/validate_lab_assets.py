#!/usr/bin/env python3
"""Offline structural checks for the lab's committed configuration assets."""

import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CUSTOM_RULE_ID_MIN = 100000
CUSTOM_RULE_ID_MAX = 120000
AUTH_OPTIONS_4_14 = {
    "disabled",
    "remote_enrollment",
    "port",
    "ipv6",
    "use_source_ip",
    "force",
    "purge",
    "use_password",
    "ssl_agent_ca",
    "ssl_verify_host",
    "ssl_manager_cert",
    "ssl_manager_key",
    "ssl_auto_negotiate",
    "ciphers",
    "key_request",
    "agents",
}
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

    outside_custom_range = sorted(
        rule_id
        for rule_id in rule_ids
        if not CUSTOM_RULE_ID_MIN <= int(rule_id) <= CUSTOM_RULE_ID_MAX
    )
    if outside_custom_range:
        raise ValueError(
            f"custom rule ids must be between {CUSTOM_RULE_ID_MIN} and "
            f"{CUSTOM_RULE_ID_MAX}: {', '.join(outside_custom_range)}"
        )

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


def validate_ossec_config(path: Path) -> tuple[set[str], int]:
    root = parse_xml(path, "ossec_config")
    auth = root.find("auth")
    if auth is not None:
        unknown_options = sorted(
            child.tag for child in auth if child.tag not in AUTH_OPTIONS_4_14
        )
        if unknown_options:
            raise ValueError(
                f"unsupported Wazuh 4.14 auth option(s): {', '.join(unknown_options)}"
            )

    integrations = root.findall("integration")
    for integration in integrations:
        name = (integration.findtext("name") or "").strip()
        if not name:
            raise ValueError("every Wazuh integration needs a name")
        if name.startswith("custom-"):
            script = path.parent / "integrations" / name
            if not script.is_file():
                raise ValueError(
                    f"custom integration {name!r} has no matching script at {script}"
                )
            first_line = script.read_text(encoding="utf-8").splitlines()[:1]
            if not first_line or not first_line[0].startswith("#!"):
                raise ValueError(f"custom integration {name!r} needs an interpreter line")

    referenced_ids = set()
    for tag in ("rule_id", "rules_id"):
        for element in root.iter(tag):
            referenced_ids.update(
                value.strip()
                for value in (element.text or "").split(",")
                if value.strip()
            )
    return referenced_ids, len(integrations)


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
    config_rule_refs, integration_count = validate_ossec_config(
        root / "configs" / "ossec.conf"
    )
    rule_count = validate_local_rules(root / "configs" / "rules" / "local_rules.xml")
    local_rules_root = parse_xml(root / "configs" / "rules" / "local_rules.xml", "group")
    local_rule_ids = {rule.get("id") for rule in local_rules_root.iter("rule")}
    unresolved_refs = sorted(config_rule_refs - local_rule_ids)
    if unresolved_refs:
        raise ValueError(
            "Wazuh config references local rule ids that are not defined: "
            + ", ".join(unresolved_refs)
        )
    workflow_nodes, workflow_branches = validate_shuffle_workflow(
        root / "configs" / "shuffle" / "soc_automated_response_workflow.json"
    )

    svg_dir = root / "assets" / "animations"
    for name in SVG_FILES:
        parse_xml(svg_dir / name, "svg")

    return {
        "local_rules": rule_count,
        "integrations": integration_count,
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
        f"{summary['integrations']} Wazuh integration(s), "
        f"{summary['shuffle_nodes']} Shuffle nodes with "
        f"{summary['shuffle_branches']} valid branches, "
        f"{summary['svgs']} SVG files."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
