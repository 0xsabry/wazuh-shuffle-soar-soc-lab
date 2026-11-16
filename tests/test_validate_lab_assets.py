import json
import tempfile
import unittest
from pathlib import Path

from scripts.validate_lab_assets import (
    validate_lab_assets,
    validate_local_rules,
    validate_shuffle_workflow,
)


class LabAssetValidationTests(unittest.TestCase):
    def test_committed_lab_assets_pass_validation(self):
        summary = validate_lab_assets()

        self.assertEqual(summary["local_rules"], 8)
        self.assertEqual(summary["shuffle_nodes"], 6)
        self.assertEqual(summary["shuffle_branches"], 5)
        self.assertEqual(summary["svgs"], 4)

    def test_duplicate_wazuh_rule_ids_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rules.xml"
            path.write_text(
                '<group><rule id="100001"/><rule id="100001"/></group>',
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "duplicate rule ids.*100001"):
                validate_local_rules(path)

    def test_shuffle_workflow_rejects_dangling_branch(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "workflow.json"
            path.write_text(json.dumps({
                "triggers": [{"id": "webhook"}],
                "actions": [{"id": "parse"}],
                "branches": [{"source": "webhook", "destination": "missing"}],
            }), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "unknown node"):
                validate_shuffle_workflow(path)

    def test_shuffle_workflow_rejects_duplicate_node_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "workflow.json"
            path.write_text(json.dumps({
                "triggers": [{"id": "same"}],
                "actions": [{"id": "same"}],
                "branches": [{"source": "same", "destination": "same"}],
            }), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "ids must be unique"):
                validate_shuffle_workflow(path)

    def test_shuffle_workflow_rejects_unconnected_action(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "workflow.json"
            path.write_text(json.dumps({
                "triggers": [{"id": "webhook"}],
                "actions": [{"id": "parse"}, {"id": "orphan"}],
                "branches": [{"source": "webhook", "destination": "parse"}],
            }), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "not connected.*orphan"):
                validate_shuffle_workflow(path)


if __name__ == "__main__":
    unittest.main()
