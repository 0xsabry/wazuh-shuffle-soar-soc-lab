import json
import importlib.util
from importlib.machinery import SourceFileLoader
import tempfile
import unittest
from unittest.mock import Mock
from pathlib import Path

from scripts.validate_lab_assets import (
    validate_lab_assets,
    validate_local_rules,
    validate_ossec_config,
    validate_shuffle_workflow,
)


class LabAssetValidationTests(unittest.TestCase):
    def test_committed_lab_assets_pass_validation(self):
        summary = validate_lab_assets()

        self.assertEqual(summary["local_rules"], 8)
        self.assertEqual(summary["integrations"], 1)
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

    def test_builtin_wazuh_rule_id_is_rejected_for_local_rule(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rules.xml"
            path.write_text('<group><rule id="5763"/></group>', encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "between 100000 and 120000"):
                validate_local_rules(path)

    def test_unsupported_wazuh_414_auth_option_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ossec.xml"
            path.write_text(
                "<ossec_config><auth><purge_removed_agents>yes</purge_removed_agents>"
                "</auth></ossec_config>",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "purge_removed_agents"):
                validate_ossec_config(path)

    def test_custom_integration_must_have_a_matching_script(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "ossec.conf"
            config.write_text(
                "<ossec_config><integration><name>custom-shuffle</name>"
                "</integration></ossec_config>",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "no matching script"):
                validate_ossec_config(config)

    def test_custom_shuffle_sends_the_original_alert_as_json(self):
        script_path = Path(__file__).resolve().parents[1] / "configs" / "integrations" / "custom-shuffle"
        loader = SourceFileLoader("custom_shuffle", str(script_path))
        spec = importlib.util.spec_from_loader("custom_shuffle", loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        alert = {"rule": {"id": "100003"}, "agent": {"id": "002"}}

        with tempfile.TemporaryDirectory() as directory:
            alert_path = Path(directory) / "alert.json"
            alert_path.write_text(json.dumps(alert), encoding="utf-8")
            response = Mock(status=202)
            response.__enter__ = Mock(return_value=response)
            response.__exit__ = Mock(return_value=False)
            opener = Mock(return_value=response)

            module.send_alert(str(alert_path), "https://shuffle.example.invalid/hooks/test", opener)

        request = opener.call_args.args[0]
        self.assertEqual(json.loads(request.data), alert)
        self.assertEqual(request.get_header("Content-type"), "application/json")
        opener.assert_called_once_with(request, timeout=10)

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
