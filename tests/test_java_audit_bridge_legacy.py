import unittest
from pathlib import Path

from java_audit_bridge import JavaAuditSkillsBridge


class JavaAuditBridgeLegacyTest(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parent.parent / "vendor" / "java-audit-skills"
        self.bridge = JavaAuditSkillsBridge(root_path=str(root))

    def test_is_available_with_cloned_vendor(self):
        self.assertTrue(self.bridge.is_available())

    def test_legacy_playbook_resolves_to_audit_skills(self):
        folder = self.bridge.resolve_playbook_folder("java-auth-audit")
        self.assertEqual(folder, "audit-skills")

    def test_load_java_auth_playbook_ok(self):
        payload = self.bridge.load_playbook_text("java-auth-audit")
        self.assertTrue(payload.get("ok"), payload.get("error"))
        self.assertEqual(payload.get("playbook_id"), "java-auth-audit")
        self.assertIn("鉴权", payload.get("text", ""))

    def test_list_playbooks_includes_legacy_ids(self):
        playbooks = self.bridge.list_playbooks()
        ids = {p.playbook_id for p in playbooks}
        self.assertIn("java-auth-audit", ids)
        self.assertIn("java-route-mapper", ids)


if __name__ == "__main__":
    unittest.main()
