import unittest

from logic_verdict_gates import (
    apply_logic_verdict_gates,
    extract_source_literals,
    method_has_identity_injection,
    parse_security_filter_summary,
    poc_uses_unverified_guesses,
)


class LogicVerdictGatesTest(unittest.TestCase):
    def test_identity_injection_detected(self):
        src = """
        @GetMapping("/menu")
        public List menu(@CurrentUsername String username) { ... }
        """
        self.assertTrue(method_has_identity_injection(src))

    def test_reject_missing_auth_with_current_user(self):
        candidate = {
            "type": "missing_auth",
            "cross_signals": [],
            "evidence": "",
        }
        result = {
            "confirmed": True,
            "refutation_verdict": "confirmed",
            "exploit_poc": "curl http://x/menu",
        }
        out = apply_logic_verdict_gates(
            candidate,
            result,
            method_source="@CurrentUser WebGoatUser user",
        )
        self.assertFalse(out["confirmed"])
        self.assertEqual(out["refutation_verdict"], "rejected")

    def test_public_endpoint_global_auth_inconclusive(self):
        candidate = {"type": "public_endpoint", "evidence": ""}
        result = {"confirmed": True, "exploit_poc": "curl /api", "refutation_verdict": "confirmed"}
        sec = parse_security_filter_summary(
            "SECURITY_CONFIG | foo | code_preview=anyRequest().authenticated()"
        )
        out = apply_logic_verdict_gates(
            candidate, result, method_source="", security_summary=sec,
        )
        self.assertFalse(out["confirmed"])
        self.assertEqual(out["refutation_verdict"], "inconclusive")

    def test_extract_literals_from_evidence_and_source(self):
        evidence = 'HARDCODED_CRED | value="bm5nhSkxCXZkKRy4" | file=x.java | line=10'
        src = 'static final String PASSWORD = "bm5nhSkxCXZkKRy4";'
        lits = extract_source_literals(src, evidence)
        self.assertIn("bm5nhSkxCXZkKRy4", lits)

    def test_poc_guess_password_rejected(self):
        bad, reason = poc_uses_unverified_guesses(
            '{"user":"Jerry","password":"password"}',
            ["bm5nhSkxCXZkKRy4"],
            candidate_type="jwt_endpoint",
        )
        self.assertTrue(bad)
        self.assertIn("password", reason.lower())

    def test_poc_correct_literal_ok(self):
        bad, _ = poc_uses_unverified_guesses(
            '{"password":"bm5nhSkxCXZkKRy4"}',
            ["bm5nhSkxCXZkKRy4"],
            candidate_type="hardcoded_cred",
        )
        self.assertFalse(bad)


if __name__ == "__main__":
    unittest.main()
