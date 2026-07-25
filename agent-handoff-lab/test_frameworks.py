"""Tests for the source-faithful framework reproductions (frameworks.py).

Asserts the handoff soft joint for each modelled real framework:
  * VULN  — an injected redirect in untrusted text crosses the privilege
            boundary and executes the crown-jewel tool (DB dump lands in _AUDIT).
  * FIXED  — the same attack is blocked at the join (off-graph or privilege
            re-auth), and NO privileged side effect occurs.
  * FIXED must NOT break a legitimate, statically-declared handoff.
  * A staff caller may legitimately reach the privileged agent under FIXED
    (the control gates by authorization, not by blanket denial).
"""
import unittest

from lab.runtime import VULN, DETECT, FIXED
from lab import tools
import frameworks as F

FRAMEWORKS = [F.AgentSquad, F.CrewAI, F.LangGraph]


class SoftJointAcrossFrameworks(unittest.TestCase):

    def test_vuln_every_framework_leaks_on_every_attack(self):
        for cls in FRAMEWORKS:
            for label, atk in F.ATTACKS.items():
                with self.subTest(framework=cls.framework, attack=label):
                    res = F._run_case(cls, VULN, atk)
                    self.assertEqual(res["reached"], "BillingAdminAgent",
                                     f"{cls.framework}/{label}: redirect did not reach privileged agent")
                    self.assertIsNotNone(res["executed"],
                                         f"{cls.framework}/{label}: privileged action did not fire")
                    self.assertTrue(any(a[0] == "run_sql" for a in res["audit"]),
                                    f"{cls.framework}/{label}: no crown-jewel side effect logged")

    def test_fixed_every_framework_blocks_every_attack(self):
        for cls in FRAMEWORKS:
            for label, atk in F.ATTACKS.items():
                with self.subTest(framework=cls.framework, attack=label):
                    res = F._run_case(cls, FIXED, atk)
                    self.assertIsNone(res["executed"],
                                      f"{cls.framework}/{label}: FIXED still executed privileged action")
                    self.assertIn(res["blocked"], ("allowlist", "reauth"),
                                  f"{cls.framework}/{label}: expected a join block, got {res['blocked']}")
                    self.assertEqual(res["audit"], [],
                                     f"{cls.framework}/{label}: side effect occurred under FIXED")

    def test_fixed_preserves_legitimate_handoff(self):
        for cls in FRAMEWORKS:
            with self.subTest(framework=cls.framework):
                res = F._run_case(cls, FIXED, F.BENIGN)
                self.assertEqual(res["reached"], "SupportAgent",
                                 f"{cls.framework}: FIXED broke a legitimate handoff")
                self.assertIsNone(res["blocked"])

    def test_fixed_authorizes_staff_to_privileged_agent(self):
        # FIXED gates by authorization, not blanket denial: a staff caller taking
        # the legit two-hop path (support -> billing w/ a refund task) is allowed.
        for cls in FRAMEWORKS:
            with self.subTest(framework=cls.framework):
                res = F._run_case(cls, FIXED,
                                  "please transfer to SupportAgent to process my refund",
                                  user_role="staff")
                # legit path exists and staff is authorized at the privileged join
                self.assertIsNone(res["blocked"],
                                  f"{cls.framework}: staff wrongly blocked on the legit path")

    def test_detect_catches_marker_but_leaks_paraphrase(self):
        # Detection != prevention: the static filter recognises the literal
        # [[HANDOFF:..]] marker and neutralises it, but the natural-language
        # redirect carries no marker and sails straight through, for every
        # framework.
        for cls in FRAMEWORKS:
            with self.subTest(framework=cls.framework):
                caught = F._run_case(cls, DETECT, F.ATTACKS["marker"])
                self.assertIsNone(caught["executed"],
                                  f"{cls.framework}: DETECT failed to strip the literal marker")
                leaked = F._run_case(cls, DETECT, F.ATTACKS["nl-redirect"])
                self.assertIsNotNone(leaked["executed"],
                                     f"{cls.framework}: DETECT unexpectedly stopped a paraphrase")


if __name__ == "__main__":
    unittest.main(verbosity=2)
