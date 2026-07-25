"""Regression tests for the exfiltration / persistence labs (A9-A12).

Mirrors test_lab.py's structure: the headline VULN=exploited / FIXED=blocked
matrix, each new control pinned independently (so a future edit can't regress
one while the matrix still looks green), and legit-path tests proving the
hardened build doesn't break the happy path.

Run:  python -m unittest test_advanced
"""
import unittest

from lab.runtime import Context, SecurityPolicy, VULN, DETECT, FIXED
from lab.advanced import build_advanced_system
from lab import tools
from attacks_advanced import (ADVANCED_ATTACKS, CHAT_SECRET, ATTACKER,
                              attack9_image_exfil, attack10_spaiware_persistence,
                              attack11_delayed_tool_invocation)


def _adv_policy(**overrides):
    """A base 'honored + no structural controls' policy, so a single new control
    can be switched on in isolation to prove it alone stops the abuse."""
    base = dict(honor_untrusted_markers=True, enforce_handoff_allowlist=False,
                scrub_context_on_handoff=False, enforce_tool_capabilities=False,
                authed_registry=False, detect_handoff_loops=False,
                verify_agent_cards=False, sanitize_untrusted=False,
                enforce_egress_allowlist=False, provenance_on_memory=False,
                confirm_sensitive_after_taint=False)
    base.update(overrides)
    return SecurityPolicy("CUSTOM", **base)


class TestAdvancedMatrix(unittest.TestCase):
    def setUp(self):
        tools.reset_audit(); tools.reset_exfil(); tools.reset_memory()

    def test_vuln_every_attack_exploited(self):
        for label, fn in ADVANCED_ATTACKS:
            with self.subTest(attack=label):
                _, _, exploited = fn(VULN)
                self.assertTrue(exploited, f"{label} should be EXPLOITED on VULN")

    def test_fixed_every_attack_blocked(self):
        for label, fn in ADVANCED_ATTACKS:
            with self.subTest(attack=label):
                _, _, exploited = fn(FIXED)
                self.assertFalse(exploited, f"{label} should be blocked on FIXED")


class TestDetectIsInsufficient(unittest.TestCase):
    """The whole thesis: a static input filter is not enough. It catches the
    labelled/known-carrier variants but not the ones that don't depend on
    recognizable input."""

    def setUp(self):
        tools.reset_audit(); tools.reset_exfil(); tools.reset_memory()

    def test_detect_fails_on_visible_image_exfil(self):
        # Filtering the INPUT cannot close the OUTPUT channel: a visible injected
        # image still renders and leaks under DETECT.
        _, _, exploited = attack9_image_exfil(DETECT)
        self.assertTrue(exploited, "DETECT must NOT stop A9 — input filtering can't fix egress")

    def test_detect_fails_on_delayed_invocation(self):
        # The trigger word 'yes' is benign; the filter has nothing to catch.
        _, _, exploited = attack11_delayed_tool_invocation(DETECT)
        self.assertTrue(exploited, "DETECT must NOT stop A11 — the trigger is laundered")


class TestIndividualControls(unittest.TestCase):
    """Pin each NEW structural control on its own, with markers still honored so
    the injection fires and only the control under test can stop it."""

    def setUp(self):
        tools.reset_audit(); tools.reset_exfil(); tools.reset_memory()

    def test_egress_allowlist_alone_stops_exfil(self):
        # Injection fires (markers honored) but the allow-list closes the channel.
        pol = _adv_policy(enforce_egress_allowlist=True)
        _, _, exploited = attack9_image_exfil(pol)
        self.assertFalse(exploited)
        self.assertTrue(any(e[0] == "render_blocked" for e in tools.audit_log()))

    def test_memory_provenance_alone_stops_persistence(self):
        # Injection fires, but untrusted content is refused a memory write.
        pol = _adv_policy(provenance_on_memory=True)
        _, _, exploited = attack10_spaiware_persistence(pol)
        self.assertFalse(exploited)
        self.assertTrue(any(e[0] == "memory_write_blocked" for e in tools.audit_log()))

    def test_taint_confirmation_alone_stops_delayed_invocation(self):
        pol = _adv_policy(confirm_sensitive_after_taint=True)
        ctx, out, exploited = attack11_delayed_tool_invocation(pol)
        self.assertFalse(exploited)
        self.assertIn("CONFIRM_REQUIRED", out)

    def test_provenance_alone_stops_smuggled_and_visible_image(self):
        # honor_untrusted_markers off is content/encoding independent: it stops
        # both the visible (A9) and the invisible (A12) image with one rule.
        pol = _adv_policy(honor_untrusted_markers=False)
        from attacks_advanced import attack12_ascii_smuggling
        for fn in (attack9_image_exfil, attack12_ascii_smuggling):
            with self.subTest(fn=fn.__name__):
                tools.reset_exfil()
                _, _, exploited = fn(pol)
                self.assertFalse(exploited)


class TestLegitTasksStillWork(unittest.TestCase):
    """FIXED must not break the happy path."""

    def setUp(self):
        tools.reset_audit(); tools.reset_exfil(); tools.reset_memory()

    def test_user_image_to_allowlisted_host_still_renders(self):
        # A legitimate image the USER supplied, to an allow-listed CDN, must
        # still load on the hardened build.
        ctx = Context(user_id="u1001", role="customer")
        ctx.add_note("![logo](https://cdn.trustedbank.example/logo.png)", source="user")
        build_advanced_system(FIXED).run("AssistantAgent", "show the logo", ctx)
        hosts = [e["host"] for e in tools.exfil_log()]
        self.assertIn("cdn.trustedbank.example", hosts)

    def test_untainted_memory_write_still_persists(self):
        # A memory the user themselves asks to store (no untrusted content in
        # context) must still persist even with provenance_on_memory on.
        pol = _adv_policy(provenance_on_memory=True)
        ctx = Context(user_id="u1001", role="customer")
        ctx.add_note("[[TOOL:remember(favorite_color=blue)]]", source="user")
        build_advanced_system(pol).run("AssistantAgent", "remember my preference", ctx)
        stored = " ".join(t for t, _ in tools.load_memories("u1001"))
        self.assertIn("favorite_color=blue", stored)

    def test_benign_session_does_not_leak(self):
        for policy in (VULN, FIXED):
            with self.subTest(policy=policy.name):
                tools.reset_exfil(); tools.reset_memory()
                ctx = Context(user_id="u1001", role="customer")
                ctx.add_note(CHAT_SECRET, source="user")
                build_advanced_system(policy).run("AssistantAgent", "what's my balance?", ctx)
                self.assertEqual(tools.exfil_log(), [], "benign session must not exfiltrate")


if __name__ == "__main__":
    unittest.main(verbosity=2)
