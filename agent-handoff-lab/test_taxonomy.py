"""Standardization guardrails: assert the taxonomy stays complete and well-formed.

If a new exploit is added without its standard mappings, or an identifier is
malformed, these tests fail — the standardization can't silently rot.

Run:  python -m unittest test_taxonomy
"""
import re
import unittest

from lab.taxonomy import TAXONOMY, BY_ID, KILL_CHAIN
from attacks import ATTACKS
from attacks_advanced import ADVANCED_ATTACKS

OWASP_RE = re.compile(r"^LLM\d{2}:2025 .+")
ATLAS_RE = re.compile(r"^AML\.T\d{4}(\.\d{3})? .+")
CWE_RE = re.compile(r"^CWE-\d+ .+")
SEVERITIES = {"informational", "Low", "Medium", "High", "Critical"}


class TestTaxonomyComplete(unittest.TestCase):
    def test_every_exploit_is_mapped(self):
        # Both attack modules together define A1..A12; each must have a mapping.
        labels = [l for l, _ in ATTACKS] + [l for l, _ in ADVANCED_ATTACKS]
        ids = {l.split()[0] for l in labels}
        self.assertEqual(ids, set(BY_ID), "taxonomy IDs must match the defined exploits exactly")
        self.assertEqual(len(TAXONOMY), 12)

    def test_no_duplicate_ids(self):
        ids = [m.id for m in TAXONOMY]
        self.assertEqual(len(ids), len(set(ids)))

    def test_each_entry_has_required_standards(self):
        for m in TAXONOMY:
            with self.subTest(exploit=m.id):
                self.assertTrue(m.owasp, f"{m.id} missing OWASP mapping")
                self.assertTrue(m.atlas, f"{m.id} missing ATLAS mapping")
                self.assertTrue(m.cwe, f"{m.id} missing CWE mapping")
                self.assertTrue(m.control, f"{m.id} missing control")
                self.assertTrue(m.source, f"{m.id} missing source")
                self.assertIn(m.severity, SEVERITIES)
                self.assertIn(m.kill_chain, KILL_CHAIN)


class TestIdentifiersWellFormed(unittest.TestCase):
    def test_owasp_ids(self):
        for m in TAXONOMY:
            for x in m.owasp:
                self.assertRegex(x, OWASP_RE, f"{m.id}: bad OWASP id {x!r}")

    def test_atlas_ids(self):
        for m in TAXONOMY:
            for x in m.atlas:
                self.assertRegex(x, ATLAS_RE, f"{m.id}: bad ATLAS id {x!r}")

    def test_cwe_ids(self):
        for m in TAXONOMY:
            for x in m.cwe:
                self.assertRegex(x, CWE_RE, f"{m.id}: bad CWE id {x!r}")

    def test_cve_ids_well_formed_when_present(self):
        for m in TAXONOMY:
            for x in m.cve:
                self.assertRegex(x, re.compile(r"^CVE-\d{4}-\d+"), f"{m.id}: bad CVE {x!r}")


class TestStandardsRenders(unittest.TestCase):
    def test_markdown_builds_and_mentions_every_exploit(self):
        from lab.taxonomy import build_standards_md
        md = build_standards_md()
        for m in TAXONOMY:
            self.assertIn(m.id, md)
            self.assertIn(m.name, md)
        self.assertIn("MITRE ATLAS", md)
        self.assertIn("OWASP", md)


if __name__ == "__main__":
    unittest.main(verbosity=2)
