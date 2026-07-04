"""Measurement harness — turns the lab's binary EXPLOITED/blocked into numbers.

Run:  python metrics.py

Produces four measured views:
  1. BLOCK-RATE matrix   — for each attack family, the fraction of its many
     phrasings (marker / NL / obfuscated / semantic) that each policy blocks.
     Shows VULN ~ leaks everything, DETECT leaks the paraphrases its static
     filter never learned, FIXED blocks every phrasing (content-independent).
  2. DETECTOR false positives — how often benign traffic *looks like* an
     instruction to the model's comprehension vs the static filter.
  3. FIXED usability       — FIXED must not break the happy path; fraction of
     benign tasks whose legitimate outcome still succeeds.
  4. CONTROL x ATTACK      — starting from all-controls-on, knock out one
     control at a time and see which of the 8 marker attacks resurface. Reveals
     which single control is load-bearing vs where defense-in-depth holds.
"""
import dataclasses
from collections import defaultdict

from lab.runtime import VULN, DETECT, FIXED
from lab import nlp
from lab.agents import build_system
from lab.runtime import Context
from variants import VARIANTS, CATEGORIES, BENIGN
from attacks import ATTACKS

POLICIES = [VULN, DETECT, FIXED]


def block_rate_matrix():
    print("=" * 78)
    print("1. BLOCK-RATE per attack family  (blocked / total phrasings)")
    print("=" * 78)
    print(f"{'attack family':<26}{'VULN':>15}{'DETECT':>17}{'FIXED':>17}")
    print("-" * 78)
    totals = {p.name: [0, 0] for p in POLICIES}
    for label, (runner, payloads) in VARIANTS.items():
        cells = []
        for pol in POLICIES:
            blocked = sum(0 if runner(pl, pol) else 1 for pl in payloads)
            n = len(payloads)
            totals[pol.name][0] += blocked
            totals[pol.name][1] += n
            cells.append(f"{blocked}/{n} ({100*blocked//n:3d}%)")
        print(f"{label:<26}{cells[0]:>15}{cells[1]:>17}{cells[2]:>17}")
    print("-" * 78)
    agg = []
    for pol in POLICIES:
        b, n = totals[pol.name]
        agg.append(f"{b}/{n} ({100*b//n:3d}%)")
    print(f"{'ALL VARIANTS':<26}{agg[0]:>15}{agg[1]:>17}{agg[2]:>17}")
    print(f"   (A4/A7/A8 are registry/federation attacks with no wording to")
    print(f"    paraphrase, so they don't appear in this phrasing sweep.)")
    print()


def leak_anatomy():
    """Where DETECT's misses live, and why they don't all count against a filter.

    Splitting the leaks by category separates the two *reasons* a static filter
    fails: obfuscation (a real de-obfuscating guard would recover these) and
    semantics (paraphrase — no filter closes it). The honest ceiling for ANY
    pure input filter is 'everything but the semantic bucket'.
    """
    print("=" * 78)
    print("1b. LEAK ANATOMY  (DETECT = a byte-level static filter)")
    print("=" * 78)
    cat_total, cat_blocked = defaultdict(int), defaultdict(int)
    for label, (runner, payloads) in VARIANTS.items():
        for pl, cat in zip(payloads, CATEGORIES[label]):
            cat_total[cat] += 1
            if not runner(pl, DETECT):
                cat_blocked[cat] += 1
    order = ["marker", "filter-plain", "filter-obf", "semantic"]
    notes = {
        "marker": "labelled -> always stripped",
        "filter-plain": "in the filter's vocabulary",
        "filter-obf": "recoverable: real guards normalize obfuscation",
        "semantic": "irreducible: no filter closes paraphrase",
    }
    print(f"{'category':<15}{'count':>7}{'DETECT blocks':>16}   note")
    print("-" * 78)
    for cat in order:
        n, b = cat_total[cat], cat_blocked[cat]
        print(f"{cat:<15}{n:>7}{f'{b}/{n} ({100*b//n:3d}%)':>16}   {notes[cat]}")
    total = sum(cat_total.values())
    semantic = cat_total["semantic"]
    detect_b = sum(cat_blocked.values())
    ceiling = total - semantic          # markers + all filter-vocab (any surface)
    print("-" * 78)
    print(f"   DETECT, this byte-level filter        : {detect_b}/{total} ({100*detect_b//total}%)")
    print(f"   ceiling for a PERFECT de-obfuscating filter: {ceiling}/{total} ({100*ceiling//total}%)")
    print(f"   irreducible semantic leak (no filter helps): {semantic}/{total} ({100*semantic//total}%)")
    print(f"   FIXED (provenance + least privilege)  : {total}/{total} (100%)")
    print()


def detector_false_positives():
    print("=" * 78)
    print("2. DETECTOR false positives on benign traffic")
    print("=" * 78)
    llm_fp = sum(1 for msg in BENIGN if nlp.detect(msg, "llm"))
    flt_fp = sum(1 for msg in BENIGN if nlp.detect(msg, "filter"))
    n = len(BENIGN)
    print(f"   model comprehension flags benign as instruction : {llm_fp}/{n}")
    print(f"   static filter        flags benign as instruction : {flt_fp}/{n}")
    print("   NOTE: 0 FP here is generous to DETECT - a real classifier buys")
    print("   recall with precision, so a fielded filter's ceiling is BELOW the")
    print("   de-obfuscation ceiling above, not at it.")
    print()


def fixed_usability():
    print("=" * 78)
    print("3. FIXED usability - benign traffic behaves identically to VULN")
    print("   (hardening must be invisible to legitimate users)")
    print("=" * 78)
    ok = 0
    for msg in BENIGN:
        v = build_system(VULN).run("TriageAgent", msg, Context(user_id="u1001", role="customer"))
        f = build_system(FIXED).run("TriageAgent", msg, Context(user_id="u1001", role="customer"))
        same = (v == f)
        ok += same
        if not same:
            print(f"   REGRESSED: {msg!r}\n      VULN  -> {v!r}\n      FIXED -> {f!r}")
    print(f"   benign responses unchanged under FIXED: {ok}/{len(BENIGN)}")
    print()


CONTROLS = [
    "honor_untrusted_markers", "enforce_handoff_allowlist", "scrub_context_on_handoff",
    "enforce_tool_capabilities", "authed_registry", "detect_handoff_loops",
    "verify_agent_cards",
]


def _knock_out(control):
    """FIXED with a single control reverted to its permissive value."""
    permissive = True if control == "honor_untrusted_markers" else False
    return dataclasses.replace(FIXED, name=f"-{control}", **{control: permissive})


def control_attack_matrix():
    print("=" * 78)
    print("4. CONTROL x ATTACK - which attacks resurface when ONE control is removed")
    print("   (all controls on = every attack blocked; 'X' = attack fires again)")
    print("=" * 78)
    short = {c: c.replace("_", " ")[:14] for c in CONTROLS}
    header = "control removed \\ attack".ljust(26) + "".join(f"{f'A{i+1}':>4}" for i in range(len(ATTACKS)))
    print(header)
    print("-" * len(header))
    for control in CONTROLS:
        pol = _knock_out(control)
        row = "".join("  X " if fn(pol)[2] else "  . " for _, fn in ATTACKS)
        print(f"{short[control]:<26}{row}")
    print("-" * len(header))
    print("   '.' = still blocked by the remaining controls (defense in depth)")
    print("   a column with a single 'X' => that attack has ONE load-bearing control")
    print()


def main():
    block_rate_matrix()
    leak_anatomy()
    detector_false_positives()
    fixed_usability()
    control_attack_matrix()


if __name__ == "__main__":
    main()
