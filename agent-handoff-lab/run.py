"""Driver: run all eight handoff exploits against VULN and FIXED, print traces
and a result matrix.

    python run.py            # both builds + summary matrix
    python run.py vuln       # only the vulnerable build (verbose traces)
    python run.py fixed      # only the hardened build (verbose traces)
"""
import sys

from lab.runtime import VULN, FIXED
from attacks import ATTACKS


def run_build(policy, verbose=True):
    print("\n" + "#" * 74)
    print(f"# BUILD: {policy.name}")
    print("#" * 74)
    results = {}
    for label, fn in ATTACKS:
        ctx, out, exploited = fn(policy)
        results[label] = exploited
        verdict = "EXPLOITED" if exploited else "blocked"
        # For VULN we expect EXPLOITED; for FIXED we expect blocked.
        good = (exploited and policy.name == "VULN") or (not exploited and policy.name == "FIXED")
        tag = "as-expected" if good else "UNEXPECTED"
        print(f"\n=== {label}  ->  {verdict}  [{tag}] ===")
        if verbose:
            for line in ctx.trace:
                print("   " + line)
            print(f"   RESULT: {out}")
    return results


def matrix(vuln_res, fixed_res):
    print("\n" + "=" * 74)
    print("RESULT MATRIX  (want: VULN=EXPLOITED, FIXED=blocked)")
    print("=" * 74)
    print(f"{'attack':<34}{'VULN':<14}{'FIXED':<14}")
    print("-" * 74)
    for label, _ in ATTACKS:
        v = "EXPLOITED" if vuln_res[label] else "blocked"
        f = "EXPLOITED" if fixed_res[label] else "blocked"
        print(f"{label:<34}{v:<14}{f:<14}")


def main():
    arg = sys.argv[1].lower() if len(sys.argv) > 1 else "both"
    if arg == "vuln":
        run_build(VULN)
    elif arg == "fixed":
        run_build(FIXED)
    else:
        v = run_build(VULN, verbose=False)
        f = run_build(FIXED, verbose=False)
        matrix(v, f)


if __name__ == "__main__":
    main()
