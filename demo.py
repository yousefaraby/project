"""Demo runner: executes all incident response scenarios, prints traces, and displays summary table."""
from __future__ import annotations

import sys
from app.services.scenarios import SCENARIOS, run_scenario


def format_trace_entry(idx: int, entry: dict) -> str:
    step = entry.get("step", "").ljust(22)
    stype = f"[{entry.get('type', '')}]".ljust(11)
    inp = str(entry.get("input", "")).replace("\n", " ")[:35].ljust(35)
    out = str(entry.get("output", "")).replace("\n", " ")[:40]
    dur = f"({entry.get('duration_ms', 0):.1f}ms)"
    branch = f"[{entry.get('branch')}]" if entry.get("branch") else ""
    return f"  [{idx:02d}] {step} {stype} {inp} -> {out} {branch} {dur}"


def run_demo() -> int:
    print("\n" + "=" * 90)
    print(" AI IT INCIDENT RESPONSE AGENT - MOCK MODE DEMONSTRATION")
    print("=" * 90)

    summary_rows = []
    all_passed = True

    # Set stdout encoding if possible
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    for case_id in SCENARIOS:
        res = run_scenario(case_id)
        status = res["status"]
        if status != "PASS":
            all_passed = False

        summary_rows.append((
            case_id,
            res["title"][:42],
            str(res["expected_outcome"]),
            str(res["actual_outcome"]),
            status,
        ))

        print(f"\n>>> [{case_id}] {res['title']}")
        print(f"    Expected: {res['expected_outcome']} | Actual: {res['actual_outcome']} | Result: {status}")
        print("    Trace:")
        for idx, entry in enumerate(res.get("trace", []), start=1):
            print(format_trace_entry(idx, entry))

        print("    Checks:")
        for chk, ok in res.get("checks", {}).items():
            symbol = "OK" if ok else "FAIL"
            print(f"      [{symbol}] {chk}")

    # Summary Table
    print("\n" + "=" * 90)
    print(" SCENARIO EXECUTION SUMMARY TABLE")
    print("=" * 90)
    header = f"{'Case':<6} | {'Scenario Title':<44} | {'Expected':<20} | {'Actual':<20} | {'Status':<6}"
    print(header)
    print("-" * 90)
    for cid, title, exp, act, stat in summary_rows:
        print(f"{cid:<6} | {title:<44} | {exp:<20} | {act:<20} | {stat:<6}")
    print("=" * 90)

    total = len(summary_rows)
    passed_count = sum(1 for r in summary_rows if r[4] == "PASS")
    print(f"\nFinal Result: {passed_count}/{total} scenarios PASSED.\n")

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(run_demo())
