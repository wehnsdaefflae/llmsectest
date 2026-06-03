"""CLI entry point for llmsectest.

Runs the packaged OWASP probe suite against a target model and emits a SARIF
report (plus optional HTML/JSON/Markdown).

Usage:
    python -m llmsectest [options] [test_path]

Examples:
    python -m llmsectest                                  # demo run (offline)
    python -m llmsectest --target openai:gpt-4o-mini      # scan a live model
    python -m llmsectest --target demo-defended           # offline hardened demo
    python -m llmsectest --report-formats=sarif,html,json,markdown
    python -m llmsectest --list-probes                    # list the corpus
    python -m llmsectest --check                          # OWASP coverage map
    python -m llmsectest --validate results/out.sarif     # validate a SARIF file

A failing probe is a *finding*: a non-zero exit means the target is vulnerable.
With no --target, the suite runs against a built-in offline demo app.
"""

import os
import subprocess
import sys
from pathlib import Path

from .reporting.owasp_metadata import OWASP_LLM_CATEGORIES

SUITE_DIR = Path(__file__).resolve().parent / "suite"


def print_banner():
    print("=" * 60)
    print("llmsectest - LLM Security Testing Framework")
    print("OWASP Top 10 for LLM Applications")
    print("=" * 60)


def check_coverage():
    """List the OWASP categories and which ones have probes."""
    from .probes import covered_categories

    covered = set(covered_categories())
    print_banner()
    print("\nOWASP LLM Top 10 — probe coverage:")
    print("-" * 60)
    for marker, category in sorted(OWASP_LLM_CATEGORIES.items()):
        mark = "✓ probes" if marker in covered else "  planned"
        print(f"  [{mark}] {category.id}: {category.name}")
    print("-" * 60)
    print(f"\nImplemented: {len(covered)}/{len(OWASP_LLM_CATEGORIES)} categories")


def list_probes():
    """Print every probe case in the corpus."""
    from .probes import get_corpus

    print_banner()
    print(f"\n{len(get_corpus())} probe cases:\n")
    current = None
    for case in get_corpus():
        if case.owasp != current:
            current = case.owasp
            print(f"\n{OWASP_LLM_CATEGORIES[case.owasp].id} — {OWASP_LLM_CATEGORIES[case.owasp].name}")
        print(f"  {case.severity:>8s}  {case.id}  ({case.technique})")


def _extract_target(args: list) -> tuple[list, str | None]:
    """Pull a --target value out of args; return (remaining_args, target)."""
    target = None
    rest = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--target":
            target = args[i + 1] if i + 1 < len(args) else None
            i += 2
            continue
        if a.startswith("--target="):
            target = a.split("=", 1)[1]
            i += 1
            continue
        rest.append(a)
        i += 1
    return rest, target


def run_suite(args: list, target: str | None) -> int:
    """Run the packaged probe suite (or an explicit path) with reporting on."""
    Path("results").mkdir(exist_ok=True)
    if target:
        os.environ["LLMSECTEST_TARGET"] = target

    # Default to the packaged suite when no explicit test path is given.
    has_path = any(not a.startswith("-") for a in args)
    test_path = [] if has_path else [str(SUITE_DIR)]

    cmd = [
        sys.executable, "-m", "pytest",
        "--sarif-output=results/pytest-results.sarif",
        *test_path,
        *args,
    ]
    print_banner()
    print(f"\nTarget: {os.environ.get('LLMSECTEST_TARGET', 'demo-vulnerable (offline demo)')}")
    print(f"Running: {' '.join(cmd)}\n")
    return subprocess.call(cmd)


def main():
    args = sys.argv[1:]

    if "--help" in args or "-h" in args:
        print(__doc__)
        return 0
    if "--check" in args:
        check_coverage()
        return 0
    if "--list-probes" in args:
        list_probes()
        return 0
    if "--validate" in args:
        from .reporting import validate_sarif

        idx = args.index("--validate")
        path = args[idx + 1] if idx + 1 < len(args) else "results/pytest-results.sarif"
        return 0 if validate_sarif(path) else 1

    args, target = _extract_target(args)
    return run_suite(args, target)


if __name__ == "__main__":
    sys.exit(main())
