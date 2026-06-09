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

Reports default to a per-target path (``results/<target-slug>.sarif``) so that
scanning several targets in a row doesn't silently overwrite earlier reports;
pass ``--sarif-output`` to choose your own path.
"""

import os
import re
import subprocess
import sys
from pathlib import Path

from .reporting.owasp_metadata import OWASP_LLM_CATEGORIES

SUITE_DIR = Path(__file__).resolve().parent / "suite"

# When no --target is given the suite runs against this offline demo app.
DEFAULT_TARGET = "demo-vulnerable"


def target_slug(target: str | None) -> str:
    """Filesystem-safe slug for a target spec (e.g. ``openai:gpt-4o-mini`` ->
    ``openai-gpt-4o-mini``); falls back to the offline demo target."""
    slug = re.sub(r"[^a-z0-9]+", "-", (target or DEFAULT_TARGET).lower()).strip("-")
    return slug or DEFAULT_TARGET


def default_sarif_path(target: str | None) -> str:
    """Per-target default SARIF path so consecutive runs don't overwrite."""
    return f"results/{target_slug(target)}.sarif"


def print_banner():
    print("=" * 60)
    print("llmsectest - LLM Security Testing Framework")
    print("OWASP Top 10 for LLM Applications")
    print("=" * 60)


# How each OWASP-2025 category is tested, and what a developer must provide for
# the categories not yet covered — so the coverage map has no silent gaps.
_TESTABILITY = {
    "owasp_llm01": ("black-box", None),
    "owasp_llm02": ("black-box", None),
    "owasp_llm03": ("white-box", "requires the app's dependencies/SBOM"),
    "owasp_llm04": ("white-box", "requires training-data/model provenance"),
    "owasp_llm05": ("black-box", None),
    "owasp_llm06": ("black-box", None),
    "owasp_llm07": ("black-box", None),
    "owasp_llm08": ("white-box", "requires the app's RAG / vector store"),
    "owasp_llm09": ("black-box", "output-verification module planned"),
    "owasp_llm10": ("white-box", "requires the app's rate/resource limits"),
}


def check_coverage():
    """List the OWASP categories, which have probes, and what the rest need."""
    from .probes import covered_categories
    from .reporting.cvss import cvss_for_category, library_available

    covered = set(covered_categories())
    print_banner()
    print("\nOWASP LLM Top 10 (2025) — coverage & how each is tested:")
    print("-" * 78)
    for marker, category in sorted(OWASP_LLM_CATEGORIES.items()):
        modality, requires = _TESTABILITY.get(marker, ("?", None))
        if marker in covered:
            status = f"✓ probes   ({modality})"
        else:
            status = f"  planned  ({modality} — {requires or 'planned'})"
        cvss = cvss_for_category(marker)
        cvss_col = f"CVSS {cvss.base_score:>4} {cvss.severity}" if cvss else ""
        print(f"  [{status}] {category.id}: {category.name:<34s} {cvss_col}")
    print("-" * 78)
    print(f"\nImplemented: {len(covered)}/{len(OWASP_LLM_CATEGORIES)} categories.")
    print("CVSS v4.0 base scores per category (worst-case for the class); reported as")
    print(f"SARIF security-severity. cvss library installed: {library_available()} "
          "(baked scores used otherwise).")
    print("Black-box categories test your running app via  --target app:<url> .")
    print("White-box categories need app internals (deps/RAG/limits) and land per milestone.")


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


# Options that consume a following value in the ``--opt value`` (space-separated)
# form. Used so an option's value is never mistaken for a positional test path.
# Covers the llmsectest plugin's value-taking options plus common pytest ones.
_VALUE_OPTS = frozenset({
    # llmsectest plugin options
    "--sarif-output", "--report-formats", "--report-dir",
    "--security-policy", "--risk-threshold", "--min-coverage",
    # common pytest value-taking options
    "-k", "-m", "-p", "-o", "-c", "-n", "--rootdir", "--maxfail",
    "--deselect", "--ignore", "--confcutdir", "--report-log",
})


def _has_explicit_path(args: list) -> bool:
    """True if ``args`` contains a positional pytest test path.

    A token is a test path only if it (1) is not an option, (2) is not the value
    of a known value-taking option in ``--opt value`` form, and (3) refers to
    something pytest could actually collect — an existing file/dir, optionally
    with a ``::nodeid`` suffix. Both guards together close the documented
    ``--opt value`` footgun, where e.g. ``--report-dir tmp`` was mistaken for a
    positional path and silently skipped the packaged suite.
    """
    skip_next = False
    for a in args:
        if skip_next:
            skip_next = False
            continue
        if a.startswith("-"):
            if a in _VALUE_OPTS:
                skip_next = True
            continue
        if Path(a.split("::", 1)[0]).exists():
            return True
    return False


def run_suite(args: list, target: str | None) -> int:
    """Run the packaged probe suite (or an explicit path) with reporting on."""
    Path("results").mkdir(exist_ok=True)
    if target:
        os.environ["LLMSECTEST_TARGET"] = target

    # Default to the packaged suite when no explicit test path is given.
    test_path = [] if _has_explicit_path(args) else [str(SUITE_DIR)]

    # Inject a per-target SARIF path unless the user chose one explicitly.
    user_sarif = any(a == "--sarif-output" or a.startswith("--sarif-output=") for a in args)
    sarif_args = [] if user_sarif else [f"--sarif-output={default_sarif_path(target)}"]

    cmd = [
        sys.executable, "-m", "pytest",
        *sarif_args,
        *test_path,
        *args,
    ]
    print_banner()
    print(f"\nTarget: {target or f'{DEFAULT_TARGET} (offline demo)'}")
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

    args, target = _extract_target(args)

    if "--validate" in args:
        from .reporting import validate_sarif

        idx = args.index("--validate")
        nxt = args[idx + 1] if idx + 1 < len(args) else None
        # An explicit path wins; otherwise validate this target's default report.
        path = nxt if (nxt and not nxt.startswith("-")) else default_sarif_path(target)
        return 0 if validate_sarif(path) else 1

    return run_suite(args, target)


if __name__ == "__main__":
    sys.exit(main())
