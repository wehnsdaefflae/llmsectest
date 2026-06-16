"""CLI entry point for llmsectest.

Runs the packaged OWASP probe suite against a target model and emits a SARIF
report (plus optional HTML/JSON/Markdown).

Usage:
    python -m llmsectest [options] [test_path]

Examples:
    python -m llmsectest                                  # demo run (offline)
    python -m llmsectest --target openai:gpt-4o-mini      # scan a live model
    python -m llmsectest --target demo-defended           # offline hardened demo
    python -m llmsectest --target app:http://localhost:8000 --repo .  # app + its deps
    python -m llmsectest --repo .                          # add the LLM03 supply-chain scan
    python -m llmsectest --repo . --osv                    # + known-CVE lookup via OSV.dev
    python -m llmsectest --redteam-set jbb/harmful-behaviors.csv  # 100 JailbreakBench prompts (LLM01)
    python -m llmsectest --redteam-benign                  # + measure over-refusal (built-in twins)
    python -m llmsectest --redteam-benign jbb/benign-behaviors.csv  # over-refusal vs the 100 JBB twins
    python -m llmsectest --target app:http://localhost:8000 \\
        --app-prompt prompt.txt --app-secret "sk-canary-123" \\
        --app-action "ACTION: refund(" --app-action "ACTION: delete_user("
                          # deeper app scan: the dev-supplied inputs unlock LLM07/02/06

Application scans (``--target app:<url>``) always exercise LLM01 + LLM05
black-box. Three optional inputs unlock the remaining black-box categories:
``--app-prompt`` (the app's own system prompt — inline text or a file path)
enables LLM07, ``--app-secret`` (a real secret the app holds) enables LLM02,
and ``--app-action`` (a privileged tool/action signature; repeatable) enables
LLM06. Categories without their input are reported as skipped-with-reason.
    python -m llmsectest --report-formats=sarif,html,json,markdown
    python -m llmsectest --list-probes                    # list the corpus
    python -m llmsectest --check                          # OWASP coverage map
    python -m llmsectest --validate results/out.sarif     # validate a SARIF file
    python -m llmsectest --version                        # print the version

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

from . import envvars
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
    "owasp_llm03": ("white-box", "requires --repo <path> (dependency manifests)"),
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
    from .probes import SCANNER_CATEGORIES, covered_categories
    from .reporting.cvss import cvss_for_category, library_available

    covered = set(covered_categories())
    print_banner()
    print("\nOWASP LLM Top 10 (2025) — coverage & how each is tested:")
    print("-" * 78)
    for marker, category in sorted(OWASP_LLM_CATEGORIES.items()):
        modality, requires = _TESTABILITY.get(marker, ("?", None))
        if marker in covered:
            kind = "scan  " if marker in SCANNER_CATEGORIES else "probes"
            status = f"✓ {kind} ({modality})"
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
    print("App scans always exercise LLM01+LLM05; add --app-prompt / --app-secret /")
    print("--app-action (repeatable) to unlock LLM07 / LLM02 / LLM06 black-box.")
    print("White-box categories need app internals (deps/RAG/limits) and land per milestone.")
    print("LLM03: --repo <path> scans dependency manifests offline; adding --osv also")
    print("queries OSV.dev for known CVEs in exactly-pinned versions (networked, no key).")
    print("LLM01: --redteam-set <csv> runs the full JailbreakBench harmful set; "
          "--redteam-benign")
    print("[<csv>] measures the over-refusal (false-refusal) rate over the benign twins.")


def list_probes():
    """Print every probe case in the corpus."""
    from .probes import get_corpus
    from .probes.redteam import builtin_behaviors

    print_banner()
    print(f"\n{len(get_corpus())} probe cases:\n")
    current = None
    for case in get_corpus():
        if case.owasp != current:
            current = case.owasp
            print(f"\n{OWASP_LLM_CATEGORIES[case.owasp].id} — {OWASP_LLM_CATEGORIES[case.owasp].name}")
        print(f"  {case.severity:>8s}  {case.id}  ({case.technique})")
    from .probes.redteam import builtin_benign

    n = len(builtin_behaviors())
    print(f"\n+ {n} red-team jailbreak prompts under LLM01 (built-in starter set; "
          "--redteam-set <csv> runs the full JailbreakBench JBB-Behaviors set of 100)")
    print(f"+ {len(builtin_benign())} benign twins for the over-refusal metric "
          "(built-in; --redteam-benign [<csv>] reports the false-refusal rate, a")
    print("  usability signal kept separate from the security findings)")


def _extract_multi_opt(args: list, opt: str) -> tuple[list, list[str]]:
    """Pull every ``--opt VALUE`` / ``--opt=VALUE`` occurrence out of ``args``.

    Returns ``(remaining_args, values)`` with each flag and its value removed,
    so a value can never be mistaken for a positional pytest test path. Used for
    the llmsectest-level options (``--target``, ``--repo``, ``--app-action``…)
    that the CLI consumes before delegating the rest to pytest.
    """
    values: list[str] = []
    rest = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == opt:
            if i + 1 < len(args):
                values.append(args[i + 1])
            i += 2
            continue
        if a.startswith(opt + "="):
            values.append(a.split("=", 1)[1])
            i += 1
            continue
        rest.append(a)
        i += 1
    return rest, values


def _extract_opt(args: list, opt: str) -> tuple[list, str | None]:
    """Like :func:`_extract_multi_opt` for a single-valued option (last one wins)."""
    rest, values = _extract_multi_opt(args, opt)
    return rest, values[-1] if values else None


def _extract_target(args: list) -> tuple[list, str | None]:
    """Pull a --target value out of args; return (remaining_args, target)."""
    return _extract_opt(args, "--target")


def _extract_flag(args: list, flag: str) -> tuple[list, bool]:
    """Pull a boolean ``--flag`` out of ``args``; return (remaining_args, present)."""
    rest = [a for a in args if a != flag]
    return rest, len(rest) != len(args)


def _extract_opt_flag(args: list, opt: str) -> tuple[list, bool, str | None]:
    """Pull an *optional-valued* flag: ``--opt`` (bare), ``--opt=VAL`` or ``--opt VAL``.

    Returns ``(remaining_args, present, value)``. The space-form value is consumed
    only when the following token is not itself an option, so a bare ``--opt`` that
    precedes another flag (or ends the args) stays bare (``value=None``). Used for
    ``--redteam-benign``, which runs the built-in benign twins when bare and a
    supplied CSV when given a path.
    """
    rest: list = []
    present = False
    value: str | None = None
    i = 0
    while i < len(args):
        a = args[i]
        if a == opt:
            present = True
            if i + 1 < len(args) and not args[i + 1].startswith("-"):
                value = args[i + 1]
                i += 2
                continue
            i += 1
            continue
        if a.startswith(opt + "="):
            present = True
            value = a.split("=", 1)[1]
            i += 1
            continue
        rest.append(a)
        i += 1
    return rest, present, value


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


# Against a real app endpoint (`app:<url>`) only the attack-side-marker categories
# transfer black-box: the canary-based LLM02/06/07 corpus cases would pass vacuously
# (they probe for a secret/persona a real app doesn't hold). So scope an app run to
# the modules that genuinely test an unknown app; the application-mode module adds
# LLM02/06/07 back when the dev supplies --app-secret/--app-action/--app-prompt.
_APP_SUITE_MODULES = (
    "test_llm01_prompt_injection.py",
    "test_redteam_jailbreaks.py",  # LLM01 red-team: does the app refuse harmful asks? (black-box)
    "test_llm05_improper_output_handling.py",
    "test_application_mode.py",  # LLM02/06/07 from dev-supplied inputs; skips otherwise
    "test_llm03_supply_chain.py",  # white-box repo scan; self-skips without --repo
    "test_owasp_coverage.py",  # enumerates all 10 — unimplemented ones skip "not yet implemented"
)


def _is_app_target(target: str | None) -> bool:
    return bool(target) and target.startswith("app:")


def _print_coverage_footer(target: str | None) -> None:
    """Surface which OWASP categories this run did and did not exercise — so a
    category is never silently left untested."""
    def cid(marker: str) -> str:
        return marker.replace("owasp_llm", "LLM")

    osv_on = bool(os.environ.get(envvars.OSV))
    print("\n" + "-" * 68)
    if _is_app_target(target):
        from .probes.application import app_coverage

        # Reflect the dev-supplied inputs (--app-prompt/--app-secret/--app-action),
        # so the footer reports exactly what this run could and could not reach.
        prompt, secret, actions = envvars.app_inputs_from_env()
        cov = app_coverage(prompt, known_secret=secret, forbidden_actions=actions or None)
        exercised = [c.owasp for c in cov if c.exercised]
        skipped = [(c.owasp, c.reason) for c in cov if not c.exercised]
        print(f"Application-scan coverage — {len(exercised)}/10 OWASP categories "
              "exercised black-box. No silent gaps:")
    else:
        from .probes import SCANNER_CATEGORIES, covered_categories

        covered = set(covered_categories())
        has_repo = bool(os.environ.get(envvars.REPO))
        exercised, skipped = [], []
        for m in sorted(OWASP_LLM_CATEGORIES):
            if m in covered:
                # A scanner category only fires when its input (a repo) is supplied.
                if m in SCANNER_CATEGORIES and not has_repo:
                    skipped.append((m, "needs --repo <path> to scan dependencies"))
                else:
                    exercised.append(m)
            else:
                skipped.append(
                    (m, f"not yet implemented ({_TESTABILITY[m][0]} — "
                        f"{_TESTABILITY[m][1] or 'planned'})")
                )
        print(f"Coverage this run — {len(exercised)}/10 OWASP categories exercised. "
              "No silent gaps:")
    print("  exercised:    " + ", ".join(cid(m) for m in exercised))
    for marker, reason in skipped:
        print(f"  not exercised {cid(marker)}: {reason}")
    if "owasp_llm01" in exercised:
        # Surface the LLM01 red-team depth (the JailbreakBench module), not just
        # that LLM01 ran — so the red-team coverage is never a silent gap. Count
        # only the in-memory built-in set; name an external set by its path (the
        # suite run itself reports how many of it ran) — the footer never does IO.
        from .probes.redteam import builtin_behaviors

        rt_path = os.environ.get(envvars.REDTEAM_SET) or None
        depth = (f"red-team set {rt_path}" if rt_path
                 else f"{len(builtin_behaviors())} built-in red-team jailbreak prompts")
        print(f"  LLM01 depth:  marker-injection corpus + {depth}; "
              "--redteam-set <csv> runs the full JailbreakBench JBB-Behaviors set")
    if not _is_app_target(target) and "owasp_llm03" in exercised:
        # Surface the depth of the LLM03 scan too, not just that it ran.
        print("  LLM03 depth:  structural scan "
              + ("+ OSV.dev known-CVE lookup (--osv)" if osv_on
                 else "only — add --osv for a known-CVE lookup (networked, no key)"))
    print("Full map: llmsectest --check")
    print("-" * 68)


def _print_over_refusal(target: str | None, path: str | None) -> None:
    """Run the JBB benign twins against the target and print the false-refusal rate.

    This is a *usability* measurement — the specificity control for the LLM01
    refusal oracle — kept deliberately separate from the SARIF security findings:
    over-refusing a harmless request is a product-quality defect, not an OWASP
    vulnerability, so it never counts as a finding or changes the exit code.
    """
    from .probes import measure_false_refusal, resolve_target

    adapter = resolve_target(target or DEFAULT_TARGET)
    report = measure_false_refusal(adapter, path)
    source = f"set {path}" if path else "built-in starter set"
    print("\n" + "-" * 68)
    print(f"Over-refusal (benign-twin) measurement — {report.total} benign requests "
          f"({source}):")
    print(f"  false-refusal rate: {report.rate:.0%} "
          f"({report.refused}/{report.total} benign requests refused)")
    for o in report.over_refusals:
        print(f"    over-refused: {o.case.id} ({o.case.technique})")
    print("  A benign twin is a harmless request matched to a red-team behavior; refusing")
    print("  it is an over-refusal — a usability defect, not a security finding. It is the")
    print("  specificity control for the refusal oracle (string-matching; a classifier")
    print("  oracle is the documented upgrade). Not counted in findings or the exit code.")
    print("-" * 68)


def run_suite(args: list, target: str | None, repo: str | None = None,
              osv: bool = False, redteam_set: str | None = None,
              app_prompt: str | None = None,
              app_secret: str | None = None,
              app_actions: tuple[str, ...] = (),
              redteam_benign: bool = False,
              redteam_benign_set: str | None = None) -> int:
    """Run the packaged probe suite (or an explicit path) with reporting on.

    ``repo`` (from ``--repo``) enables the white-box LLM03 supply-chain scan
    against that project's dependency manifests, alongside the model/app probes.
    ``osv`` (from ``--osv``) additionally queries OSV.dev for known CVEs in the
    repo's exactly-pinned dependency versions (networked, opt-in).
    ``redteam_set`` (from ``--redteam-set``) points the LLM01 red-team module at
    a JailbreakBench JBB-Behaviors CSV; without it the built-in starter set runs.
    ``app_prompt``/``app_secret``/``app_actions`` (from ``--app-prompt``/
    ``--app-secret``/``--app-action``) are the dev-supplied application inputs
    that unlock LLM07/LLM02/LLM06 against an ``app:<url>`` target.
    ``redteam_benign`` (from ``--redteam-benign``) additionally measures the
    target's **false-refusal rate** over the JBB benign twins after the security
    suite — a usability metric reported separately, never a SARIF finding.
    """
    Path("results").mkdir(exist_ok=True)
    # Only-when-supplied env vars travel from the CLI to the suite subprocess;
    # an absent value must leave the variable unset (the suite treats unset as
    # "use the default") — see envvars for the contract.
    suite_env = {
        envvars.TARGET: target,
        envvars.REPO: repo,
        envvars.OSV: "1" if osv else None,
        envvars.REDTEAM_SET: redteam_set,
        envvars.APP_PROMPT: app_prompt,
        envvars.APP_SECRET: app_secret,
        envvars.APP_ACTIONS: (
            envvars.ACTIONS_SEPARATOR.join(app_actions) if app_actions else None
        ),
    }
    for name, value in suite_env.items():
        if value:
            os.environ[name] = value

    # Default to the packaged suite when no explicit test path is given; for an app
    # endpoint, scope to the categories that actually transfer black-box.
    if _has_explicit_path(args):
        test_path = []
    elif _is_app_target(target):
        test_path = [str(SUITE_DIR / m) for m in _APP_SUITE_MODULES]
    else:
        test_path = [str(SUITE_DIR)]

    # Inject a per-target SARIF path unless the user chose one explicitly.
    user_sarif = any(a == "--sarif-output" or a.startswith("--sarif-output=") for a in args)
    sarif_args = [] if user_sarif else [f"--sarif-output={default_sarif_path(target)}"]

    cmd = [
        sys.executable, "-m", "pytest",
        "-rs",  # always print skip reasons, so "not yet implemented" categories are visible
        *sarif_args,
        *test_path,
        *args,
    ]
    print_banner()
    print(f"\nTarget: {target or f'{DEFAULT_TARGET} (offline demo)'}")
    print(f"Running: {' '.join(cmd)}\n")
    rc = subprocess.call(cmd)
    _print_coverage_footer(target)
    if redteam_benign:
        _print_over_refusal(target, redteam_benign_set)
    return rc


def main():
    args = sys.argv[1:]

    if "--help" in args or "-h" in args:
        print(__doc__)
        return 0
    if "--version" in args:
        from importlib.metadata import PackageNotFoundError, version

        try:
            print(f"llmsectest {version('llmsectest')}")
        except PackageNotFoundError:
            print("llmsectest (not installed — running from source)")
        return 0
    if "--check" in args:
        check_coverage()
        return 0
    if "--list-probes" in args:
        list_probes()
        return 0

    args, target = _extract_target(args)
    args, repo = _extract_opt(args, "--repo")
    args, osv = _extract_flag(args, "--osv")
    args, redteam_set = _extract_opt(args, "--redteam-set")
    args, redteam_benign, redteam_benign_set = _extract_opt_flag(args, "--redteam-benign")
    args, app_prompt = _extract_opt(args, "--app-prompt")
    args, app_secret = _extract_opt(args, "--app-secret")
    args, app_actions = _extract_multi_opt(args, "--app-action")

    if redteam_set and not Path(redteam_set).is_file():
        # Fail loudly rather than silently falling back to the built-in set.
        print(f"error: --redteam-set file not found: {redteam_set}", file=sys.stderr)
        return 2
    if redteam_benign_set and not Path(redteam_benign_set).is_file():
        # A path was given but doesn't exist — don't silently use the built-in set.
        print(f"error: --redteam-benign file not found: {redteam_benign_set}",
              file=sys.stderr)
        return 2

    if (app_prompt or app_secret or app_actions) and not _is_app_target(target):
        # Silently ignoring an app input would be a silent coverage gap.
        print("error: --app-prompt/--app-secret/--app-action describe a running "
              "application and require --target app:<url> "
              f"(got {target or 'the offline demo'})", file=sys.stderr)
        return 2
    if app_prompt and Path(app_prompt).is_file():
        # System prompts are long and multiline — accept a file path too.
        app_prompt = Path(app_prompt).read_text(encoding="utf-8")

    if "--validate" in args:
        from .reporting import validate_sarif

        idx = args.index("--validate")
        nxt = args[idx + 1] if idx + 1 < len(args) else None
        # An explicit path wins; otherwise validate this target's default report.
        path = nxt if (nxt and not nxt.startswith("-")) else default_sarif_path(target)
        return 0 if validate_sarif(path) else 1

    return run_suite(args, target, repo, osv, redteam_set=redteam_set,
                     app_prompt=app_prompt, app_secret=app_secret,
                     app_actions=tuple(app_actions),
                     redteam_benign=redteam_benign,
                     redteam_benign_set=redteam_benign_set)


if __name__ == "__main__":
    sys.exit(main())
