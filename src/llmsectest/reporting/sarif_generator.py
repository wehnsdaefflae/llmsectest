"""SARIF v2.1.0 report generator for pytest results."""

import hashlib
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .. import envvars
from .compliance_mapper import (
    get_compliance_mappings,
    get_compliance_summary,
    get_frameworks_covered,
)
from .constants import SARIF_SEVERITY_MAP, SEVERITY_SCORES
from .cvss import cvss_for_category
from .models import TestResult
from .owasp_metadata import (
    OWASP_LLM_CATEGORIES,
    get_cwe_tags,
    get_owasp_category,
    get_owasp_markers_from_test,
    get_security_tags,
    resolve_edition,
)
from .statistics import attack_tally, exercised_categories, withstood_probes

#: How much of a withstood probe's reply travels into the SARIF result. The full reply
#: lives in the pytest run, but publishing every one of 30+ transcripts in full can turn
#: a small report into a large one for a defended target; issue #21 names report size as
#: the objection and accepts a cap as the answer. The cap is disclosed per row
#: (``reply_truncated`` / ``reply_characters``) and in the run property
#: ``withstood_transcripts``, so a truncated transcript can never be mistaken for a
#: complete one.
WITHSTOOD_REPLY_LIMIT = 4000

#: The OWASP LLM Top 10 taxonomy declared on every run. Consumers key on this
#: guid to group and filter results by category across runs, so it is a fixed
#: constant, never derived from the run or the edition: changing it would split
#: every consumer's history in two.
OWASP_TAXONOMY_GUID = "75fe736f-2c9f-4f09-8c70-f22a263bfe90"
OWASP_TAXONOMY_NAME = "OWASP LLM Top 10"


def _owasp_taxonomy() -> dict[str, Any]:
    """The OWASP LLM Top 10 taxonomy, in the edition this report publishes under.

    Every category is declared, not just the ones this run exercised: a taxonomy
    is the classification system, and results reference the subset they belong
    to. Taxon ids are the same edition-adjusted ids the results' properties
    already publish, so a result's taxa reference always matches a declared taxon.
    """
    edition = resolve_edition()
    taxa = []
    for marker in OWASP_LLM_CATEGORIES:
        category = get_owasp_category(marker)
        taxon: dict[str, Any] = {
            "id": category.id,
            "name": category.name,
            "shortDescription": {"text": category.description},
            "fullDescription": {"text": category.full_description},
        }
        if category.references:
            taxon["helpUri"] = category.references[0]
        taxa.append(taxon)
    return {
        "guid": OWASP_TAXONOMY_GUID,
        "name": OWASP_TAXONOMY_NAME,
        "version": edition,
        "taxa": taxa,
    }


def _taxa_reference(category: Any) -> list[dict[str, Any]] | None:
    """The ``taxa`` entry pointing a result at its OWASP category, or None."""
    if category is None:
        return None
    return [
        {
            "id": category.id,
            "toolComponent": {"name": OWASP_TAXONOMY_NAME, "guid": OWASP_TAXONOMY_GUID},
        }
    ]


def _as_int(value: Any) -> int | None:
    """Coerce a recorded ``output_tokens`` property to ``int``, else ``None``.

    The value arrives from ``pytest`` ``user_properties`` (recorded by the probe
    fixture) and is normally already an ``int``; guard against a stray ``None`` or
    a non-numeric string so the cost plumbing never raises on a malformed record.
    """
    if isinstance(value, bool):  # bool is an int subclass, never a token count
        return None
    if isinstance(value, (int, float)):
        return int(value)
    return None


def _as_float(value: Any) -> float | None:
    """Coerce a recorded elapsed-seconds property to ``float``, else ``None``.

    Same contract and same guard as :func:`_as_int`, kept separate because rounding a
    latency to a whole second would throw away the only digit that distinguishes a fast
    probe from a slow one on a local model. A negative value is dropped rather than
    reported: wall-clock seconds cannot be negative, so it is a malformed record.
    """
    if isinstance(value, bool):  # bool is an int subclass, never a duration
        return None
    if isinstance(value, (int, float)) and value >= 0:
        return float(value)
    return None


#: The key our result identity travels under. GitHub's SARIF reference marks
#: ``partialFingerprints`` *Required* and uses it to decide whether a result in this
#: upload is the same finding as one in the last: without it, "a new alert will be
#: created, and the old one will be closed", so a scan closes the previous scan's
#: alerts and an alert somebody dismissed as a false positive comes back.
#:
#: Its documented fallback does not reach us. ``github/codeql-action`` populates
#: fingerprints only for results whose location has a ``region.startLine`` and resolves
#: to a file in the checkout; a behavioural finding's location is the target endpoint,
#: which has neither. So the identity has to be ours to compute.
FINGERPRINT_KEY = "llmsecTestFindingHash/v1"

#: A target URL with the port captured separately, because the port is the one part of
#: a locally launched application's address that changes between runs.
_TARGET_URI = re.compile(r"^(?P<scheme>[a-z][a-z0-9+.\-]*://)(?P<host>[^/:]+)(?::\d+)?(?P<rest>.*)$", re.I)


def _stable_target(uri: str) -> str:
    """``uri`` with an ephemeral port removed, so one target has one identity.

    A cohort member is launched on whatever port is free, so the same application is
    ``http://127.0.0.1:8103/chat`` today and ``:8211`` tomorrow. Hashing the raw URI
    would therefore give the same finding a new identity on every run — the failure
    this function exists to prevent. A path, a repo-relative artifact or anything else
    without a scheme and host is returned untouched: there is nothing ephemeral in it.
    """
    match = _TARGET_URI.match(uri)
    if not match:
        return uri
    return f"{match['scheme']}{match['host']}{match['rest']}"


def _finding_identity(result: TestResult, rule_id: str, location: dict[str, Any]) -> str:
    """A stable identity for one finding, as a hex digest.

    WHAT IS IN IT, and why each part. The ``rule_id`` and the pytest ``nodeid`` say
    which question was put; the probe case says which concrete attack asked it, so two
    cases under one rule stay two findings; the port-stripped target says what was
    asked. Together they are the finding, and they are the same on the next run.

    WHAT IS DELIBERATELY NOT IN IT: the message, the severity, the duration, the
    timestamp and the raw port. A finding whose wording we improve, or whose score a
    re-run nudges, is still the same finding — the identity has to survive our own
    edits or it is not an identity. This mirrors the one comparable tool that solved
    it (Promptfoo hashes a normalized, length-capped finding text with its file and
    rule) while leaving out the text, which in our reports quotes the target's reply
    and so would change whenever the target phrases itself differently.
    """
    artifact = location.get("artifactLocation", {}).get("uri", "")
    case = result.properties.get("llmsec_case") or ""
    parts = (rule_id, result.nodeid or result.test_name or "", str(case), _stable_target(str(artifact)))
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()


class SARIFGenerator:
    """Generates SARIF v2.1.0 compliant reports."""

    SARIF_VERSION = "2.1.0"
    SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

    def __init__(self, tool_name: str, tool_version: str, source_root: Path):
        self.tool_name = tool_name
        self.tool_version = tool_version
        self.source_root = source_root

    def generate(self, results: list[TestResult], baseline_analysis=None) -> str:
        """Generate SARIF JSON from test results.

        Args:
            results: List of test results
            baseline_analysis: Optional baseline regression analysis

        Returns:
            SARIF JSON string
        """
        sarif = {
            "version": self.SARIF_VERSION,
            "$schema": self.SARIF_SCHEMA,
            "runs": [self._create_run(results, baseline_analysis)]
        }

        return json.dumps(sarif, indent=2, ensure_ascii=False)

    def _create_run(self, results: list[TestResult], baseline_analysis=None) -> dict[str, Any]:
        """Create SARIF run object."""
        rules = self._generate_rules(results)
        sarif_results = self._generate_results(results, baseline_analysis)
        artifacts = self._generate_artifacts(results)

        run = {
            "tool": {
                "driver": {
                    "name": self.tool_name,
                    "version": self.tool_version,
                    "informationUri": "https://github.com/wehnsdaefflae/llmsectest",
                    "rules": rules
                }
            },
            "results": sarif_results,
            "artifacts": artifacts,
            "columnKind": "utf16CodeUnits",
            # WHICH SCAN THIS IS. GitHub groups alerts by the run's automation id, so two
            # scans of two different applications uploaded from one repository are two
            # series rather than one that keeps overwriting itself. The id is the target
            # with its ephemeral port stripped, for the same reason the fingerprints strip
            # it: the port is not part of what was scanned. With no target recorded (a
            # white-box-only run) the category stays bare, which is a valid id and groups
            # every such run together — the honest answer when there is nothing to tell
            # them apart.
            "automationDetails": {"id": self._automation_id(results)},
            "invocations": [
                {
                    "executionSuccessful": True,
                    "endTimeUtc": datetime.now(UTC).isoformat()
                }
            ]
        }

        # Declare the OWASP taxonomy first-class, so consumers that understand
        # SARIF can group and filter by category without knowing our property
        # names. The properties keys below stay exactly as they were: removing
        # them would break readers that already parse them.
        run["taxonomies"] = [_owasp_taxonomy()]

        # Collect OWASP markers for compliance mapping
        # **The categories this run put to the target, never every marker present
        # (2026-09-04).** Each run carries one coverage-map assertion per category, wearing
        # that category's marker, so a set built from every marker was all ten on every run.
        # This block publishes a *compliance* claim, so that read `owasp_mapped: 10` and six
        # named frameworks into the SARIF of a scan that exercised four categories, which is
        # the one number here somebody might paste into an audit.
        all_owasp_markers = exercised_categories(results)

        # Build properties object
        properties = {}

        # Add compliance framework coverage
        if all_owasp_markers:
            frameworks = get_frameworks_covered(list(all_owasp_markers))
            summary = get_compliance_summary(list(all_owasp_markers))

            properties["compliance_frameworks"] = {
                "frameworks_covered": sorted(frameworks),
                "framework_count": len(frameworks),
                "framework_summary": {
                    framework: {
                        "controls": summary[framework]["total_controls"],
                        "categories": summary[framework]["categories_covered"],
                        "owasp_mapped": summary[framework]["owasp_mapped"]
                    }
                    for framework in summary
                }
            }

        # Add baseline comparison properties if available
        if baseline_analysis:
            properties["baseline_comparison"] = {
                "has_regressions": baseline_analysis.has_regressions,
                "has_improvements": baseline_analysis.has_improvements,
                "regression_count": baseline_analysis.regression_count,
                "improvement_count": baseline_analysis.improvement_count,
                "regressed_tests": baseline_analysis.regressed_tests,
                "fixed_tests": baseline_analysis.fixed_tests,
                "baseline_pass_rate": baseline_analysis.baseline_pass_rate,
                "current_pass_rate": baseline_analysis.current_pass_rate,
                "pass_rate_change": baseline_analysis.pass_rate_change,
                "severity_impact": baseline_analysis.severity_impact,
                "owasp_impact": baseline_analysis.owasp_impact,
                "regression_severity": baseline_analysis.regression_severity
            }

        # Run-level denial-of-wallet cost: the real provider output-token spend
        # across every probe that reported usage (pass or fail). This surfaces the
        # LLM10 cost figure even when no LLM10 finding fired — a well-behaved but
        # token-hungry target is a cost signal, not a security finding — and lets CI
        # track total token spend of the scan over time. A black-box app endpoint
        # reports no usage, so it simply contributes nothing here (no key present).
        token_costs = [
            tok
            for r in results
            if (tok := _as_int(r.properties.get("output_tokens"))) is not None
        ]
        if token_costs:
            properties["denial_of_wallet"] = {
                "probes_with_usage": len(token_costs),
                "total_output_tokens": sum(token_costs),
                "peak_output_tokens": max(token_costs),
                "mean_output_tokens": round(sum(token_costs) / len(token_costs), 1),
            }

        # Run-level probe latency, the sibling of the tally above and added for the same
        # reason one level along: a scan already reported the probes that ran out of time
        # and nothing at all about the ones that nearly did. A probe answered at 88s under
        # a 90s budget is next pass's inconclusive, and today it reads exactly like one
        # answered in 3s. The 2026-08-13 cohort pass turned that gap into a published
        # number: ten members recorded timeouts, and re-driving one of them standalone the
        # next morning answered every probe in well under a tenth of the budget — so the
        # timeouts described the machine the pass ran on rather than the targets, and
        # nothing in any report could have told the two apart. `peak_probe` names the
        # slowest probe rather than only its time, because "which request costs the most"
        # is the actionable half.
        #
        # A probe cut off at the deadline measured the deadline and not the target, so it
        # is counted apart from the rest (2026-08-17). The first version of this property
        # averaged the two populations together, which quietly turned `mean_seconds` into
        # a rescaled timeout count: on the 2026-08-14 cohort pass ten members read 18.4 to
        # 23.3 s against the other forty's 3.5 to 10.1, were written up as two disjoint
        # clusters of fast and slow targets, and taking the timed-out probes back out
        # collapses the gap to 5.1-12.2 against 3.6-10.1, which overlap. One population,
        # not two. Every key below therefore describes the probes that *finished*, and the
        # ones that did not get two keys of their own rather than being folded in.
        finished: list[tuple[float, str]] = []
        unfinished: list[float] = []
        hit_deadline: list[float] = []
        for r in results:
            secs = _as_float(r.properties.get("llmsec_elapsed"))
            if secs is None:
                continue
            if r.properties.get("llmsec_inconclusive") is not None:
                unfinished.append(secs)
            elif r.properties.get("llmsec_timed_out") is not None:
                hit_deadline.append(secs)
            else:
                finished.append((secs, str(r.properties.get("llmsec_case", ""))))
        if finished or unfinished or hit_deadline:
            latency: dict[str, Any] = {"probes_measured": len(finished)}
            if finished:
                peak_seconds, peak_probe = max(finished)
                total = sum(secs for secs, _ in finished)
                latency["total_seconds"] = round(total, 1)
                latency["peak_seconds"] = round(peak_seconds, 1)
                latency["peak_probe"] = peak_probe
                latency["mean_seconds"] = round(total / len(finished), 1)
            if unfinished:
                # `unfinished` rather than `inconclusive` because this is the timing half
                # of that count: the same probes, and the seconds they burned before the
                # budget cut them off are real machine time even though they measure
                # nothing about the target.
                latency["probes_unfinished"] = len(unfinished)
                latency["unfinished_seconds"] = round(sum(unfinished), 1)
            if hit_deadline:
                # These timed out but were scored as findings, so they are not
                # inconclusive; their seconds are the budget, not the target's latency.
                latency["probes_hit_deadline"] = len(hit_deadline)
                latency["deadline_seconds"] = round(max(hit_deadline), 1)
            properties["latency"] = latency

        # Run-level generation tally. What matters here is the *rejected* count, not
        # the accepted one: a generator that quietly discarded half its output would
        # shrink the attack surface run over run while every report still said "no
        # findings", which is indistinguishable from a target that got safer. The reasons
        # come with it, since "12 rejected" is a number and "12 rejected, all of them for
        # dropping the marker" is a diagnosis.
        generation = [
            str(r.properties["llmsec_generation"])
            for r in results
            if r.properties.get("llmsec_generation") is not None
        ]
        if generation:
            properties["generated_attacks"] = generation[0]

        # Run-level concurrent-load tally. Without it the stress pass is legible only
        # through its failures: a `regressed` verdict travels in the assertion message,
        # while `held` and `inconclusive` produce a passing test and say nothing, so a
        # reader could not tell a guardrail that survived a real wave from one whose wave
        # never arrived. Those are the two outcomes the whole module exists to keep apart
        # (see llmsectest.probes.stress), and a verdict with no denominator beside it is
        # the shape this project keeps having to fix. Every verdict is counted and the
        # measured load lines are carried verbatim.
        stress = [
            (str(r.properties["llmsec_stress_verdict"]),
             str(r.properties.get("llmsec_stress_load", "")))
            for r in results
            if r.properties.get("llmsec_stress_verdict") is not None
        ]
        if stress:
            verdicts: dict[str, int] = {}
            for verdict, _ in stress:
                verdicts[verdict] = verdicts.get(verdict, 0) + 1
            properties["stress"] = {
                "cases": len(stress),
                "verdicts": verdicts,
                # Only the loads that were actually applied. A `not-applicable` case sends
                # no requests at all, so an empty line there is absence rather than a
                # measurement of zero.
                "loads": [load for _, load in stress if load][:20],
            }

        # Run-level inconclusive-probe tally: a probe whose target exceeded the per-request
        # --app-timeout is recorded errored (llmsec_inconclusive) — neither a finding nor a
        # clean pass. Being errored, it never becomes a SARIF result, so without this
        # run-level count the report (and any count-based regression check reading only the
        # findings) would silently treat a timed-out probe as clean. Surfacing it keeps the
        # run honest ("N probes could not be concluded") and lets a cohort baseline flag a
        # member whose probes start hanging — a real perf/hang regression a finding-count
        # band would hide. Parallels denial_of_wallet: an aggregate over all results.
        inconclusive = [
            str(r.properties["llmsec_inconclusive"])
            for r in results
            if r.properties.get("llmsec_inconclusive") is not None
        ]
        if inconclusive:
            properties["inconclusive"] = {
                "count": len(inconclusive),
                "reasons": inconclusive[:20],
            }

        # The subset of the above that never got an answer to score: unreachable
        # endpoint, malformed reply, auth failure. Its own run-level property because a
        # consumer reading the file (our renderer, a CI job, a cohort baseline) has to be
        # able to tell "this scan could not talk to the target" from a clean report
        # without our code. The run also exits non-zero when this is non-empty.
        undelivered = [
            str(r.properties["llmsec_undelivered"])
            for r in results
            if r.properties.get("llmsec_undelivered") is not None
        ]
        if undelivered:
            properties["undelivered"] = {
                "count": len(undelivered),
                "reasons": undelivered[:20],
            }

        # The subset of the above that the application's own input boundary refused. It
        # is still undelivered (nothing was scored, and the run exits non-zero), but it
        # says the opposite about the target: the application defended itself rather than
        # the transport failing. A consumer reading the file has to be able to tell the
        # two apart without our code, or the property reintroduces the defect it exists
        # to fix (issue #18).
        boundary_refused = [
            str(r.properties["llmsec_boundary_refused"])
            for r in results
            if r.properties.get("llmsec_boundary_refused") is not None
        ]
        if boundary_refused:
            properties["boundary_refused"] = {
                "count": len(boundary_refused),
                "reasons": boundary_refused[:20],
            }

        # Every probe whose reply carried the value passed to --app-secret, whichever
        # category asked. Its own run-level property because it invalidates a clean LLM02
        # row, and a consumer reading the file (our renderer, a CI gate) has to be able to
        # see that without our code. See llmsectest.probes.detectors.secret_exposed.
        secret_exposed = [
            str(r.properties["llmsec_secret_exposed"])
            for r in results
            if r.properties.get("llmsec_secret_exposed") is not None
        ]
        if secret_exposed:
            properties["secret_exposed"] = {
                "count": len(secret_exposed),
                "reasons": secret_exposed[:20],
            }

        # **Which white-box scanners this run was pointed at, and at what (2026-09-06).**
        # `attacks_withstood` below counts probes DELIVERED to a target; LLM03 and LLM04
        # read the project's own artefacts instead, so they can never appear in it. That
        # left a consumer of this file seeing a category with 71 findings and no tally row
        # at all, which is indistinguishable from a category no probe ever ran — the exact
        # defect the tally exists to prevent, one category along. Measured on a scan whose
        # own report read LLM03 as *not tested* while the same file carried dozens of
        # supply-chain findings.
        scanners = {
            category: {"input": flag, "path": os.environ[variable]}
            for category, flag, variable in (
                ("LLM03", "--repo", envvars.REPO),
                ("LLM04", "--model-scan", envvars.MODEL_SCAN),
                ("LLM08", "--vector-store", envvars.VECTOR_STORE),
            )
            if os.environ.get(variable)
        }
        if scanners:
            properties["white_box_scanners"] = scanners

        # Run-level "what did the target withstand" tally — the positive half of the
        # run, so an empty findings list is evidence rather than silence. Rationale and
        # counting rules in :func:`~llmsectest.reporting.statistics.attack_tally`.
        withstood = attack_tally(results)
        if withstood:
            properties["attacks_withstood"] = withstood
            # Lifted to the top level as well as living inside the tally: it qualifies a
            # whole category's row, and a CI gate reading this file should not have to
            # walk into by_category to find out that a clean row proves nothing.
            if withstood.get("unconfirmed_markers"):
                properties["unconfirmed_markers"] = withstood["unconfirmed_markers"]

        # How many of those withstood probes left a transcript, and what was cut from it.
        # Issue #21 asked for the count and the rows to agree; this makes the one case
        # where they cannot, a reply over the size cap, visible in the file rather than
        # leaving a silently shortened transcript.
        transcript_rows = [
            r for r in (sarif_results or [])
            if r["properties"].get("llmsec_withstood")
        ]
        if transcript_rows:
            properties["withstood_transcripts"] = {
                "count": len(transcript_rows),
                "reply_limit_characters": WITHSTOOD_REPLY_LIMIT,
                "truncated": sum(
                    1 for r in transcript_rows if r["properties"].get("reply_truncated")
                ),
            }

        # Add properties to run if any exist
        if properties:
            run["properties"] = properties

        return run

    def _generate_rules(self, results: list[TestResult]) -> list[dict[str, Any]]:
        """Generate SARIF rule definitions with OWASP metadata."""
        rules = {}

        for result in results:
            rule_id = self._get_rule_id(result)
            if rule_id not in rules:
                # Get OWASP category information
                owasp_markers = get_owasp_markers_from_test(result.markers)
                owasp_category = (
                    get_owasp_category(owasp_markers[0]) if owasp_markers else None
                )

                # Build rule definition
                rule = {
                    "id": rule_id,
                    "name": result.test_name,
                    "shortDescription": {
                        "text": result.docstring or f"Security test: {result.test_name}"
                    },
                    "defaultConfiguration": {"level": self._get_severity_level(result)},
                }

                # Add full description if OWASP category is available
                if owasp_category:
                    rule["fullDescription"] = {
                        "text": f"{owasp_category.name}: {owasp_category.full_description}"
                    }
                    rule["help"] = {
                        "text": owasp_category.help_text,
                        "markdown": f"# {owasp_category.name}\n\n{owasp_category.help_text}",
                    }

                # Build comprehensive property tags
                properties = {
                    "tags": result.markers + get_security_tags(result.markers),
                }

                # security-severity: prefer the OWASP category's real CVSS v4.0
                # base score; fall back to the marker-based placeholder for tests
                # with no OWASP category. (GitHub code-scanning buckets findings
                # by this numeric property.)
                cvss_score = cvss_for_category(owasp_markers[0]) if owasp_markers else None
                if cvss_score is not None:
                    properties["security-severity"] = f"{cvss_score.base_score}"
                    properties["cvss_version"] = cvss_score.version
                    properties["cvss_vector"] = cvss_score.vector
                    properties["cvss_base_score"] = cvss_score.base_score
                    properties["cvss_base_severity"] = cvss_score.severity
                else:
                    properties["security-severity"] = self._get_numeric_severity(result)

                # Add OWASP-specific properties.
                #
                # **The edition travels with the number (2026-10-20).** Eight of the ten
                # categories changed number between the 2025 and 2026 editions, so
                # `owasp-category: LLM03` alone is ambiguous: it is Supply Chain under 2025
                # and Excessive Agency under 2026. A consumer reading a stored SARIF has no
                # way to date it from the file, and this project has published 92 reports
                # carrying 2025 numbers. So every finding names the edition it was scored
                # under, and the 2025 number travels beside it wherever the two differ —
                # which is what lets the old reports stay readable instead of being rewritten.
                if owasp_category:
                    properties["owasp-category"] = owasp_category.id
                    properties["owasp-name"] = owasp_category.name
                    properties["owasp-edition"] = resolve_edition()
                    legacy = (
                        get_owasp_category(owasp_markers[0], edition="2025")
                        if owasp_markers
                        else None
                    )
                    if legacy is not None and legacy.id != owasp_category.id:
                        properties["owasp-category-2025"] = legacy.id

                # Add CWE tags
                cwe_ids = get_cwe_tags(result.markers)
                if cwe_ids:
                    properties["cwe"] = cwe_ids

                # Add compliance framework mappings
                if owasp_markers:
                    compliance_mappings = get_compliance_mappings(owasp_markers[0])
                    if compliance_mappings:
                        frameworks = list({m.framework for m in compliance_mappings})
                        properties["compliance-frameworks"] = frameworks
                        properties["compliance-controls"] = [
                            {
                                "framework": m.framework,
                                "control_id": m.control_id,
                                "control_name": m.control_name,
                                "category": m.category
                            }
                            for m in compliance_mappings
                        ]

                rule["properties"] = properties

                # Add help URI if OWASP category has references
                if owasp_category and owasp_category.references:
                    rule["helpUri"] = owasp_category.references[0]

                rules[rule_id] = rule

        return list(rules.values())

    def _automation_id(self, results: list[TestResult]) -> str:
        """The id under which GitHub groups this run's alerts.

        SARIF's ``automationDetails.id`` conventionally ends in ``/``, which marks the
        part before it as the category and lets several uploads coexist. We key it on
        the application that was scanned, port-stripped, so scanning two targets from
        one repository keeps two alert series instead of each upload closing the
        other's findings — the same failure the fingerprints prevent per result, one
        level up.
        """
        for result in results:
            # ``llmsec_artifact_uri`` IS the scanned target for a behavioural finding:
            # ``suite/conftest.py`` records the stripped ``app:`` endpoint under it. For a
            # white-box finding it is a repo-relative manifest path instead, which is
            # equally the thing that was scanned, so one property answers both.
            target = result.properties.get("llmsec_artifact_uri")
            if target:
                return f"llmsectest/{_stable_target(str(target))}/"
        return "llmsectest/"

    def _physical_location(self, result: TestResult) -> dict[str, Any]:
        """Where the finding points.

        A white-box finding about the *tested* project (e.g. an LLM03 supply-chain
        risk in a dependency manifest) records the offending artifact's repo-relative
        path as the ``llmsec_artifact_uri`` test property; point the SARIF location
        there, in the scanned project, rather than at the test file inside this tool.
        Behavioural findings have no project source line for their cause, so they
        fall back to the test node that produced them.
        """
        artifact = result.properties.get("llmsec_artifact_uri")
        if artifact:
            location: dict[str, Any] = {"artifactLocation": {"uri": artifact}}
            line = result.properties.get("llmsec_artifact_line")
            if line:
                location["region"] = {"startLine": int(line), "startColumn": 1}
            return location
        return {
            "artifactLocation": {"uri": result.file_path, "uriBaseId": "%SRCROOT%"},
            "region": {"startLine": result.line_number, "startColumn": 1},
        }

    def _generate_results(self, results: list[TestResult], baseline_analysis=None) -> list[dict[str, Any]]:
        """Generate SARIF result objects for findings, plus a pass row per held probe."""
        sarif_results = []

        # Create set of regressed test IDs for quick lookup
        regressed_test_ids = set(baseline_analysis.regressed_tests) if baseline_analysis else set()
        # The same set attack_tally counts, so a report's withstood number and its
        # transcript rows cannot disagree. See statistics.withstood_probes.
        withstood = {id(r) for r in withstood_probes(results)}

        for result in results:
            if result.outcome == "failed":
                # Get OWASP category for enriched messaging
                owasp_markers = get_owasp_markers_from_test(result.markers)
                owasp_category = (
                    get_owasp_category(owasp_markers[0]) if owasp_markers else None
                )

                # Prefer the clean finding message (what the tested app/project did
                # wrong) recorded by the suite; fall back to the pytest longrepr only
                # when none was recorded. This keeps this tool's own test source and
                # assertion traceback out of the report.
                message_text = result.properties.get("llmsec_finding") or result.longrepr or "Test failed"

                # Mark regressions prominently
                is_regression = result.nodeid in regressed_test_ids
                if is_regression:
                    message_text = f"⚠ REGRESSION: {message_text}"
                elif owasp_category:
                    message_text = f"[{owasp_category.id}] {message_text}"

                rule_id = self._get_rule_id(result)
                physical = self._physical_location(result)
                sarif_result = {
                    "ruleId": rule_id,
                    "level": self._get_severity_level(result),
                    "message": {"text": message_text},
                    "locations": [
                        {"physicalLocation": physical}
                    ],
                    "partialFingerprints": {
                        FINGERPRINT_KEY: _finding_identity(result, rule_id, physical)
                    },
                    "properties": {
                        "test_outcome": result.outcome,
                        "test_duration": result.duration,
                        "test_markers": result.markers,
                    },
                }

                # Mark as baseline regression
                if is_regression:
                    sarif_result["properties"]["baseline_regression"] = True
                    sarif_result["baselineState"] = "new"  # SARIF standard property for new issues

                # Add OWASP category to properties
                if owasp_category:
                    sarif_result["properties"]["owasp_category"] = owasp_category.id
                    sarif_result["properties"]["owasp_name"] = owasp_category.name
                    sarif_result["taxa"] = _taxa_reference(owasp_category)

                    # Attach the category's CVSS v4.0 base score to the finding.
                    cvss_score = cvss_for_category(owasp_markers[0]) if owasp_markers else None
                    if cvss_score is not None:
                        sarif_result["properties"]["cvss_base_score"] = cvss_score.base_score
                        sarif_result["properties"]["cvss_base_severity"] = cvss_score.severity
                        sarif_result["properties"]["cvss_vector"] = cvss_score.vector

                    # Add remediation suggestions as SARIF fixes
                    if owasp_category.remediation_steps:
                        sarif_result["fixes"] = self._generate_fixes(owasp_category)

                # Add CWE information
                cwe_ids = get_cwe_tags(result.markers)
                if cwe_ids:
                    sarif_result["properties"]["cwe_ids"] = cwe_ids

                # Attach the finding's real provider output-token cost (its concrete
                # denial-of-wallet figure), when the target reported usage.
                output_tokens = _as_int(result.properties.get("output_tokens"))
                if output_tokens is not None:
                    sarif_result["properties"]["output_tokens"] = output_tokens

                # The two axes beside the oracle's verdict (bl-084, roadmap phase-03
                # item b), carried onto the finding so a reader of the report can tell
                # three different questions apart instead of reading one score as the
                # answer to all of them:
                #   capability        — did the attacker actually GET anything?
                #   refusal_content   — did the refusal itself disclose the prompt?
                # Each rides with its own evidence string, which prints the measurement
                # (the word counts, the echoed span) rather than a bare verdict, so the
                # reader judges the span instead of trusting a threshold. NEITHER changes
                # `level` or `test_outcome`: the detector keeps the gate.
                for prop in (
                    "llmsec_capability",
                    "llmsec_capability_evidence",
                    "llmsec_refusal_content",
                    "llmsec_refusal_content_evidence",
                ):
                    value = result.properties.get(prop)
                    if value:
                        sarif_result["properties"][prop.removeprefix("llmsec_")] = value

                sarif_results.append(sarif_result)
            elif id(result) in withstood and result.properties.get("llmsec_reply") is not None:
                sarif_results.append(self._withstood_result(result))

        return sarif_results

    def _withstood_result(self, result: TestResult) -> dict[str, Any]:
        """A SARIF row for a probe the target survived, carrying what it said.

        ``kind: pass`` and ``level: none`` are what keep this apart from a finding: a
        consumer that counts ``results`` as vulnerabilities would otherwise read every
        refusal as a defect. The reply is the point of the row (issue #21), capped for
        size with the cut disclosed on the row itself.
        """
        reply = str(result.properties.get("llmsec_reply", ""))
        truncated = len(reply) > WITHSTOOD_REPLY_LIMIT
        case = str(result.properties.get("llmsec_case") or result.test_name)

        rule_id = self._get_rule_id(result)
        physical = self._physical_location(result)
        sarif_result = {
            "ruleId": rule_id,
            "kind": "pass",
            "level": "none",
            "message": {"text": f"attack withstood: {case}"},
            "locations": [
                {"physicalLocation": physical}
            ],
            "partialFingerprints": {
                FINGERPRINT_KEY: _finding_identity(result, rule_id, physical)
            },
            "properties": {
                "test_outcome": result.outcome,
                "test_duration": result.duration,
                "test_markers": result.markers,
                "llmsec_withstood": True,
                "probe": case,
                "reply": reply[:WITHSTOOD_REPLY_LIMIT],
                "reply_characters": len(reply),
            },
        }
        if truncated:
            sarif_result["properties"]["reply_truncated"] = True

        # The axes answer questions that arise when the target held, too — a refusal that
        # leaks its own instructions is a held probe whose transcript matters most.
        for prop in (
            "llmsec_capability",
            "llmsec_capability_evidence",
            "llmsec_refusal_content",
            "llmsec_refusal_content_evidence",
        ):
            value = result.properties.get(prop)
            if value:
                sarif_result["properties"][prop.removeprefix("llmsec_")] = value

        owasp_markers = get_owasp_markers_from_test(result.markers)
        owasp_category = get_owasp_category(owasp_markers[0]) if owasp_markers else None
        if owasp_category:
            sarif_result["properties"]["owasp_category"] = owasp_category.id
            sarif_result["properties"]["owasp_name"] = owasp_category.name
            sarif_result["taxa"] = _taxa_reference(owasp_category)

        return sarif_result

    def _generate_artifacts(self, results: list[TestResult]) -> list[dict[str, Any]]:
        """Generate SARIF artifact objects, consistent with each finding's location.

        A finding that points at a tested-project artifact (``llmsec_artifact_uri``,
        e.g. an LLM03 dependency manifest) lists that manifest; otherwise the test
        file in this tool. Mirrors :meth:`_physical_location`.
        """
        artifacts = {}

        for result in results:
            artifact = result.properties.get("llmsec_artifact_uri")
            if artifact:
                artifacts.setdefault(artifact, {"location": {"uri": artifact}})
            elif result.file_path not in artifacts:
                artifacts[result.file_path] = {
                    "location": {
                        "uri": result.file_path,
                        "uriBaseId": "%SRCROOT%"
                    }
                }

        return list(artifacts.values())

    def _get_rule_id(self, result: TestResult) -> str:
        """Generate unique rule ID from test."""
        # Remove parametrization brackets for cleaner rule IDs
        return result.test_name.replace("[", "_").replace("]", "")

    def _get_severity_level(self, result: TestResult) -> str:
        """Extract severity level from test markers."""
        for marker in result.markers:
            if marker in SARIF_SEVERITY_MAP:
                return SARIF_SEVERITY_MAP[marker]
        return "warning"  # Default severity

    def _get_numeric_severity(self, result: TestResult) -> str:
        """Get numeric severity score for security tools."""
        for marker in result.markers:
            if marker in SEVERITY_SCORES:
                return SEVERITY_SCORES[marker]
        return "5.0"  # Default medium severity

    def _generate_fixes(self, owasp_category) -> list[dict[str, Any]]:
        """Generate SARIF fix objects from remediation steps.

        Args:
            owasp_category: OWASPCategory with remediation steps

        Returns:
            List of SARIF fix objects
        """
        fixes = []

        for idx, step in enumerate(owasp_category.remediation_steps, 1):
            fix = {
                "description": {
                    "text": f"Remediation step {idx}: {step}"
                },
                "artifactChanges": []  # Conceptual fixes, no specific file changes
            }
            fixes.append(fix)

        return fixes
