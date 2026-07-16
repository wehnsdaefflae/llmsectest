"""SARIF v2.1.0 report generator for pytest results."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any

from .models import TestResult
from .owasp_metadata import (
    get_owasp_category,
    get_owasp_markers_from_test,
    get_cwe_tags,
    get_security_tags,
)
from .compliance_mapper import (
    get_compliance_mappings,
    get_frameworks_covered,
    get_compliance_summary,
)
from .constants import SARIF_SEVERITY_MAP, SEVERITY_SCORES
from .cvss import cvss_for_category


def _as_int(value: Any) -> int | None:
    """Coerce a recorded ``output_tokens`` property to ``int``, else ``None``.

    The value arrives from ``pytest`` ``user_properties`` (recorded by the probe
    fixture) and is normally already an ``int``; guard against a stray ``None`` or
    a non-numeric string so the cost plumbing never raises on a malformed record.
    """
    if isinstance(value, bool):  # bool is an int subclass — never a token count
        return None
    if isinstance(value, (int, float)):
        return int(value)
    return None


class SARIFGenerator:
    """Generates SARIF v2.1.0 compliant reports."""

    SARIF_VERSION = "2.1.0"
    SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

    def __init__(self, tool_name: str, tool_version: str, source_root: Path):
        self.tool_name = tool_name
        self.tool_version = tool_version
        self.source_root = source_root

    def generate(self, results: List[TestResult], baseline_analysis=None) -> str:
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

    def _create_run(self, results: List[TestResult], baseline_analysis=None) -> Dict[str, Any]:
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
            "invocations": [
                {
                    "executionSuccessful": True,
                    "endTimeUtc": datetime.now(timezone.utc).isoformat()
                }
            ]
        }

        # Collect OWASP markers for compliance mapping
        all_owasp_markers = set()
        for result in results:
            owasp_markers = get_owasp_markers_from_test(result.markers)
            all_owasp_markers.update(owasp_markers)

        # Build properties object
        properties = {}

        # Add compliance framework coverage
        if all_owasp_markers:
            frameworks = get_frameworks_covered(list(all_owasp_markers))
            summary = get_compliance_summary(list(all_owasp_markers))

            properties["compliance_frameworks"] = {
                "frameworks_covered": sorted(list(frameworks)),
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

        # Add properties to run if any exist
        if properties:
            run["properties"] = properties

        return run

    def _generate_rules(self, results: List[TestResult]) -> List[Dict[str, Any]]:
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

                # Add OWASP-specific properties
                if owasp_category:
                    properties["owasp-category"] = owasp_category.id
                    properties["owasp-name"] = owasp_category.name

                # Add CWE tags
                cwe_ids = get_cwe_tags(result.markers)
                if cwe_ids:
                    properties["cwe"] = cwe_ids

                # Add compliance framework mappings
                if owasp_markers:
                    compliance_mappings = get_compliance_mappings(owasp_markers[0])
                    if compliance_mappings:
                        frameworks = list(set(m.framework for m in compliance_mappings))
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

    def _physical_location(self, result: TestResult) -> Dict[str, Any]:
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
            location: Dict[str, Any] = {"artifactLocation": {"uri": artifact}}
            line = result.properties.get("llmsec_artifact_line")
            if line:
                location["region"] = {"startLine": int(line), "startColumn": 1}
            return location
        return {
            "artifactLocation": {"uri": result.file_path, "uriBaseId": "%SRCROOT%"},
            "region": {"startLine": result.line_number, "startColumn": 1},
        }

    def _generate_results(self, results: List[TestResult], baseline_analysis=None) -> List[Dict[str, Any]]:
        """Generate SARIF result objects for failed tests."""
        sarif_results = []

        # Create set of regressed test IDs for quick lookup
        regressed_test_ids = set(baseline_analysis.regressed_tests) if baseline_analysis else set()

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

                sarif_result = {
                    "ruleId": self._get_rule_id(result),
                    "level": self._get_severity_level(result),
                    "message": {"text": message_text},
                    "locations": [
                        {"physicalLocation": self._physical_location(result)}
                    ],
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

                sarif_results.append(sarif_result)

        return sarif_results

    def _generate_artifacts(self, results: List[TestResult]) -> List[Dict[str, Any]]:
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

    def _generate_fixes(self, owasp_category) -> List[Dict[str, Any]]:
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
