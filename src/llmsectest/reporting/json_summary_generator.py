"""JSON summary report generator for pytest security test results."""

import json
from datetime import datetime
from typing import List, Dict, Any, Optional

from .models import TestResult
from .owasp_metadata import get_owasp_category, get_owasp_markers_from_test, get_cwe_tags
from .statistics import calculate_statistics, get_test_severity, get_coverage_gaps


class JSONSummaryGenerator:
    """Generates comprehensive JSON summary reports for security test results."""

    def __init__(self, tool_name: str, tool_version: str):
        self.tool_name = tool_name
        self.tool_version = tool_version

    def generate(
        self,
        results: List[TestResult],
        trend_analytics: Optional[Dict] = None,
        baseline_analysis=None,
        risk_score=None,
        policy_violations=None,
        security_policy=None
    ) -> str:
        """Generate JSON summary from test results.

        Args:
            results: List of test results
            trend_analytics: Optional trend analytics data
            baseline_analysis: Optional baseline regression analysis
            risk_score: Optional risk score assessment
            policy_violations: Optional list of policy violations
            security_policy: Optional security policy configuration

        Returns:
            JSON formatted summary report
        """
        stats = calculate_statistics(results)

        summary = {
            "metadata": {
                "tool": self.tool_name,
                "version": self.tool_version,
                "generated_at": datetime.now().isoformat(),
                "report_format": "json-summary-v2.0"
            },
            "summary": {
                "total_tests": stats["total"],
                "passed": stats["passed"],
                "failed": stats["failed"],
                "skipped": stats["skipped"],
                "pass_rate": stats["pass_rate"],
                "fail_rate": stats["fail_rate"],
                "total_duration": stats["total_duration"]
            },
            "severity_distribution": dict(stats["severity_distribution"]),
            "owasp_coverage": self._generate_owasp_coverage(results, stats),
            "test_results": self._generate_test_results(results),
            "failures": self._generate_failures(results),
            "coverage_gaps": get_coverage_gaps(results)
        }

        # Add baseline comparison if available
        if baseline_analysis:
            summary["baseline_comparison"] = baseline_analysis.to_dict()

        # Add trend analytics if available
        if trend_analytics and trend_analytics.get("has_history"):
            summary["trend_analytics"] = trend_analytics

        # Add risk assessment if available
        if risk_score:
            summary["risk_assessment"] = {
                "overall_score": risk_score.overall_score,
                "risk_level": risk_score.risk_level,
                "confidence": risk_score.confidence,
                "category_scores": risk_score.category_scores,
                "severity_scores": risk_score.severity_scores,
                "trend_score": risk_score.trend_score,
                "baseline_score": risk_score.baseline_score,
                "factors": risk_score.factors,
                "recommendations": risk_score.recommendations
            }

        # Add policy compliance if available
        if security_policy and policy_violations is not None:
            summary["policy_compliance"] = {
                "policy_name": security_policy.name,
                "policy_version": security_policy.version,
                "description": security_policy.description,
                "is_compliant": len(policy_violations) == 0,
                "total_violations": len(policy_violations),
                "compliance_frameworks": security_policy.compliance_frameworks,
                "violations": [
                    {
                        "severity": v.severity,
                        "category": v.category,
                        "message": v.message,
                        "current_value": str(v.current_value),
                        "threshold": str(v.threshold),
                        "recommendation": v.recommendation
                    }
                    for v in policy_violations
                ],
                "violations_by_severity": {
                    "critical": sum(1 for v in policy_violations if v.severity == "critical"),
                    "high": sum(1 for v in policy_violations if v.severity == "high"),
                    "medium": sum(1 for v in policy_violations if v.severity == "medium"),
                }
            }

        return json.dumps(summary, indent=2, ensure_ascii=False)

    def _generate_owasp_coverage(self, results: List[TestResult], stats: Dict) -> Dict[str, Any]:
        """Generate OWASP category coverage with metadata from pre-calculated stats."""
        owasp_coverage = {}

        for cat_id, cat_stats in stats["owasp_categories"].items():
            category = get_owasp_category(f"owasp_{cat_id.lower()}")
            if category:
                total = cat_stats["total"]
                owasp_coverage[cat_id] = {
                    "total_tests": total,
                    "passed": cat_stats["passed"],
                    "failed": cat_stats["failed"],
                    "skipped": cat_stats.get("skipped", 0),
                    "pass_rate": round((cat_stats["passed"] / total * 100), 2) if total > 0 else 0,
                    "category_name": category.name,
                    "description": category.description,
                    "cwe_ids": category.cwe_ids,
                    "tags": category.tags
                }

        return owasp_coverage

    def _generate_test_results(self, results: List[TestResult]) -> List[Dict[str, Any]]:
        """Generate detailed test results."""
        test_results = []

        for result in results:
            owasp_markers = get_owasp_markers_from_test(result.markers)
            owasp_categories = []

            for marker in owasp_markers:
                category = get_owasp_category(marker)
                if category:
                    owasp_categories.append({
                        "id": category.id,
                        "name": category.name
                    })

            severity = get_test_severity(result)
            cwe_ids = get_cwe_tags(result.markers)

            test_results.append({
                "name": result.test_name,
                "file": result.file_path,
                "line": result.line_number,
                "outcome": result.outcome,
                "duration": round(result.duration, 3),
                "severity": severity,
                "owasp_categories": owasp_categories,
                "cwe_ids": cwe_ids,
                "docstring": result.docstring,
                "markers": result.markers
            })

        return test_results

    def _generate_failures(self, results: List[TestResult]) -> List[Dict[str, Any]]:
        """Generate detailed failure information."""
        failures = []

        for result in results:
            if result.outcome == "failed":
                owasp_markers = get_owasp_markers_from_test(result.markers)
                owasp_category = None

                if owasp_markers:
                    category = get_owasp_category(owasp_markers[0])
                    if category:
                        owasp_category = {
                            "id": category.id,
                            "name": category.name,
                            "description": category.description
                        }

                failures.append({
                    "test_name": result.test_name,
                    "file": result.file_path,
                    "line": result.line_number,
                    "severity": get_test_severity(result),
                    "owasp_category": owasp_category,
                    "error_message": result.longrepr,
                    "duration": round(result.duration, 3)
                })

        return failures

