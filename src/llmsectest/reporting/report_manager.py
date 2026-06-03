"""Report manager for generating multiple report formats."""

from pathlib import Path
from typing import Any, List, Optional
import logging

from .models import TestResult
from .sarif_generator import SARIFGenerator
from .html_generator import HTMLReportGenerator
from .json_summary_generator import JSONSummaryGenerator
from .markdown_generator import MarkdownReportGenerator


logger = logging.getLogger(__name__)


class ReportManager:
    """Manages generation of multiple report formats from test results."""

    def __init__(
        self,
        tool_name: str,
        tool_version: str,
        source_root: Path,
        output_dir: Path = Path("results")
    ):
        """Initialize report manager.

        Args:
            tool_name: Name of the testing tool
            tool_version: Version of the testing tool
            source_root: Root directory of the source code
            output_dir: Directory where reports will be saved
        """
        self.tool_name = tool_name
        self.tool_version = tool_version
        self.source_root = source_root
        self.output_dir = output_dir

        # Initialize generators
        self.sarif_generator = SARIFGenerator(tool_name, tool_version, source_root)
        self.html_generator = HTMLReportGenerator(tool_name, tool_version)
        self.json_generator = JSONSummaryGenerator(tool_name, tool_version)
        self.markdown_generator = MarkdownReportGenerator(tool_name, tool_version)

    def generate_reports(
        self,
        results: List[TestResult],
        formats: List[str] = None,
        custom_paths: dict = None,
        trend_analytics: Optional[dict] = None,
        baseline_analysis: Optional[Any] = None,
        risk_score: Optional[Any] = None,
        policy_violations: Optional[List] = None,
        security_policy: Optional[Any] = None
    ) -> dict:
        """Generate reports in specified formats.

        Args:
            results: List of test results
            formats: List of format names to generate (default: all)
            custom_paths: Optional dict mapping format names to custom file paths
            trend_analytics: Optional trend analytics data to include in reports
            baseline_analysis: Optional baseline regression analysis to include in reports
            risk_score: Optional risk score assessment
            policy_violations: Optional list of policy violations
            security_policy: Optional security policy configuration

        Returns:
            Dict mapping format names to generated file paths
        """
        if formats is None:
            formats = ["sarif", "html", "json", "markdown"]

        if custom_paths is None:
            custom_paths = {}

        generated_files = {}

        # Ensure output directory exists
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Generate SARIF report
        if "sarif" in formats:
            sarif_path = custom_paths.get("sarif", self.output_dir / "pytest-results.sarif")
            try:
                sarif_content = self.sarif_generator.generate(results, baseline_analysis)
                self._write_report(sarif_path, sarif_content)
                generated_files["sarif"] = sarif_path
                logger.info(f"Generated SARIF report: {sarif_path}")
            except Exception as e:
                logger.error(f"Failed to generate SARIF report: {e}")

        # Generate HTML report
        if "html" in formats:
            html_path = custom_paths.get("html", self.output_dir / "pytest-results.html")
            try:
                html_content = self.html_generator.generate(
                    results, trend_analytics, baseline_analysis,
                    risk_score, policy_violations, security_policy
                )
                self._write_report(html_path, html_content)
                generated_files["html"] = html_path
                logger.info(f"Generated HTML report: {html_path}")
            except Exception as e:
                logger.error(f"Failed to generate HTML report: {e}")

        # Generate JSON summary
        if "json" in formats:
            json_path = custom_paths.get("json", self.output_dir / "pytest-summary.json")
            try:
                json_content = self.json_generator.generate(
                    results, trend_analytics, baseline_analysis,
                    risk_score, policy_violations, security_policy
                )
                self._write_report(json_path, json_content)
                generated_files["json"] = json_path
                logger.info(f"Generated JSON summary: {json_path}")
            except Exception as e:
                logger.error(f"Failed to generate JSON summary: {e}")

        # Generate Markdown report
        if "markdown" in formats:
            md_path = custom_paths.get("markdown", self.output_dir / "pytest-results.md")
            try:
                md_content = self.markdown_generator.generate(results, baseline_analysis)
                self._write_report(md_path, md_content)
                generated_files["markdown"] = md_path
                logger.info(f"Generated Markdown report: {md_path}")
            except Exception as e:
                logger.error(f"Failed to generate Markdown report: {e}")

        return generated_files

    def _write_report(self, path: Path, content: str):
        """Write report content to file.

        Args:
            path: Path where report should be written
            content: Report content as string
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

