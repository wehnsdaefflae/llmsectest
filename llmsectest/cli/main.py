"""Main CLI entry point for LLMSecTest."""

import asyncio
import os
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

from llmsectest.core.base import OWASPCategory
from llmsectest.core.suite import SecurityTestSuite


console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="llmsectest")
def cli() -> None:
    """LLMSecTest - Security Testing Framework for LLM Applications."""
    pass


@cli.command()
@click.option(
    "--provider",
    type=click.Choice(["openai", "anthropic"], case_sensitive=False),
    required=True,
    help="LLM provider to test",
)
@click.option(
    "--api-key",
    type=str,
    envvar="LLM_API_KEY",
    help="API key (or set LLM_API_KEY env var)",
)
@click.option(
    "--model",
    type=str,
    help="Model to test (provider-specific)",
)
@click.option(
    "--category",
    type=click.Choice([cat.value for cat in OWASPCategory]),
    multiple=True,
    help="Specific OWASP categories to test (can specify multiple)",
)
@click.option(
    "--output",
    type=click.Path(),
    help="Output file path for report",
)
@click.option(
    "--format",
    type=click.Choice(["json", "html", "sarif"]),
    default="json",
    help="Report format",
)
def test(
    provider: str,
    api_key: Optional[str],
    model: Optional[str],
    category: tuple,
    output: Optional[str],
    format: str,
) -> None:
    """Run security tests against an LLM application."""
    console.print("[bold blue]LLMSecTest - Security Testing Framework[/bold blue]")
    console.print()

    # Get API key from environment if not provided
    if not api_key:
        env_var = f"{provider.upper()}_API_KEY"
        api_key = os.getenv(env_var)
        if not api_key:
            console.print(
                f"[bold red]Error:[/bold red] API key required. "
                f"Provide via --api-key or set {env_var} environment variable."
            )
            sys.exit(1)

    # Initialize adapter
    adapter = None
    try:
        if provider == "openai":
            from llmsectest.adapters import OpenAIAdapter

            adapter = OpenAIAdapter(
                api_key=api_key, model=model or "gpt-4"
            )
        elif provider == "anthropic":
            console.print("[bold red]Error:[/bold red] Anthropic adapter not yet implemented")
            sys.exit(1)
    except ImportError as e:
        console.print(
            f"[bold red]Error:[/bold red] {str(e)}\n"
            f"Install with: pip install llmsectest[{provider}]"
        )
        sys.exit(1)

    # Create test suite
    suite = SecurityTestSuite(adapter)

    # Add tests
    from llmsectest.tests import PromptInjectionTest

    suite.add_test(PromptInjectionTest(adapter))

    # Parse categories
    categories = [OWASPCategory(cat) for cat in category] if category else None

    # Run tests
    console.print(f"[bold]Provider:[/bold] {provider}")
    console.print(f"[bold]Model:[/bold] {adapter.get_model_name()}")
    if categories:
        console.print(f"[bold]Categories:[/bold] {', '.join(cat.value for cat in categories)}")
    else:
        console.print("[bold]Categories:[/bold] All")
    console.print()
    console.print("[bold yellow]Running tests...[/bold yellow]")
    console.print()

    # Run tests asynchronously
    results = asyncio.run(suite.run_all_tests(categories=categories))

    # Display results
    _display_results(results)

    # Save report if output specified
    if output:
        output_path = Path(output)
        if format == "json":
            output_path.write_text(results.to_json())
            console.print(f"\n[bold green]Report saved to:[/bold green] {output_path}")
        elif format == "html":
            console.print("[bold red]HTML format not yet implemented[/bold red]")
        elif format == "sarif":
            console.print("[bold red]SARIF format not yet implemented[/bold red]")

    # Exit with non-zero code if vulnerabilities found
    if results.vulnerabilities_found > 0:
        sys.exit(1)


def _display_results(results: "TestSuiteResult") -> None:  # type: ignore
    """Display test results in a formatted table."""
    # Summary
    console.print("[bold]Summary:[/bold]")
    console.print(f"  Total tests: {results.total_tests}")
    console.print(f"  Passed: [green]{results.passed_tests}[/green]")
    console.print(f"  Failed: [red]{results.failed_tests}[/red]")
    console.print(
        f"  Vulnerabilities found: [red bold]{results.vulnerabilities_found}[/red bold]"
    )
    console.print()

    # Detailed results table
    table = Table(title="Test Results")
    table.add_column("Test", style="cyan")
    table.add_column("Category", style="magenta")
    table.add_column("Severity", style="yellow")
    table.add_column("Status", style="bold")
    table.add_column("Message", style="white")

    for result in results.results:
        status = "[green]✓ PASS[/green]" if result.passed else "[red]✗ FAIL[/red]"
        severity_color = {
            "critical": "red bold",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "white",
        }.get(result.severity.value, "white")

        table.add_row(
            result.test_name[:30],
            result.owasp_category.value,
            f"[{severity_color}]{result.severity.value.upper()}[/{severity_color}]",
            status,
            result.message[:50],
        )

    console.print(table)


if __name__ == "__main__":
    cli()
