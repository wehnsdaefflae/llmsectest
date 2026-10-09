"""Keep example documentation aligned with the OWASP LLM Top 10 (2025)."""

from __future__ import annotations

import ast
from pathlib import Path

EXAMPLES = Path(__file__).parents[1] / "examples"


def _module_docstring(filename: str) -> str:
    source = (EXAMPLES / filename).read_text(encoding="utf-8")
    return ast.get_docstring(ast.parse(source)) or ""


def test_current_categories_match_the_2025_coverage_map() -> None:
    expected = {
        "test_excessive_agency.py": ("LLM06", "excessive agency"),
        "test_denial_of_service.py": ("LLM10", "unbounded consumption"),
        "test_overreliance.py": ("LLM09", "misinformation"),
    }

    for filename, (category, name) in expected.items():
        docstring = _module_docstring(filename).lower()
        assert category.lower() in docstring
        assert name in docstring


def test_retired_2023_categories_are_described_without_a_2025_number() -> None:
    for filename in ("test_model_theft.py", "test_insecure_plugin_use.py"):
        docstring = _module_docstring(filename)
        assert "no OWASP LLM Top 10 (2025) category" in docstring
        assert "LLM06" not in docstring
        assert "LLM10" not in docstring


def test_fixture_section_labels_match_the_example_modules() -> None:
    conftest = (EXAMPLES / "conftest.py").read_text(encoding="utf-8")
    assert "OWASP 2025 LLM06: Excessive Agency Fixtures" in conftest
    assert "OWASP 2025 LLM09: Misinformation Fixtures" in conftest
    assert "Legacy Model Theft Fixtures (no OWASP LLM Top 10 2025 category)" in conftest

