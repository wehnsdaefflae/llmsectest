# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

LLMSecTest is a security testing framework for LLM applications implementing the OWASP Top 10 for LLMs 2025 standard. The framework uses a pytest-like interface and is currently in proof-of-concept stage (v0.1.0) with LLM01 (Prompt Injection) tests implemented.

## Development Commands

### Setup
```bash
# Create virtual environment and install
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

### Testing
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=llmsectest --cov-report=html

# Run specific test file
pytest tests/unit/test_base.py

# Run specific test
pytest tests/unit/test_base.py::TestLLMMessage::test_create_message -v
```

### Code Quality
```bash
# Format code (required before commit)
black llmsectest tests

# Lint code
ruff check llmsectest tests

# Fix auto-fixable linting issues
ruff check llmsectest tests --fix

# Type check
mypy llmsectest
```

### CLI Testing
```bash
# Test CLI commands
llmsectest --version
llmsectest --help
llmsectest test --help

# Run tests (requires API key)
export OPENAI_API_KEY="your-key"
llmsectest test --provider openai
```

## Architecture

### Core Design Pattern

The framework follows a **provider-agnostic adapter pattern** with three main abstraction layers:

1. **LLMAdapter** - Provider interface (in `llmsectest/core/base.py`)
2. **SecurityTest** - Test implementation interface
3. **SecurityTestSuite** - Test orchestration

All components are async-first for performance.

### Key Architectural Concepts

**LLMAdapter Interface:**
- Abstract base class that all provider adapters must implement
- Async `send_message()` for LLM communication
- Handles conversation history and system prompts
- Returns standardized `LLMResponse` objects
- Example: `OpenAIAdapter` in `llmsectest/adapters/openai_adapter.py`

**SecurityTest Base Class:**
- Each OWASP category gets its own test module (e.g., `llm01_prompt_injection.py`)
- Tests must implement `run()` returning `List[TestResult]`
- Tests use `get_owasp_category()` to declare which OWASP LLM category they cover
- Create results via `create_result()` helper which auto-populates test metadata

**TestResult Data Flow:**
- Immutable dataclass with OWASP category, severity, pass/fail status
- Contains `vulnerability_found` flag (separate from `passed` - test can pass but find vulnerability)
- Includes `remediation` guidance for vulnerabilities
- Converts to dict/JSON for reporting

**SecurityTestSuite Orchestration:**
- Aggregates multiple `SecurityTest` instances
- Supports category filtering (run only LLM01, LLM02, etc.)
- `run_all_tests()` - sequential execution
- `run_parallel()` - concurrent execution via asyncio.gather
- Returns `TestSuiteResult` with aggregated statistics

### Directory Structure Logic

```
llmsectest/
├── core/           # Framework abstractions (LLMAdapter, SecurityTest, etc.)
├── adapters/       # Provider implementations (openai_adapter.py, etc.)
├── tests/          # OWASP test modules (llm01_*.py, llm02_*.py, etc.)
├── cli/            # Click-based CLI
└── reporting/      # Report generation (planned)

tests/              # Framework tests (not security tests)
├── unit/           # Unit tests for core components
└── integration/    # Integration tests (planned)
```

## Adding New Components

### Adding a New LLM Provider Adapter

1. Create `llmsectest/adapters/{provider}_adapter.py`
2. Subclass `LLMAdapter` from `llmsectest.core.base`
3. Implement async `send_message()`, `get_provider_name()`, `get_model_name()`
4. Add to `llmsectest/adapters/__init__.py` exports
5. Add optional dependency to `pyproject.toml` under `[project.optional-dependencies]`
6. Update CLI in `llmsectest/cli/main.py` to support new provider

### Adding a New OWASP Test Module

1. Create `llmsectest/tests/llmXX_{name}.py`
2. Subclass `SecurityTest` from `llmsectest.core.base`
3. Implement required methods:
   - `get_owasp_category()` - return appropriate `OWASPCategory` enum
   - `get_test_name()` - human-readable test name
   - `get_description()` - what the test checks
   - `async run()` - test logic returning `List[TestResult]`
4. Use `self.create_result()` to build `TestResult` objects
5. Add to `llmsectest/tests/__init__.py` exports
6. Create unit tests in `tests/unit/test_llmXX_{name}.py`

## Code Standards

- **Type hints required** on all functions/methods (enforced by mypy)
- **Line length**: 100 characters (Black + Ruff)
- **Async by default**: All LLM interactions and tests are async
- **Docstrings**: Google-style docstrings on all public classes/functions
- **Import sorting**: Handled by Ruff (isort rules)

## Testing Philosophy

- Unit tests go in `tests/unit/`
- Use `MockAdapter` pattern for testing `SecurityTest` implementations
- All async tests need `@pytest.mark.asyncio` decorator
- Coverage target: >90% (currently 38% baseline)

## Important Notes

- The CONTRIBUTING.md file is in `.project-docs/` (gitignored), not in root
- Only `README.md`, `LICENSE`, and `pyproject.toml` should be in project root
- Test modules in `llmsectest/tests/` are **security test implementations**, not pytest tests
- Framework tests go in `tests/` directory (separate from security test modules)
- All LLM adapters should handle API keys via constructor or environment variables, never hardcoded
