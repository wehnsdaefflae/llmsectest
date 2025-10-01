# Contributing to LLMSecTest

Thank you for your interest in contributing to LLMSecTest! This document provides guidelines and instructions for contributing.

## 🎯 Project Vision

LLMSecTest aims to make LLM security testing as standard as unit testing, providing comprehensive coverage of OWASP Top 10 for LLMs vulnerabilities in an accessible, developer-friendly framework.

## 🚀 Getting Started

### Setting Up Development Environment

1. **Clone the repository**
   ```bash
   git clone https://github.com/mwernsdorfer/llmsectest.git
   cd llmsectest
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -e ".[dev]"
   ```

4. **Install pre-commit hooks**
   ```bash
   pre-commit install
   ```

## 🧪 Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=llmsectest --cov-report=html

# Run specific test file
pytest tests/unit/test_base.py

# Run with verbose output
pytest -v
```

## 🔍 Code Quality

We maintain high code quality standards:

### Linting and Formatting

```bash
# Format code with black
black llmsectest tests

# Check code with ruff
ruff check llmsectest tests

# Type check with mypy
mypy llmsectest
```

### Pre-commit Hooks

Pre-commit hooks automatically run before each commit to ensure code quality:
- Trailing whitespace removal
- End-of-file fixer
- YAML/TOML validation
- Black formatting
- Ruff linting
- MyPy type checking

## 📝 Coding Standards

### Python Style

- Follow PEP 8 guidelines
- Use type hints for all functions and methods
- Maximum line length: 100 characters
- Use descriptive variable and function names

### Documentation

- All public classes and functions must have docstrings
- Use Google-style docstrings
- Include examples in docstrings for complex functionality

Example:
```python
def my_function(arg1: str, arg2: int) -> bool:
    """
    Brief description of function.

    Longer description if needed, explaining the purpose
    and behavior in detail.

    Args:
        arg1: Description of first argument
        arg2: Description of second argument

    Returns:
        Description of return value

    Raises:
        ValueError: When and why this exception is raised

    Example:
        >>> result = my_function("test", 42)
        >>> print(result)
        True
    """
    pass
```

### Testing

- Write unit tests for all new functionality
- Aim for >90% code coverage
- Use descriptive test names: `test_<what>_<condition>_<expected_result>`
- Use pytest fixtures for reusable test setup

## 🎁 Contributing New Features

### Adding New OWASP Test Modules

To add a new OWASP test module (e.g., LLM03, LLM04):

1. **Create test module file**: `llmsectest/tests/llmXX_<name>.py`

2. **Implement SecurityTest interface**:
   ```python
   from llmsectest.core.base import SecurityTest, OWASPCategory, TestResult
   from typing import List

   class MyNewTest(SecurityTest):
       def get_owasp_category(self) -> OWASPCategory:
           return OWASPCategory.LLMXX

       def get_test_name(self) -> str:
           return "My Test Name"

       def get_description(self) -> str:
           return "Description of what this tests"

       async def run(self) -> List[TestResult]:
           # Implement test logic
           pass
   ```

3. **Add tests**: Create unit tests in `tests/unit/`

4. **Update documentation**: Add to README and module docstring

### Adding New LLM Adapters

To add support for a new LLM provider:

1. **Create adapter file**: `llmsectest/adapters/<provider>_adapter.py`

2. **Implement LLMAdapter interface**:
   ```python
   from llmsectest.core.base import LLMAdapter, LLMResponse, LLMMessage
   from typing import List, Optional

   class NewProviderAdapter(LLMAdapter):
       async def send_message(
           self,
           message: str,
           system_prompt: Optional[str] = None,
           conversation_history: Optional[List[LLMMessage]] = None,
       ) -> LLMResponse:
           # Implement provider-specific logic
           pass

       def get_provider_name(self) -> str:
           return "provider-name"

       def get_model_name(self) -> str:
           return self.model or "default-model"
   ```

3. **Add to pyproject.toml**: Add optional dependency group

4. **Update documentation**: Document provider setup

## 🐛 Reporting Bugs

When reporting bugs, please include:

1. **Description**: Clear description of the issue
2. **Reproduction steps**: Minimal code to reproduce
3. **Expected behavior**: What should happen
4. **Actual behavior**: What actually happens
5. **Environment**:
   - Python version
   - LLMSecTest version
   - OS
   - LLM provider and model

## 💡 Requesting Features

For feature requests, please:

1. Check existing issues to avoid duplicates
2. Clearly describe the feature and its benefits
3. Explain the use case
4. Provide examples if possible

## 📋 Pull Request Process

1. **Fork and create branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make changes**
   - Write code following our standards
   - Add tests
   - Update documentation

3. **Commit changes**
   ```bash
   git commit -m "Add feature: brief description"
   ```
   - Use clear, descriptive commit messages
   - Reference issues when applicable: "Fixes #123"

4. **Push and create PR**
   ```bash
   git push origin feature/your-feature-name
   ```
   - Fill out the PR template
   - Link related issues
   - Ensure CI passes

5. **Code review**
   - Address reviewer feedback
   - Update as needed
   - Maintainers will merge when approved

## 🏷️ Good First Issues

Look for issues labeled `good first issue` - these are great starting points for new contributors!

## 📜 Code of Conduct

- Be respectful and inclusive
- Welcome newcomers and help them learn
- Focus on constructive feedback
- Prioritize the community's well-being

## 📧 Questions?

- Open a GitHub issue for questions
- Check existing issues and documentation first

## 🙏 Recognition

Contributors will be recognized in:
- README contributors section
- Release notes
- Annual contributor highlights

Thank you for contributing to LLMSecTest! Together we're making LLM applications more secure. 🛡️
