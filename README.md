# LLMSecTest

Security testing framework for LLM applications, implementing the OWASP Top 10 for LLMs standard.

## Why LLMSecTest?

Testing LLM applications for security vulnerabilities is hard. Most developers don't have security expertise, and existing tools only cover 1-2 vulnerability types. LLMSecTest provides comprehensive testing for all 10 OWASP LLM categories with a pytest-like interface that's familiar to Python developers.

## Installation

```bash
pip install llmsectest

# With specific providers
pip install llmsectest[openai]
pip install llmsectest[anthropic]
```

## Usage

Python API:

```python
from llmsectest import SecurityTestSuite
from llmsectest.adapters import OpenAIAdapter
from llmsectest.tests import PromptInjectionTest

adapter = OpenAIAdapter(api_key="your-api-key")
suite = SecurityTestSuite(adapter)
suite.add_test(PromptInjectionTest(adapter))

results = await suite.run_all_tests()
print(f"Vulnerabilities found: {results.vulnerabilities_found}")
```

Command line:

```bash
llmsectest test --provider openai --api-key YOUR_KEY
llmsectest test --category LLM01 --output report.json
```

## What Gets Tested

Current implementation covers:

- **LLM01: Prompt Injection** - Direct injection, system prompt extraction, delimiter attacks, role confusion

Planned:

- LLM02-LLM10 (in development)

See the [OWASP Top 10 for LLMs](https://owasp.org/www-project-top-10-for-large-language-model-applications/) for full vulnerability details.

## Project Status

This is v0.1.0 - proof of concept stage. The core architecture is in place with the first test module (prompt injection) implemented. Under active development as part of Prototype Fund Round 02.

## CI/CD Integration

Add to your GitHub Actions workflow:

```yaml
- run: pip install llmsectest[openai]
- run: llmsectest test --provider openai --api-key ${{ secrets.OPENAI_API_KEY }}
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## License

MIT License - see [LICENSE](LICENSE)
