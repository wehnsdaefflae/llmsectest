# CI/CD integration

LLMSecTest exits non-zero when it finds a vulnerability and writes a **SARIF v2.1.0** report, so it
plugs into any pipeline and into GitHub/GitLab code-scanning.

## GitHub Actions

```yaml
name: llm-security
on: [push, pull_request]

jobs:
  llmsectest:
    runs-on: ubuntu-latest
    permissions:
      security-events: write   # to upload SARIF to code-scanning
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }

      - run: pip install "git+https://github.com/wehnsdaefflae/llmsectest"   # pre-alpha: not yet on PyPI

      # Start your app backed by a local/test model so there are no paid calls,
      # then test it. (Replace with however your app boots.)
      - run: ./scripts/start-test-app.sh &

      - name: Run LLMSecTest
        run: llmsectest --target app:http://localhost:8000/chat --sarif-output results/llmsectest.sarif
        continue-on-error: true   # upload the report even when findings fail the run

      - name: Upload SARIF to code-scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results/llmsectest.sarif

      - name: Fail the build on findings
        run: llmsectest --target app:http://localhost:8000/chat
```

Findings then appear in the repository's **Security → Code scanning** tab, mapped to their OWASP LLM
category with severity and remediation guidance.

## Report formats

```bash
llmsectest --target app:http://localhost:8000/chat \
  --report-formats=sarif,html,json,markdown
```

- **SARIF** — code-scanning ingestion (GitHub, GitLab, Azure DevOps).
- **HTML** — a human-readable report to attach as a build artifact.
- **JSON** — machine-readable for your own dashboards.
- **Markdown** — drop into a PR comment or job summary.

## Gating policy

By default any finding fails the run. Use a baseline to accept known issues and fail only on *new*
ones — see the policy/baseline options in the [CLI reference](../cli.md).
