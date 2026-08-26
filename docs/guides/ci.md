# CI/CD integration

LLMSecTest exits non-zero when it finds a vulnerability and writes a **SARIF v2.1.0** report, so it
plugs into any pipeline and into GitHub/GitLab code-scanning.

## Try it before you wire anything up

The offline demo needs no target, no API key and no GPU. It finishes in under a second:

```bash
pip install llmsectest
llmsectest --target demo-defended
```

That runs the packaged probe suite against a built-in hardened demo app, prints the coverage footer
and exits 0. Drop `--target demo-defended` to scan the weak demo instead. It exits non-zero because
it has real findings. Between those two you can see what a pass and a failure look like before
pointing anything at your own app.

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

      - run: pip install llmsectest

      # Start your app backed by a local/test model so there are no paid calls.
      # (Replace with however your app boots.)
      - run: ./scripts/start-test-app.sh &

      - name: Wait for the app to answer
        run: |
          for _ in $(seq 1 30); do
            curl -sf http://localhost:8000/health >/dev/null && exit 0
            sleep 2
          done
          echo "the app never came up, so the scan would have nothing to test"
          exit 1

      - name: Run LLMSecTest
        id: scan
        continue-on-error: true      # let the SARIF upload run before the job fails
        run: |
          llmsectest --target app:http://localhost:8000/chat \
            --sarif-output results/llmsectest.sarif \
            --app-timeout 60

      - name: Upload SARIF to code-scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results/llmsectest.sarif

      - name: Fail the build on findings
        if: steps.scan.outcome == 'failure'
        run: exit 1
```

Findings then appear in the repository's **Security → Code scanning** tab, mapped to their OWASP LLM
category with severity and remediation guidance.

**Scan once, then decide.** The last step re-reads the outcome of the scan that produced the report
rather than running a second scan. Probes are model-driven, so two scans of one application can
disagree, which would leave you with an uploaded report describing a different run from the one that
passed or failed your build. `continue-on-error` plus `steps.scan.outcome` keeps the report and the
verdict describing the same run.

On a pull request from a fork, GitHub issues a read-only token and the upload step cannot write to
code-scanning. Findings still show in the job log, so treat the fork case as report-only.

## What a non-zero exit means

A non-zero exit means the run is not a clean bill of health. It does **not** always mean the
application is vulnerable. Two cases produce it:

- **Findings.** A probe landed and the application failed it.
- **Undelivered probes.** We could not get an answer out of the target, so probes are recorded
  `inconclusive` and never scored as findings. A scan reporting `0 findings, 25 undelivered` must not
  pass CI as clean, so it exits non-zero too.

The summary line, the SARIF run properties and the HTML banner all carry the inconclusive count, so a
red build tells you which of the two you have. In the second case the console summary reports its
status as `INCOMPLETE` rather than `PASSED` and claims no security posture, so the log cannot read as
a clean bill of health on a scan that never reached your app. A timeout is the usual cause of the second one: raise
`--app-timeout` for a legitimately slow app, or lower it to hold the scan inside a fixed CI budget.

## Report formats

```bash
llmsectest --target app:http://localhost:8000/chat \
  --report-formats=sarif,html,json,markdown
```

- **SARIF**, code-scanning ingestion (GitHub, GitLab, Azure DevOps).
- **HTML**, a human-readable report to attach as a build artifact.
- **JSON**, machine-readable for your own dashboards.
- **Markdown**, drop into a PR comment or job summary.

## Gating policy

By default any finding fails the run. Use a baseline to accept known issues and fail only on *new*
ones, see the policy/baseline options in the [CLI reference](../cli.md).
