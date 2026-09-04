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

## GitLab CI

```yaml
stages: [test]

llmsectest:
  stage: test
  image: python:3.11
  script:
    - pip install llmsectest

    # Start your app backed by a local/test model so there are no paid calls.
    # (Replace with however your app boots.)
    - ./scripts/start-test-app.sh &

    - |
      up=0
      for _ in $(seq 1 30); do
        if curl -sf http://localhost:8000/health >/dev/null; then up=1; break; fi
        sleep 2
      done
      [ "$up" = 1 ] || { echo "the app never came up, so the scan would have nothing to test"; exit 1; }

    - |
      llmsectest --target app:http://localhost:8000/chat \
        --report-formats=sarif,html \
        --report-dir results \
        --sarif-output results/llmsectest.sarif \
        --app-timeout 60
  artifacts:
    when: always
    paths:
      - results/
    reports:
      sarif: results/llmsectest.sarif
```

**One scan here too. `when: always` is what makes that possible.** GitLab uploads artifacts from a
failed job when you ask it to, so the scan's own exit code can fail the job while the report it
produced still reaches you. There is no second invocation to disagree with the first.

**`reports:sarif` needs GitLab Ultimate**, where it was generally available in 19.2 (behind the
`sarif_ingestion` flag from 18.11). On Ultimate the findings land in the pipeline's **Security** tab,
the security dashboard and the project vulnerability report. On any other tier that key is ignored and
you still get everything under `paths:`: `results/llmsectest.sarif` and `results/pytest-results.html`
as downloadable job artifacts. Nothing else in the job changes, so the same file works on both.

## Jenkins

```groovy
pipeline {
  agent any

  stages {
    stage('LLM security scan') {
      steps {
        sh 'python3 -m venv .venv && .venv/bin/pip install llmsectest'

        // Start your app backed by a local/test model so there are no paid calls.
        sh './scripts/start-test-app.sh &'

        sh '''
          up=0
          for _ in $(seq 1 30); do
            if curl -sf http://localhost:8000/health >/dev/null; then up=1; break; fi
            sleep 2
          done
          [ "$up" = 1 ] || { echo "the app never came up, so the scan would have nothing to test"; exit 1; }
        '''

        catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE',
                   message: 'llmsectest exited non-zero: findings, or probes that never came back') {
          sh '''
            .venv/bin/llmsectest --target app:http://localhost:8000/chat \
              --report-formats=sarif,html \
              --report-dir results \
              --sarif-output results/llmsectest.sarif \
              --app-timeout 60
          '''
        }
      }
    }
  }

  post {
    always {
      archiveArtifacts artifacts: 'results/**', allowEmptyArchive: true
      recordIssues tools: [sarif(pattern: 'results/llmsectest.sarif')]
    }
  }
}
```

`recordIssues` comes from the [Warnings Next Generation](https://plugins.jenkins.io/warnings-ng/)
plugin, whose `sarif` parser reads any SARIF 2.1.0 file and puts the findings on the build page. The
`post { always { … } }` block runs whatever the stage did, so the report is archived and parsed on a
build that the scan just marked unstable.

**Unstable or failed is one line.** `catchError(buildResult: 'UNSTABLE')` turns a non-zero
scan into an amber build rather than a red one, the idiomatic Jenkins choice while a team is still
deciding what it wants to gate on. Drop the `catchError` wrapper and the same `sh` step fails
the build outright. The scan runs once either way: the wrapper reads the exit code the scan already
produced, so the archived report and the build result describe the same run.

Be careful what you promise with the amber build. **`UNSTABLE` is a real result and nothing downstream
treats it as success**, so use it to keep a pipeline moving rather than to make a category of finding
disappear. In particular the second case below, a scan that never reached your app, is not a softer
version of a finding, and an amber build says nothing about whether the app is safe.

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

- **SARIF**, code-scanning ingestion (GitHub, GitLab Ultimate, Azure DevOps).
- **HTML**, a human-readable report to attach as a build artifact. It is written to
  `<report-dir>/pytest-results.html`, which is why the examples above archive the whole directory
  rather than one file.
- **JSON**, machine-readable for your own dashboards.
- **Markdown**, drop into a PR comment or job summary.

## Gating policy

By default any finding fails the run. Use a baseline to accept known issues and fail only on *new*
ones, see the policy/baseline options in the [CLI reference](../cli.md).

**What each CI system can express is different. The scan's own vocabulary is the same in all
three.** LLMSecTest has one verdict, the exit code, and everything above it is your pipeline's
translation of it. GitHub Actions and GitLab have pass and fail; Jenkins adds `UNSTABLE` in between.
None of them has a state for *the scan could not reach the app*, so that case arrives as the same
non-zero exit as a finding, and the log line is what tells the two apart. Whichever you wire up, read
[what a non-zero exit means](#what-a-non-zero-exit-means) before deciding what to make it do.
