# Test fixtures

Real-world inputs used by the test suite, kept as committed files so tests do not
depend on any external tool being installed.

## `ruff-0.15.15.sarif`

A **genuine third-party SARIF v2.1.0 report**, emitted by [ruff](https://docs.astral.sh/ruff/)
0.15.15 — not hand-written by us. It backs the `--render-sarif` interop tests in
`test_sarif_html.py`, which prove that our renderer displays *any* tool's SARIF, not
just our own. Ruff is a good foil: its findings carry no OWASP category, no CVSS
`security-severity`, and put the human-readable rule name under `properties.name`
(not the top-level `name`), so the file exercises the renderer's graceful-degradation
and level-based-severity paths against output whose shape we did not design.

Regenerated with:

```
ruff check sample_module.py --output-format sarif --select F,E
```

over a small module with an unused import, unused variables, and a `== None`
comparison. The only edit applied afterwards is normalizing the machine-specific
absolute `file://` source URI down to the relative `sample_module.py`, so the
committed fixture is portable and leaks no local path.

## `bandit-1.9.4.sarif`

A **genuine third-party SARIF v2.1.0 report**, emitted by
[Bandit](https://bandit.readthedocs.io/) 1.9.4 — a real Python *security*
scanner (ruff, above, is only a linter and carries no CWE). It backs the second
`--render-sarif` interop test set in `test_sarif_html.py`. Bandit is a valuable
foil because it records CWE the way most security scanners do — **not** in an
explicit `properties.cwe` field like we do, but as an `external/cwe/cwe-NNN`
entry in the rule's `properties.tags` (the GitHub code-scanning convention). The
fixture proves the renderer surfaces CWE from that convention too.

Regenerated with:

```
bandit -f sarif -o bandit-1.9.4.sarif sample_vuln.py
```

over a small module with a hardcoded password (B105 → CWE-259), `subprocess`
with `shell=True` (B602 → CWE-78), a weak MD5 hash (B324 → CWE-327), and `eval`
(B307). The only edits applied afterwards normalize the machine-specific source
path down to the basename `sample_vuln.py` (in both the `artifactLocation.uri`
and the `run.properties.metrics` key), so the committed fixture is portable and
leaks no local path.

## `semgrep-1.172.0.sarif`

A **genuine third-party SARIF v2.1.0 report**, emitted by
[Semgrep](https://semgrep.dev/) OSS 1.172.0. It backs the third `--render-sarif`
interop test set in `test_sarif_html.py`, and it is committed **verbatim** (unlike the
two fixtures above, which needed path normalization): run from the `code/` directory
against committed inputs, Semgrep's output already contains no absolute path and no
machine-specific value.

Semgrep is the third distinct CWE convention in this directory, which is the point of
keeping it. Ruff carries no CWE at all; Bandit uses the GitHub `external/cwe/cwe-NNN`
tag; Semgrep writes a **descriptive** tag whose text merely *starts* with the id, e.g.
`"CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval
Injection')"`. The fixture proves the renderer pulls the bare id out of that and does
not leak the descriptive remainder into the CWE chip.

It also answers, with evidence rather than from the specification, whether scanners
attach CWE through SARIF's `run.taxonomies` / `result.taxa` mechanism: **Semgrep OSS
1.172.0 emits neither key**. `test_semgrep_fixture_carries_no_taxonomies` pins that, so
a future regeneration that starts emitting them fails loudly instead of passing
silently while the renderer ignores the data.

Finally, the fixture is what exposed the namespaced-rule-id defect: Semgrep sets a
rule's `name` to its `id`, and the id is namespaced by the config it was loaded from,
so findings were headed `tests.fixtures.python-eval-of-request-data` (registry rules
are worse: `python.lang.security.audit.eval-detected`). Titles now show the last
segment of a dotted *id* only, never shortening a name a tool wrote for humans.

Regenerated from the `code/` directory with:

```
semgrep --config tests/fixtures/semgrep-cwe-rules.yaml --sarif --metrics=off \
        tests/fixtures/semgrep_sample_vuln.py > tests/fixtures/semgrep-1.172.0.sarif
```

`semgrep-cwe-rules.yaml` (three rules carrying one, one and two CWEs) and
`semgrep_sample_vuln.py` (a hardcoded credential, `subprocess` with `shell=True`, and
`eval`) are committed alongside, so the fixture is reproducible without inventing the
inputs. Semgrep itself is **not** a project dependency: it is installed ad hoc only
when the fixture is regenerated, exactly as ruff and Bandit are for theirs.
