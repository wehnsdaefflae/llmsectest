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
