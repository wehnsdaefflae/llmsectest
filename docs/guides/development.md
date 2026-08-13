# Development

How to run the tests and measure coverage on this project.

## Install

```bash
pip install -e ".[dev,cvss]"
```

## Run the unit suite

```bash
pytest -q
```

The unit suite is offline and fast (about 1.5 seconds). It never contacts a model,
so it can run anywhere, including in CI on every push.

## Measure coverage

Use `coverage run -m pytest`, **not** `pytest --cov`:

```bash
coverage run -m pytest -q
coverage report
```

Both commands look equivalent and are not. `llmsectest` registers a
[`pytest11` entry point](https://docs.pytest.org/en/stable/how-to/writing_plugins.html),
so pytest imports the package while loading plugins, which happens *before*
`pytest-cov` starts measuring. Every module reached on that path has its
module-level statements recorded as never executed. On the same green suite:

| Invocation | Reported coverage |
|---|---|
| `pytest --cov=llmsectest` | 48% |
| `coverage run -m pytest` | 72% |

The 48% comes from import order. The code is tested. `coverage run` starts
measuring before pytest loads anything, so it sees the real picture. This is a
general trap for any package that is itself a pytest plugin.

Configuration lives in `pyproject.toml` under `[tool.coverage.run]` and
`[tool.coverage.report]`. Branch coverage is on, and `coverage report` fails below
the floor set in `fail_under`. The floor ratchets upward: raise it when a change
legitimately lifts coverage, and never lower it to turn a red build green.

### What is excluded

`src/llmsectest/suite/` (the packaged probe suite) is omitted from the
measurement. Those modules only execute against a live target (a model, or an
application endpoint), so a unit run can never enter them; counting them would
measure how much of the product needs a GPU rather than how much of it is
untested. They are exercised end to end against real applications instead.

## Lint

```bash
ruff check src tests
```

The rule set is declared explicitly in `pyproject.toml` rather than inherited from
ruff's defaults, and the tool is pinned to a major range. Ruff's default selection
changes between releases, so an unpinned linter can turn a green branch red without
a single line of code changing.

## Profiling

There is no profiling dependency, and adding one has been measured to be
unnecessary. A real scan is dominated by waiting for the model: in a 183-second
bare-model run, 180.8 seconds (98.8%) were spent in `socket.recv`, and everything
this project's own Python does totalled under 1.2 seconds, most of it interpreter
startup. If you do need a profile, stdlib `cProfile` is enough:

```bash
LLMSECTEST_TARGET="ollama:your-model" \
  python -m cProfile -o scan.prof -m pytest src/llmsectest/suite -q
```

Revisit this only if a scan ever becomes CPU-bound rather than model-bound.
