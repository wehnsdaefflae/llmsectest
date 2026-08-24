# Contributing

Thanks for looking. This is a small project with one maintainer, so the most useful thing you can do
is tell me where it broke.

## The most valuable contribution is a bad first run

I run this tool against 50 applications every day. Every one of them is an application I wrote.
That means I'm the worst person to find out where it fails on *your* application. If you tried it and
gave up, please open an issue saying where you stopped. "I gave up at X" is the report I want most.
Two of them have already changed the tool. One person bounced off the README, another off a stale
OWASP category number, and both are fixed.

You don't have to be polite about it and you don't have to investigate first.

## Running it locally

```bash
git clone https://github.com/wehnsdaefflae/llmsectest
cd llmsectest
pip install -e ".[dev,cvss]"
llmsectest --check          # prints the OWASP coverage map
```

Tests, lint and coverage, which is what CI runs:

```bash
ruff check src tests examples
coverage run -m pytest -q
coverage report
```

**Use `coverage run -m pytest`, never `pytest --cov`.** This package is a `pytest11` plugin, so pytest
imports it before `pytest-cov` starts measuring and the number comes out about 24 points low. There is
a longer writeup in `docs/guides/development.md`.

## What a good change looks like

- **A test that fails before your fix.** This is a security scanner. A change with no test is a claim.
- **Say what you measured.** "This should be faster" is a hypothesis. "This takes 6.1s against 9.4s on
  the same corpus" is a result. Either is fine in a PR. Just say which one it is.
- **Match the surrounding style.** Comments here explain *why*, usually with the incident that caused
  the code to look like that. If you remove a guard, the comment above it should tell you what it was
  guarding against.
- **No new runtime dependencies without a reason in the PR.** The installed package depends on nothing;
  optional extras are how vendor SDKs and CVSS scoring get in. That's deliberate in a security tool.

## Good first issues

Issues tagged [`good first issue`](https://github.com/wehnsdaefflae/llmsectest/labels/good%20first%20issue)
are real gaps rather than busywork. Each one says what "done" means. If one is unclear, that's a
bug in the issue and I'd like to hear about it.

## Reporting a vulnerability

In this tool rather than in a target. See [SECURITY.md](SECURITY.md), and please don't use a public
issue for that one.

## Licence and provenance

MIT. By contributing you agree your work ships under it. The project is funded by the German Federal
Ministry of Research, Technology and Space through the [Prototype Fund](https://prototypefund.de),
funding code 16IS26S10. That changes nothing about the licence. It's worth knowing.
