**What does this change, and what was wrong before?**

**How do you know it works?**
<!-- The test that fails without this change, or the measurement. If it's a hypothesis rather than a
     result, say so — that's fine, it just changes how I read it. -->

**Checklist**
- [ ] `ruff check src tests examples` passes
- [ ] `coverage run -m pytest -q` passes (not `pytest --cov` — see CONTRIBUTING)
- [ ] A test covers the change
- [ ] `CHANGELOG.md` has a bullet under `[Unreleased]` if the behaviour moved
