"""Target resolution for the packaged probe suite.

The target is chosen by the ``LLMSECTEST_TARGET`` environment variable (the
``llmsectest`` CLI sets it from ``--target``). With no target set, the suite
runs against the offline demo-vulnerable app so a zero-config run still
produces a meaningful report.
"""

import os

import pytest

from llmsectest import envvars
from llmsectest.probes import resolve_target
from llmsectest.probes.runner import run_probe


@pytest.fixture(scope="session")
def target_adapter():
    return resolve_target(os.environ.get(envvars.TARGET, "demo-vulnerable"))


@pytest.fixture
def probe(target_adapter):
    """Return a callable that runs a probe case against the resolved target."""

    def _run(case):
        return run_probe(target_adapter, case)

    return _run
