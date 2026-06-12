"""The environment-variable contract between the llmsectest CLI and the packaged suite.

The ``llmsectest`` CLI runs the packaged pytest suite in a subprocess, so every
llmsectest-level option travels from the CLI to the suite as an environment
variable. This module is the single place those names live — the CLI sets them,
the suite modules and the coverage footer read them — so the two sides of the
contract cannot drift apart.

CLI option → environment variable:

========================  ==========================
``--target <spec>``       :data:`TARGET`
``--repo <path>``         :data:`REPO`
``--osv``                 :data:`OSV` (``"1"`` when requested)
``--app-prompt <text>``   :data:`APP_PROMPT`
``--app-secret <value>``  :data:`APP_SECRET`
``--app-action <sig>``    :data:`APP_ACTIONS` (repeatable; joined)
========================  ==========================
"""

from __future__ import annotations

import os

TARGET = "LLMSECTEST_TARGET"
REPO = "LLMSECTEST_REPO"
OSV = "LLMSECTEST_OSV"
APP_PROMPT = "LLMSECTEST_APP_PROMPT"
APP_SECRET = "LLMSECTEST_APP_SECRET"
APP_ACTIONS = "LLMSECTEST_APP_ACTIONS"

# Joins the repeatable ``--app-action`` values into the single APP_ACTIONS
# variable. The ASCII unit separator cannot appear in a tool/action signature,
# so splitting on it can never break a signature apart.
ACTIONS_SEPARATOR = "\x1f"


def app_inputs_from_env() -> tuple[str, str | None, tuple[str, ...]]:
    """The dev-supplied application inputs, as ``app_cases()`` expects them.

    Returns ``(app_prompt, known_secret, forbidden_actions)`` — the app's own
    system prompt (``""`` if unknown), a real secret the app holds (``None`` if
    none named), and the app's privileged action signatures (``()`` if none).
    """
    prompt = os.environ.get(APP_PROMPT, "")
    secret = os.environ.get(APP_SECRET) or None
    raw = os.environ.get(APP_ACTIONS, "")
    actions = tuple(a for a in raw.split(ACTIONS_SEPARATOR) if a)
    return prompt, secret, actions
