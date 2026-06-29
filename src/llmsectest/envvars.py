"""The environment-variable contract between the llmsectest CLI and the packaged suite.

The ``llmsectest`` CLI runs the packaged pytest suite in a subprocess, so every
llmsectest-level option travels from the CLI to the suite as an environment
variable. This module is the single place those names live — the CLI sets them,
the suite modules and the coverage footer read them — so the two sides of the
contract cannot drift apart.

CLI option → environment variable:

==========================  ==========================
``--target <spec>``         :data:`TARGET`
``--repo <path>``           :data:`REPO`
``--osv``                   :data:`OSV` (``"1"`` when requested)
``--model-scan <path>``     :data:`MODEL_SCAN`
``--redteam-set <csv>``     :data:`REDTEAM_SET`
``--app-prompt <text>``     :data:`APP_PROMPT`
``--app-secret <value>``    :data:`APP_SECRET`
``--app-action <sig>``      :data:`APP_ACTIONS` (repeatable; joined)
``--app-canary <value>``    :data:`APP_CANARY`
``--app-rag-poison <mark>`` :data:`APP_RAG_POISON`
==========================  ==========================
"""

from __future__ import annotations

import os

TARGET = "LLMSECTEST_TARGET"
REPO = "LLMSECTEST_REPO"
OSV = "LLMSECTEST_OSV"
MODEL_SCAN = "LLMSECTEST_MODEL_SCAN"
REDTEAM_SET = "LLMSECTEST_REDTEAM_SET"
APP_PROMPT = "LLMSECTEST_APP_PROMPT"
APP_SECRET = "LLMSECTEST_APP_SECRET"
APP_ACTIONS = "LLMSECTEST_APP_ACTIONS"
APP_CANARY = "LLMSECTEST_APP_CANARY"
APP_RAG_POISON = "LLMSECTEST_APP_RAG_POISON"

# Joins the repeatable ``--app-action`` values into the single APP_ACTIONS
# variable. The ASCII unit separator cannot appear in a tool/action signature,
# so splitting on it can never break a signature apart.
ACTIONS_SEPARATOR = "\x1f"


def app_inputs_from_env() -> tuple[str, str | None, tuple[str, ...], str | None, str | None]:
    """The dev-supplied application inputs, as ``app_cases()`` expects them.

    Returns ``(app_prompt, known_secret, forbidden_actions, known_canary,
    known_poison)`` — the app's own system prompt (``""`` if unknown), a real secret
    the app holds (``None`` if none named), the app's privileged action signatures
    (``()`` if none), a confidential canary planted in the app's retrieved corpus
    (``None`` if none named, enables LLM08 retrieval-exposure probes), and the marker
    an indexed *poisoned* document instructs the app to emit (``None`` if none named,
    enables LLM08 indirect-prompt-injection-via-retrieved-document probes).
    """
    prompt = os.environ.get(APP_PROMPT, "")
    secret = os.environ.get(APP_SECRET) or None
    raw = os.environ.get(APP_ACTIONS, "")
    actions = tuple(a for a in raw.split(ACTIONS_SEPARATOR) if a)
    canary = os.environ.get(APP_CANARY) or None
    poison = os.environ.get(APP_RAG_POISON) or None
    return prompt, secret, actions, canary, poison
