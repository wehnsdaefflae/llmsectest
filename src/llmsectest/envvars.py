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
``--vector-store <path>``   :data:`VECTOR_STORE`
``--redteam-set <csv>``     :data:`REDTEAM_SET`
``--app-prompt <text>``     :data:`APP_PROMPT`
``--app-secret <value>``    :data:`APP_SECRET`
``--app-action <sig>``      :data:`APP_ACTIONS` (repeatable; joined)
``--app-canary <value>``    :data:`APP_CANARY`
``--app-rag-poison <mark>`` :data:`APP_RAG_POISON`
``--app-timeout <seconds>`` :data:`APP_TIMEOUT`
``--app-stress <N>``        :data:`APP_STRESS`
``--redteam-generate <N>``  :data:`REDTEAM_GENERATE`
==========================  ==========================
"""

from __future__ import annotations

import json
import os

TARGET = "LLMSECTEST_TARGET"
REPO = "LLMSECTEST_REPO"
OSV = "LLMSECTEST_OSV"
MODEL_SCAN = "LLMSECTEST_MODEL_SCAN"
VECTOR_STORE = "LLMSECTEST_VECTOR_STORE"
REDTEAM_SET = "LLMSECTEST_REDTEAM_SET"
APP_PROMPT = "LLMSECTEST_APP_PROMPT"
APP_SECRET = "LLMSECTEST_APP_SECRET"
APP_ACTIONS = "LLMSECTEST_APP_ACTIONS"
APP_CANARY = "LLMSECTEST_APP_CANARY"
APP_RAG_POISON = "LLMSECTEST_APP_RAG_POISON"
APP_TIMEOUT = "LLMSECTEST_APP_TIMEOUT"
APP_STRESS = "LLMSECTEST_APP_STRESS"
#: How a real application's HTTP contract differs from the one we guessed. Added 2026-09-04:
#: the adapter has carried `request_field`, `response_path`, `headers` and `extra_body` since
#: it was written, and **none of them was reachable from the CLI**, so every third-party member
#: of the cohort got a hand-written translation shim instead. Five real applications, five
#: shims, while the README says to point the scanner at your endpoint.
APP_REQUEST_FIELD = "LLMSECTEST_APP_REQUEST_FIELD"
APP_RESPONSE_PATH = "LLMSECTEST_APP_RESPONSE_PATH"
APP_HEADERS = "LLMSECTEST_APP_HEADERS"
APP_BODY = "LLMSECTEST_APP_BODY"
REDTEAM_GENERATE = "LLMSECTEST_REDTEAM_GENERATE"

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


def app_timeout_from_env() -> float | None:
    """The per-request timeout (seconds) for an ``app:<url>`` target, if set.

    Returns ``None`` when unset or unparseable, so the app adapter falls back to
    its own default rather than failing the scan on a malformed value.
    """
    raw = os.environ.get(APP_TIMEOUT, "")
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


def app_shape_from_env() -> dict:
    """How this application's HTTP contract differs from the default one.

    Returns the keyword arguments `AppEndpointAdapter` takes for a non-default request or
    response shape, leaving out anything unset so the adapter keeps its own defaults.

    **Why it exists (2026-09-04).** The adapter has always been able to POST a different
    field name, read a reply out of a dotted path, carry headers and add fixed body keys.
    None of it was reachable without writing Python, so every real application enrolled in
    the cohort got a bespoke shim: private-gpt speaks Anthropic `/v1/messages`, open-webui
    has its own, Langflow wants `{input_value, output_type, input_type}` and answers with the
    reply nested five levels down. The tool told users to point it at their endpoint and then
    only worked on endpoints shaped like the one we imagined.

    A malformed value fails loudly here rather than silently reverting to the default, since
    a scan that quietly talked to the wrong shape would record a whole application as
    unreachable and the honesty guarantee would report that faithfully.
    """
    shape: dict = {}
    field = os.environ.get(APP_REQUEST_FIELD, "").strip()
    if field:
        shape["request_field"] = field
    path = os.environ.get(APP_RESPONSE_PATH, "").strip()
    if path:
        shape["response_path"] = path
    for name, key in ((APP_HEADERS, "headers"), (APP_BODY, "extra_body")):
        raw = os.environ.get(name, "").strip()
        if not raw:
            continue
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"{name} must be a JSON object: {exc}") from exc
        if not isinstance(value, dict):
            raise SystemExit(f"{name} must be a JSON object, got {type(value).__name__}")
        shape[key] = value
    return shape


def app_stress_from_env() -> int | None:
    """The requested stress concurrency for an ``app:<url>`` target, if set.

    Returns ``None`` when unset or unparseable, which leaves the stress suite
    **skipped with a reason** rather than silently running at some default concurrency.
    A load test nobody asked for is a load test against somebody else's application, so
    the absence of the flag has to mean absence of load and never a fallback value.
    """
    raw = os.environ.get(APP_STRESS, "")
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return None
    return value if value >= 2 else None


def redteam_generate_from_env() -> int:
    """How many model-composed variants to add per authored seed, or ``0``.

    Zero when unset or unparseable, so the authored corpus runs alone unless somebody
    asked for more. A generator nobody requested would make two runs incomparable for a
    reason the operator never chose.
    """
    raw = os.environ.get(REDTEAM_GENERATE, "")
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return 0
    return value if value > 0 else 0
