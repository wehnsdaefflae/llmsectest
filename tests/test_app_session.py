"""Every probe gets its own session with the application, or the scan measures itself.

**The defect, 2026-09-05, found by standing khoj v1.42.10 up rather than by reasoning about
adapters.** ``AppEndpointAdapter`` sent one POST per probe with one fixed body, so every
probe of a run was the same request with a different prompt. An application that hangs its
persona, its knowledge base or its tool set off a *conversation* left a scan two wrong
choices, and both were measured on khoj:

* with ``conversation_id`` pointing at a conversation bound to our named agent, the persona
  is live and the planted canary came back to the second probe, while all 28 probes share
  one conversation, so each attack sees the ones before it;
* with ``create_new: true``, khoj's only per-probe isolation, the conversation is fresh on
  the **default** agent and the persona is gone.

The two fields are mutually exclusive there. LibreChat, Dify and RAGFlow key retrieval or
the agent on a conversation the same way; we happened to have a route around it on each.

These tests pin the two shapes that fix it, and the third property is the one that matters
for honesty: a **session step that fails is inconclusive and never a finding**, and never an
``AdapterTimeoutError`` either, because an application that did not answer a setup request
has said nothing about how it bounds the work of a probe it never received.
"""

from __future__ import annotations

import http.server
import json
import threading

import pytest

import llmsectest.envvars as envvars
from llmsectest.adapters import AdapterError, CompletionRequest, Message, Role
from llmsectest.adapters.app_endpoint import AppEndpointAdapter
from llmsectest.adapters.base import AdapterTimeoutError
from llmsectest.probes.demo import resolve_target

_ASK = CompletionRequest(messages=[Message(role=Role.USER, content="hello")])


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in (envvars.APP_SESSION_FIELD, envvars.APP_SESSION_INIT,
                 envvars.APP_REQUEST_FIELD, envvars.APP_RESPONSE_PATH,
                 envvars.APP_HEADERS, envvars.APP_BODY):
        monkeypatch.delenv(name, raising=False)


class _App:
    """A tiny application that issues session ids and records every request it received.

    ``/sessions`` mints one; ``/chat`` answers a reply. ``seen`` is the record the tests
    assert against, so what the adapter *sent* is what is checked rather than what it holds.
    """

    def __init__(self, *, session_reply=None, session_status=200):
        self.seen: list[tuple[str, dict]] = []
        self.issued = 0
        self._session_reply = session_reply
        self._session_status = session_status
        app = self

        class _Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length", 0)) or 0)
                body = json.loads(raw) if raw else {}
                app.seen.append((self.path, body))
                if self.path.startswith("/sessions"):
                    app.issued += 1
                    payload = (app._session_reply if app._session_reply is not None
                               else {"conversation_id": f"conv-{app.issued}"})
                    self._send(app._session_status, payload)
                else:
                    self._send(200, {"reply": "ok"})

            def _send(self, status, payload):
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *_a):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def app():
    a = _App()
    yield a
    a.close()


# --- the side that must not move ---------------------------------------------

def test_without_the_flags_the_body_is_what_it_always_was(app):
    """Every application enrolled before today keeps its exact request shape."""
    AppEndpointAdapter(endpoint=f"{app.base}/chat").complete(_ASK)
    assert app.seen == [("/chat", {"message": "hello"})]
    assert app.issued == 0


def test_an_unset_session_leaves_the_shape_empty():
    assert envvars.app_shape_from_env() == {}
    assert resolve_target("app:http://x/chat").session_field is None


# --- client-minted: the cheap shape, and the one most applications need -------

def test_a_client_minted_id_is_fresh_for_every_probe(app):
    a = AppEndpointAdapter(endpoint=f"{app.base}/chat", session_field="conversation_id")
    a.complete(_ASK)
    a.complete(_ASK)
    ids = [body["conversation_id"] for _, body in app.seen]
    assert len(ids) == 2
    assert ids[0] != ids[1], "two probes sharing an id is the defect this fixes"
    assert all(ids)
    assert app.issued == 0, "the client-minted shape costs no extra request"


def test_a_dotted_session_field_reaches_a_nested_envelope(app):
    AppEndpointAdapter(endpoint=f"{app.base}/chat",
                       session_field="metadata.session.id").complete(_ASK)
    _, body = app.seen[0]
    assert isinstance(body["metadata"]["session"]["id"], str)
    assert body["message"] == "hello"


def test_a_session_field_never_overwrites_the_prompt(app):
    """The prompt field and the session field are separate keys of one body."""
    AppEndpointAdapter(endpoint=f"{app.base}/chat", request_field="q",
                       session_field="conversation_id",
                       extra_body={"stream": False}).complete(_ASK)
    _, body = app.seen[0]
    assert body["q"] == "hello"
    assert body["stream"] is False
    assert body["conversation_id"]


@pytest.mark.parametrize("path", ["items.0.id", "0"])
def test_a_list_index_in_the_session_field_is_refused(path):
    """Reading past a list index is unambiguous; writing into one would have to invent
    how long the list is, so it is named as an error instead of guessed."""
    a = AppEndpointAdapter(endpoint="http://x/chat", session_field=path)
    with pytest.raises(AdapterError, match="named fields only"):
        a.complete(_ASK)


# --- server-issued: the shape khoj needs -------------------------------------

def test_the_application_issues_an_id_and_the_probe_carries_it(app):
    a = AppEndpointAdapter(
        endpoint=f"{app.base}/chat",
        session_field="conversation_id",
        session_init={"url": "/sessions", "response_path": "conversation_id"},
    )
    a.complete(_ASK)
    a.complete(_ASK)
    paths = [p for p, _ in app.seen]
    assert paths == ["/sessions", "/chat", "/sessions", "/chat"]
    chats = [body for p, body in app.seen if p == "/chat"]
    assert [c["conversation_id"] for c in chats] == ["conv-1", "conv-2"]


def test_a_relative_init_url_resolves_against_the_endpoint(app):
    """So the operator writes the path their API docs show, not a second full URL."""
    a = AppEndpointAdapter(
        endpoint=f"{app.base}/api/chat",
        session_field="cid",
        session_init={"url": "/sessions", "response_path": "conversation_id"},
    )
    a.complete(_ASK)
    assert next(p for p, _ in app.seen) == "/sessions"


def test_the_init_body_and_method_reach_the_application(app):
    a = AppEndpointAdapter(
        endpoint=f"{app.base}/chat",
        session_field="cid",
        session_init={"url": "/sessions", "method": "post",
                      "body": {"agent_slug": "support-bot"},
                      "response_path": "conversation_id"},
    )
    a.complete(_ASK)
    assert app.seen[0] == ("/sessions", {"agent_slug": "support-bot"})


def test_a_session_init_must_name_its_response_path(app):
    """Never auto-detected. The reply-shape detection reads `message`/`content`/`text`,
    which a session response plausibly also carries, so a guess here would take "created"
    for a conversation id and report the numbers as if the session had been set."""
    a = AppEndpointAdapter(endpoint=f"{app.base}/chat", session_field="cid",
                           session_init={"url": "/sessions"})
    with pytest.raises(AdapterError, match="needs a 'response_path'"):
        a.complete(_ASK)
    assert app.seen == [], "no request is made on a spec that cannot be honoured"


# --- the refusals, which are where a wrong measurement would come from -------

def test_an_init_without_a_field_to_put_it_in_is_refused():
    with pytest.raises(AdapterError, match="thrown away"):
        AppEndpointAdapter(endpoint="http://x/chat", session_init={"url": "/s"})


def test_an_unknown_init_key_is_refused_rather_than_ignored():
    """A misspelled `response_path` would otherwise leave the scan auto-detecting some
    other field and reporting the numbers as if the session had been set."""
    a = AppEndpointAdapter(endpoint="http://x/chat", session_field="cid",
                           session_init={"url": "/s", "responsePath": "id"})
    with pytest.raises(AdapterError, match="unknown key"):
        a.complete(_ASK)


def test_an_init_without_a_url_is_refused():
    a = AppEndpointAdapter(endpoint="http://x/chat", session_field="cid", session_init={})
    with pytest.raises(AdapterError, match="needs a 'url'"):
        a.complete(_ASK)


def test_a_reply_with_no_session_value_names_the_session_step():
    a = _App(session_reply={"detail": "created"})
    try:
        adapter = AppEndpointAdapter(
            endpoint=f"{a.base}/chat", session_field="cid",
            session_init={"url": "/sessions", "response_path": "conversation_id"},
        )
        with pytest.raises(AdapterError, match="no session value"):
            adapter.complete(_ASK)
        assert not [p for p, _ in a.seen if p == "/chat"], "no probe is sent blind"
    finally:
        a.close()


def test_an_empty_session_value_is_refused():
    """An empty id would silently put every probe back in the application's default
    session, which is the state this whole flag exists to leave."""
    a = _App(session_reply={"conversation_id": ""})
    try:
        adapter = AppEndpointAdapter(
            endpoint=f"{a.base}/chat", session_field="cid",
            session_init={"url": "/sessions", "response_path": "conversation_id"},
        )
        with pytest.raises(AdapterError, match="empty session value"):
            adapter.complete(_ASK)
    finally:
        a.close()


def test_a_failed_session_step_is_never_a_timeout_finding():
    """The honesty property. ``AdapterTimeoutError`` is the class the two bounded LLM10
    probes score as a finding, so a session step that fails must stay out of it."""
    a = _App(session_status=500)
    try:
        adapter = AppEndpointAdapter(
            endpoint=f"{a.base}/chat", session_field="cid",
            session_init={"url": "/sessions", "response_path": "conversation_id"},
        )
        with pytest.raises(AdapterError) as caught:
            adapter.complete(_ASK)
        assert not isinstance(caught.value, AdapterTimeoutError)
        assert "session step" in str(caught.value)
    finally:
        a.close()


# --- the CLI contract --------------------------------------------------------

def test_both_flags_reach_the_adapter_through_the_environment(monkeypatch):
    monkeypatch.setenv(envvars.APP_SESSION_FIELD, "conversation_id")
    monkeypatch.setenv(envvars.APP_SESSION_INIT,
                       json.dumps({"url": "/sessions", "response_path": "id"}))
    a = resolve_target("app:http://x/chat", app_shape=envvars.app_shape_from_env())
    assert a.session_field == "conversation_id"
    assert a.session_init == {"url": "/sessions", "response_path": "id"}


@pytest.mark.parametrize("raw", ['{"url"', '"a string"', "[1,2]"])
def test_a_malformed_session_init_fails_loudly(monkeypatch, raw):
    monkeypatch.setenv(envvars.APP_SESSION_INIT, raw)
    with pytest.raises(SystemExit):
        envvars.app_shape_from_env()


def test_the_cli_refuses_an_init_with_nowhere_to_put_the_value(monkeypatch, capsys):
    from llmsectest.__main__ import main

    monkeypatch.setattr("sys.argv", ["llmsectest", "--target", "app:http://x/chat",
                                     "--app-session-init", '{"url": "/s"}'])
    assert main() == 2
    assert "--app-session-field" in capsys.readouterr().err


def test_a_mistyped_response_path_is_named_rather_than_raising_a_keyerror(app):
    """Found by writing the session tests, and it predates them: `_extract` named a path
    that walked into a scalar and let a missing dict key out as a bare `KeyError`."""
    a = AppEndpointAdapter(endpoint=f"{app.base}/chat", response_path="repl")
    with pytest.raises(AdapterError, match="does not match the reply JSON"):
        a.complete(_ASK)
