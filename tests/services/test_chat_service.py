import pytest
from langchain_core.messages import AIMessage, HumanMessage

from app.schemas.chat import ChatRequest
from app.services import chat_service as svc
from app.services.chat_store import ChatStore, SessionNotFoundError
from tests.conftest import FakeRegistry


ATTACK = "GET /x?q=<script>alert(1)</script> HTTP/1.1"


def canned_reply(session, analysis) -> str:
    return "Agithar says hello."


def test_respond_creates_session_and_stores_turn():
    store = ChatStore(ttl_seconds=600)
    reply = svc.respond(
        store, FakeRegistry(), 7, ChatRequest(input=ATTACK), canned_reply
    )
    session = store.get(7, reply.session_id)

    assert reply.message.content == "Agithar says hello."
    assert reply.message.evidence_refs == []
    assert [m.role for m in session.messages] == ["analyst", "system"]
    assert reply.evidence
    assert reply.evidence[0].detector == "http_payload_sensor"


def test_unknown_session_id_is_never_created():
    store = ChatStore(ttl_seconds=600)
    request = ChatRequest(input="hello", session_id="does-not-exist")

    with pytest.raises(SessionNotFoundError):
        svc.respond(store, FakeRegistry(), 7, request)

    assert store.list_for_owner(7, 0, 10)[1] == 0


def test_stream_events_order_and_cumulative_tokens():
    store = ChatStore(ttl_seconds=600)
    reply = svc.respond(store, FakeRegistry(), 1, ChatRequest(input=ATTACK))
    events = list(svc.stream_events(reply))
    tokens = [e.text for e in events if e.type == "token"]

    assert events[0].type == "evidence"
    assert events[-1].type == "done"
    assert tokens[-1] == reply.message.content
    assert all(reply.message.content.startswith(t) for t in tokens)


def test_history_messages_limit_and_roles():
    store = ChatStore(ttl_seconds=600)
    session_id = None

    for text in ["one", "two", "three"]:
        request = ChatRequest(input=text, session_id=session_id)
        session_id = svc.respond(
            store, FakeRegistry(), 1, request, canned_reply
        ).session_id

    history = svc.history_messages(store.get(1, session_id), 4)

    assert len(history) == 4
    assert isinstance(history[0], HumanMessage)
    assert isinstance(history[1], AIMessage)
    assert svc.history_messages(store.get(1, session_id), 0) == []


def test_status_text_uses_fixed_labels():
    call = {"name": "shop_traffic", "args": {"shop": "maisonroast<b>"}}

    assert "maisonroast" in svc.status_text(call)
    assert "<b>" not in svc.status_text(call)
    assert svc.status_text({"name": "rm -rf /", "args": {}}) == "Using rmrf"
