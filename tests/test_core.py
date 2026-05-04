"""Tests for Agent Blackbox."""

import pytest

from agent_blackbox import AgentBlackbox, JEPEvent, Verb
from agent_blackbox.jep import JAC_CHAIN_EXT, HJS_EVIDENCE_EXT


def test_jep_event_sign_and_verify():
    finder = AgentBlackbox()
    event = JEPEvent(
        verb=Verb.JUDGMENT,
        who="test-agent",
        when=1234567890,
        what={"claim": "decision"},
        nonce="nonce-1",
    )
    key = finder._get_agent_private_key("test-agent")
    event.sign(key)
    assert event.verify(key.public_key()) is True
    assert event.event_hash().startswith("sha256:")


def test_trace_decorator_success(tmp_path):
    box = AgentBlackbox(storage=str(tmp_path))

    @box.trace(agent_name="test-agent")
    def add(a, b):
        return a + b

    assert add(2, 3) == 5
    assert len(box.events) == 1
    event_hash = list(box.events.keys())[0]
    event = box.events[event_hash]
    assert event.ext[JAC_CHAIN_EXT]["based_on_type"] == "chain-root"
    assert HJS_EVIDENCE_EXT in event.ext
    assert box.verify_event(event_hash) is True


def test_trace_decorator_failure(tmp_path):
    box = AgentBlackbox(storage=str(tmp_path))

    @box.trace(agent_name="test-agent")
    def fail():
        raise ValueError("Something went wrong")

    with pytest.raises(ValueError):
        fail()

    event_hash = list(box.events.keys())[0]
    trace = box.traces[event_hash]
    assert trace.status == "failed"
    assert trace.error_digest is not None


def test_parent_task_hash_maps_to_jac_ext(tmp_path):
    box = AgentBlackbox(storage=str(tmp_path))
    parent = "sha256:" + "a" * 64

    @box.trace(agent_name="child-agent", parent_task_hash=parent)
    def child():
        return "ok"

    child()
    event_hash = list(box.events.keys())[0]
    event = box.events[event_hash]
    assert event.ref == parent
    assert event.ext[JAC_CHAIN_EXT]["based_on"] == parent
    assert "task_based_on" not in event.to_dict()


def test_review_incident_failed_node(tmp_path):
    box = AgentBlackbox(storage=str(tmp_path))

    @box.trace(agent_name="bad-agent")
    def fail():
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        fail()

    event_hash = list(box.events.keys())[0]
    report = box.review_incident(event_hash)
    assert report["candidate_failure_node"] == "bad-agent"
    assert report["boundary"]["not_legal_liability"] is True


def test_blame_alias_kept_but_boundary_present(tmp_path):
    box = AgentBlackbox(storage=str(tmp_path))

    @box.trace(agent_name="agent")
    def ok():
        return "ok"

    ok()
    event_hash = list(box.events.keys())[0]
    result = box.blame(event_hash)
    assert "verdict" in result
    assert result["boundary"]["not_factual_causality_proof"] is True


def test_causality_tree(tmp_path):
    box = AgentBlackbox(storage=str(tmp_path))

    @box.trace(agent_name="root")
    def root():
        return "root"

    root()
    root_hash = list(box.events.keys())[0]

    @box.trace(agent_name="child", parent_event_hash=root_hash)
    def child():
        return "child"

    child()

    tree = box.get_causality_tree(root_hash)
    assert tree["agent"] == "root"
    assert len(tree["children"]) == 1
