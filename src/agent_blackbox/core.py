"""Agent Blackbox core tracing and incident review."""

from __future__ import annotations

import functools
import json
import time
import uuid
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from cryptography.hazmat.primitives.asymmetric import ed25519

from .jep import (
    HJS_EVIDENCE_EXT,
    JAC_CHAIN_EXT,
    JEPEvent,
    Verb,
    digest_value,
    make_hjs_evidence_refs,
    make_jac_chain_ext,
)


@dataclass
class TraceRecord:
    event_hash: str
    agent_name: str
    status: str
    started_at: int
    finished_at: int
    parent_event_hash: Optional[str]
    input_digest: Optional[str]
    output_digest: Optional[str]
    error_digest: Optional[str]
    event: Dict[str, Any]


@dataclass
class IncidentReview:
    incident: str
    candidate_failure_node: str
    diagnostic_summary: str
    review_score: float
    chain: List[Dict[str, Any]]
    boundary: Dict[str, bool]


class AgentBlackbox:
    """Runtime recorder for agent workflow events.

    AgentBlackbox records JEP-style events and JAC dependency links. It supports
    incident review, but it does not make legal or factual determinations.
    """

    def __init__(self, storage: str = "./blackbox_logs", audience: str = "agent-blackbox"):
        self.storage = Path(storage)
        self.storage.mkdir(parents=True, exist_ok=True)
        self.audience = audience

        self._keys: Dict[str, ed25519.Ed25519PrivateKey] = {}
        self.events: Dict[str, JEPEvent] = {}
        self.traces: Dict[str, TraceRecord] = {}

        self.log_path = self.storage / "events.jsonl"

    # Backward-compatible alias.
    @property
    def receipts(self):
        return self.events

    def _get_agent_private_key(self, agent_name: str) -> ed25519.Ed25519PrivateKey:
        if agent_name not in self._keys:
            self._keys[agent_name] = ed25519.Ed25519PrivateKey.generate()
        return self._keys[agent_name]

    def _get_agent_public_key(self, agent_name: str):
        return self._get_agent_private_key(agent_name).public_key()

    def trace(
        self,
        agent_name: str,
        parent_event_hash: Optional[str] = None,
        relation: str = "derived-from",
        verb: Verb = Verb.JUDGMENT,
        parent_task_hash: Optional[str] = None,  # backward-compatible input
    ) -> Callable:
        """Trace an agent function.

        `parent_task_hash` is accepted for backward compatibility but is mapped
        into the JAC v0.5 chain extension as `based_on`.
        """

        if parent_event_hash is None and parent_task_hash is not None:
            parent_event_hash = parent_task_hash

        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                started = int(time.time())
                input_digest = digest_value({"args": args, "kwargs": kwargs})
                output_digest = None
                error_digest = None
                status = "success"
                result = None
                error_obj = None

                try:
                    result = func(*args, **kwargs)
                    output_digest = digest_value(result)
                    return result
                except Exception as exc:
                    status = "failed"
                    error_obj = {"type": exc.__class__.__name__, "message": str(exc)}
                    error_digest = digest_value(error_obj)
                    raise
                finally:
                    finished = int(time.time())
                    event = self._make_event(
                        agent_name=agent_name,
                        verb=verb,
                        status=status,
                        started_at=started,
                        finished_at=finished,
                        parent_event_hash=parent_event_hash,
                        relation=relation,
                        input_digest=input_digest,
                        output_digest=output_digest,
                        error_digest=error_digest,
                        error=error_obj,
                    )
                    self._store_event(event, agent_name, status, started, finished, parent_event_hash, input_digest, output_digest, error_digest)

            return wrapper

        return decorator

    def _make_event(
        self,
        agent_name: str,
        verb: Verb,
        status: str,
        started_at: int,
        finished_at: int,
        parent_event_hash: Optional[str],
        relation: str,
        input_digest: Optional[str],
        output_digest: Optional[str],
        error_digest: Optional[str],
        error: Optional[Dict[str, Any]],
    ) -> JEPEvent:
        what = {
            "type": "agent-runtime-trace",
            "status": status,
            "input_digest": input_digest,
            "output_digest": output_digest,
            "error_digest": error_digest,
            "error": error,
        }

        based_on_type = "jep-event" if parent_event_hash else "chain-root"
        chain_relation = relation if parent_event_hash else "chain-root"

        ext = {
            JAC_CHAIN_EXT: make_jac_chain_ext(
                based_on=parent_event_hash,
                based_on_type=based_on_type,
                relation=chain_relation,
            ),
            HJS_EVIDENCE_EXT: make_hjs_evidence_refs(
                input_digest=input_digest,
                output_digest=output_digest,
                error_digest=error_digest,
            ),
        }

        event = JEPEvent(
            verb=verb,
            who=agent_name,
            when=finished_at,
            what=what,
            nonce=str(uuid.uuid4()),
            aud=self.audience,
            ref=parent_event_hash,
            ext=ext,
            ext_crit=[JAC_CHAIN_EXT],
        )
        event.sign(self._get_agent_private_key(agent_name), kid=f"{agent_name}#local")
        return event

    def _store_event(
        self,
        event: JEPEvent,
        agent_name: str,
        status: str,
        started_at: int,
        finished_at: int,
        parent_event_hash: Optional[str],
        input_digest: Optional[str],
        output_digest: Optional[str],
        error_digest: Optional[str],
    ) -> str:
        event_hash = event.event_hash()
        self.events[event_hash] = event
        record = TraceRecord(
            event_hash=event_hash,
            agent_name=agent_name,
            status=status,
            started_at=started_at,
            finished_at=finished_at,
            parent_event_hash=parent_event_hash,
            input_digest=input_digest,
            output_digest=output_digest,
            error_digest=error_digest,
            event=event.to_dict(),
        )
        self.traces[event_hash] = record

        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(record), ensure_ascii=False) + "\n")

        return event_hash

    def review_incident(self, incident_hash: str) -> Dict[str, Any]:
        """Review an incident and reconstruct declared chain context.

        This does not assign blame. It identifies candidate failure nodes for
        human or external review.
        """

        if incident_hash not in self.traces:
            return {
                "incident": incident_hash,
                "candidate_failure_node": "not_found",
                "diagnostic_summary": "No event found for the supplied incident hash.",
                "review_score": 0.0,
                "chain": [],
                "boundary": self._boundary(),
            }

        chain = self.reconstruct_chain(incident_hash)
        incident = self.traces[incident_hash]

        if incident.status == "failed":
            candidate = incident.agent_name
            summary = "The selected event has status failed. Review declared parents and evidence references."
            score = 0.72
        else:
            failed = [node for node in chain if node.get("status") == "failed"]
            if failed:
                candidate = failed[-1]["agent"]
                summary = "A failed event appears in the declared chain. Review surrounding evidence."
                score = 0.62
            else:
                candidate = "undetermined"
                summary = "No failed event was found in the observed declared chain."
                score = 0.25

        return asdict(IncidentReview(
            incident=incident_hash,
            candidate_failure_node=candidate,
            diagnostic_summary=summary,
            review_score=score,
            chain=chain,
            boundary=self._boundary(),
        ))

    # Backward-compatible alias.
    def blame(self, incident_id: str) -> Dict[str, Any]:
        review = self.review_incident(incident_id)
        return {
            "incident": review["incident"],
            "verdict": review["candidate_failure_node"],
            "reason": review["diagnostic_summary"],
            "confidence": review["review_score"],
            "chain": review["chain"],
            "boundary": review["boundary"],
        }

    def reconstruct_chain(self, event_hash: str) -> List[Dict[str, Any]]:
        chain: List[Dict[str, Any]] = []
        seen = set()
        current = event_hash

        while current and current not in seen:
            seen.add(current)
            record = self.traces.get(current)
            if not record:
                chain.append({"event_hash": current, "missing": True})
                break
            chain.append({
                "event_hash": current,
                "agent": record.agent_name,
                "status": record.status,
                "parent_event_hash": record.parent_event_hash,
                "input_digest": record.input_digest,
                "output_digest": record.output_digest,
                "error_digest": record.error_digest,
            })
            current = record.parent_event_hash

        chain.reverse()
        return chain

    def get_causality_tree(self, root_hash: str) -> Dict[str, Any]:
        if root_hash not in self.traces:
            return {"hash": root_hash, "missing": True}

        record = self.traces[root_hash]
        children = [
            self.get_causality_tree(h)
            for h, t in self.traces.items()
            if t.parent_event_hash == root_hash
        ]
        return {
            "hash": root_hash,
            "agent": record.agent_name,
            "status": record.status,
            "verb": record.event.get("verb"),
            "children": children,
        }

    def verify_event(self, event_hash: str) -> bool:
        event = self.events.get(event_hash)
        if not event:
            return False
        return event.verify(self._get_agent_public_key(event.who))

    # Backward-compatible alias.
    def verify_receipt(self, receipt_hash: str) -> bool:
        return self.verify_event(receipt_hash)

    def _boundary(self) -> Dict[str, bool]:
        return {
            "not_legal_liability": True,
            "not_factual_causality_proof": True,
            "not_compliance_determination": True,
            "not_complete_log_proof": True,
        }
