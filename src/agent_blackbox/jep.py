"""JEP v0.6-style event objects for Agent Blackbox."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional, List

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519


JEP_WIRE_VERSION = "1"
JEP_CORE_PROFILE = "jep-core-0.6"
JAC_CHAIN_EXT = "https://jac.org/chain"
HJS_EVIDENCE_EXT = "https://hjs.org/evidence-refs"


class Verb(str, Enum):
    JUDGMENT = "J"
    DELEGATION = "D"
    TERMINATION = "T"
    VERIFICATION = "V"

    # Backward-compatible names
    JUDGE = "J"
    DELEGATE = "D"
    TERMINATE = "T"
    VERIFY = "V"


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64u_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def canonicalize(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def tagged_hash(obj: Any) -> str:
    raw = obj if isinstance(obj, bytes) else canonicalize(obj)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def digest_value(value: Any) -> str:
    if isinstance(value, bytes):
        return tagged_hash(value)
    if isinstance(value, str):
        return tagged_hash(value.encode("utf-8"))
    return tagged_hash(value)


@dataclass
class JEPEvent:
    """JEP v0.6-style event used by Agent Blackbox.

    This is an implementation seed object, not a full replacement for the
    normative JEP-Core specification.
    """

    verb: Verb
    who: str
    when: int
    what: Any
    nonce: str
    aud: str = "agent-blackbox"
    ref: Optional[str] = None
    ext: Dict[str, Any] = field(default_factory=dict)
    ext_crit: List[str] = field(default_factory=list)
    sig: Optional[str] = None

    def unsigned_dict(self) -> Dict[str, Any]:
        data = {
            "jep": JEP_WIRE_VERSION,
            "verb": self.verb.value,
            "who": self.who,
            "when": self.when,
            "what": self.what,
            "nonce": self.nonce,
            "aud": self.aud,
            "ref": self.ref,
        }
        if self.ext:
            data["ext"] = self.ext
        if self.ext_crit:
            data["ext_crit"] = self.ext_crit
        return data

    def to_dict(self) -> Dict[str, Any]:
        data = self.unsigned_dict()
        data["sig"] = self.sig
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "JEPEvent":
        return cls(
            verb=Verb(data["verb"]),
            who=data["who"],
            when=int(data["when"]),
            what=data.get("what"),
            nonce=data["nonce"],
            aud=data.get("aud", "agent-blackbox"),
            ref=data.get("ref"),
            ext=data.get("ext", {}),
            ext_crit=data.get("ext_crit", []),
            sig=data.get("sig"),
        )

    def event_hash(self) -> str:
        return tagged_hash(self.to_dict())

    def unsigned_hash(self) -> str:
        return tagged_hash(self.unsigned_dict())

    def sign(self, private_key: ed25519.Ed25519PrivateKey, kid: str = "local-agent-key") -> str:
        protected = {
            "alg": "Ed25519",
            "kid": kid,
            "typ": "jep-event+jws",
            "jep": JEP_WIRE_VERSION,
        }
        protected_b64 = b64u(canonicalize(protected))
        payload_b64 = b64u(canonicalize(self.unsigned_dict()))
        signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
        signature = private_key.sign(signing_input)
        self.sig = f"{protected_b64}..{b64u(signature)}"
        return self.sig

    def verify(self, public_key: ed25519.Ed25519PublicKey) -> bool:
        if not self.sig or self.sig.count(".") != 2:
            return False
        protected_b64, empty, sig_b64 = self.sig.split(".")
        if empty != "":
            return False
        payload_b64 = b64u(canonicalize(self.unsigned_dict()))
        signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
        try:
            public_key.verify(b64u_decode(sig_b64), signing_input)
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False


def make_jac_chain_ext(
    based_on: Optional[str],
    based_on_type: str = "jep-event",
    relation: str = "derived-from",
    observed_log_assumption: str = "partial",
) -> Dict[str, Any]:
    return {
        "based_on": based_on,
        "based_on_type": based_on_type,
        "relation": relation,
        "observed_log_assumption": observed_log_assumption,
    }


def make_hjs_evidence_refs(
    input_digest: Optional[str] = None,
    output_digest: Optional[str] = None,
    error_digest: Optional[str] = None,
) -> Dict[str, Any]:
    refs = {}
    if input_digest:
        refs["input_digest"] = input_digest
    if output_digest:
        refs["output_digest"] = output_digest
    if error_digest:
        refs["error_digest"] = error_digest
    return refs
