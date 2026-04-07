"""
Core implementation of JEP (Judgment Event Protocol) and JAC (Judgment Accountability Chain).
"""

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature


class Verb(Enum):
    """JEP protocol verbs - the four atomic operations."""
    JUDGE = "J"      # Make a judgment/decision
    DELEGATE = "D"   # Delegate responsibility to another agent
    TERMINATE = "T"  # End a judgment chain
    VERIFY = "V"     # Verify a previous judgment


class Verdict(Enum):
    """Blame analysis result."""
    CHAIN_INTACT = "chain_intact"
    BROKEN_LINK = "broken_link"
    MISSING_PARENT = "missing_parent"
    SIGNATURE_INVALID = "signature_invalid"


@dataclass
class JEPReceipt:
    """
    A JEP (Judgment Event Protocol) receipt.
    Immutable record of an agent's decision.
    """
    verb: Verb
    who: str           # Agent ID
    when: int          # Unix timestamp
    what: str          # Hash or description of the decision/action
    ref: Optional[str] = None      # HJS: responsibility chain - parent receipt hash
    task_based_on: Optional[str] = None  # JAC: causality chain - parent task hash
    signature: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert receipt to dictionary for serialization."""
        return {
            "verb": self.verb.value,
            "who": self.who,
            "when": self.when,
            "what": self.what,
            "ref": self.ref,
            "task_based_on": self.task_based_on,
            "sig": self.signature
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "JEPReceipt":
        """Create receipt from dictionary."""
        return cls(
            verb=Verb(data["verb"]),
            who=data["who"],
            when=data["when"],
            what=data["what"],
            ref=data.get("ref"),
            task_based_on=data.get("task_based_on"),
            signature=data.get("sig")
        )

    def calculate_hash(self) -> str:
        """Calculate SHA-256 hash of the receipt (excluding signature)."""
        content = {
            "verb": self.verb.value,
            "who": self.who,
            "when": self.when,
            "what": self.what,
            "ref": self.ref,
            "task_based_on": self.task_based_on
        }
        return hashlib.sha256(json.dumps(content, sort_keys=True).encode()).hexdigest()

    def sign(self, private_key: ed25519.Ed25519PrivateKey) -> "JEPReceipt":
        """Sign the receipt with an Ed25519 private key."""
        hash_value = self.calculate_hash()
        signature = private_key.sign(hash_value.encode())
        self.signature = signature.hex()
        return self

    def verify(self, public_key: ed25519.Ed25519PublicKey) -> bool:
        """Verify the receipt's signature."""
        if not self.signature:
            return False
        try:
            hash_value = self.calculate_hash()
            public_key.verify(bytes.fromhex(self.signature), hash_value.encode())
            return True
        except InvalidSignature:
            return False


@dataclass
class TraceContext:
    """Context for a traced agent execution."""
    agent_name: str
    receipt: JEPReceipt
    parent_receipt_hash: Optional[str] = None
    parent_task_hash: Optional[str] = None
    children: List[str] = field(default_factory=list)
    status: str = "pending"  # pending, success, failed


class BlameFinder:
    """
    Main class for Agent Blame-Finder.
    Installs a cryptographic blackbox in every agent.
    """

    def __init__(self, storage: str = "./blackbox_logs"):
        """
        Initialize BlameFinder.

        Args:
            storage: Path to storage directory for receipts
        """
        self.storage = storage
        self.receipts: Dict[str, JEPReceipt] = {}
        self.traces: Dict[str, TraceContext] = {}
        self._key_cache: Dict[str, ed25519.Ed25519PublicKey] = {}
        self._init_storage()

    def _init_storage(self):
        """Initialize storage directory."""
        import os
        os.makedirs(self.storage, exist_ok=True)

    def _save_receipt(self, receipt: JEPReceipt):
        """Save receipt to storage."""
        import os
        receipt_hash = receipt.calculate_hash()
        filepath = os.path.join(self.storage, f"{receipt_hash}.json")
        with open(filepath, "w") as f:
            json.dump(receipt.to_dict(), f, indent=2)
        self.receipts[receipt_hash] = receipt
        return receipt_hash

    def _load_receipt(self, receipt_hash: str) -> Optional[JEPReceipt]:
        """Load receipt from storage."""
        import os
        if receipt_hash in self.receipts:
            return self.receipts[receipt_hash]

        filepath = os.path.join(self.storage, f"{receipt_hash}.json")
        if not os.path.exists(filepath):
            return None
        with open(filepath, "r") as f:
            data = json.load(f)
        receipt = JEPReceipt.from_dict(data)
        self.receipts[receipt_hash] = receipt
        return receipt

    def trace(self, agent_name: str, parent_task_hash: Optional[str] = None):
        """
        Decorator to trace an agent's execution.

        Args:
            agent_name: Name/ID of the agent
            parent_task_hash: Hash of the parent task (for JAC causality chain)

        Usage:
            @finder.trace(agent_name="Coder-Agent")
            def my_function(...):
                ...
        """
        def decorator(func):
            def wrapper(*args, **kwargs):
                # Create JEP receipt for this judgment
                receipt = JEPReceipt(
                    verb=Verb.JUDGE,
                    who=agent_name,
                    when=int(time.time()),
                    what="",  # Will be filled after execution
                    ref=None,  # Will be set if parent exists
                    task_based_on=parent_task_hash
                )

                # Store context
                context = TraceContext(
                    agent_name=agent_name,
                    receipt=receipt,
                    parent_task_hash=parent_task_hash
                )

                try:
                    # Execute the actual function
                    result = func(*args, **kwargs)

                    # Update receipt with result hash
                    receipt.what = hashlib.sha256(
                        json.dumps({"result": str(result), "args": str(args), "kwargs": str(kwargs)}).encode()
                    ).hexdigest()

                    receipt.sign(self._get_agent_key(agent_name))
                    receipt_hash = self._save_receipt(receipt)

                    context.status = "success"
                    context.receipt = receipt
                    self.traces[receipt_hash] = context

                    return result

                except Exception as e:
                    # Record failure
                    receipt.what = hashlib.sha256(
                        json.dumps({"error": str(e), "args": str(args), "kwargs": str(kwargs)}).encode()
                    ).hexdigest()
                    receipt.sign(self._get_agent_key(agent_name))
                    receipt_hash = self._save_receipt(receipt)

                    context.status = "failed"
                    context.receipt = receipt
                    self.traces[receipt_hash] = context

                    raise e

            return wrapper
        return decorator

    def _get_agent_key(self, agent_name: str) -> ed25519.Ed25519PrivateKey:
        """
        Get or generate an Ed25519 key pair for an agent.
        In production, keys should be managed securely.
        """
        import os
        key_file = os.path.join(self.storage, f"{agent_name}.key")
        if os.path.exists(key_file):
            with open(key_file, "rb") as f:
                private_bytes = f.read()
            return ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
        else:
            private_key = ed25519.Ed25519PrivateKey.generate()
            with open(key_file, "wb") as f:
                f.write(private_key.private_bytes_raw())
            return private_key

    def blame(self, incident_id: str) -> Dict[str, Any]:
        """
        Analyze an incident and find out which agent is responsible.

        Args:
            incident_id: The receipt hash of the failed task

        Returns:
            Dict containing blame analysis result
        """
        receipt = self._load_receipt(incident_id)
        if not receipt:
            return {
                "incident": incident_id,
                "verdict": "not_found",
                "reason": f"No receipt found for {incident_id}"
            }

        # Trace back the causality chain
        chain = []
        current_hash = incident_id
        broken_link = None

        while current_hash:
            current_receipt = self._load_receipt(current_hash)
            if not current_receipt:
                broken_link = current_hash
                break

            # Verify signature
            agent_key = self._get_agent_public_key(current_receipt.who)
            if not current_receipt.verify(agent_key):
                return {
                    "incident": incident_id,
                    "verdict": Verdict.SIGNATURE_INVALID.value,
                    "reason": f"Signature invalid for {current_receipt.who}",
                    "chain": chain
                }

            chain.append({
                "agent": current_receipt.who,
                "verb": current_receipt.verb.value,
                "timestamp": current_receipt.when,
                "status": self.traces.get(current_hash, {}).get("status", "unknown")
            })

            # Move to parent via task_based_on (JAC causality)
            current_hash = current_receipt.task_based_on

        if broken_link:
            return {
                "incident": incident_id,
                "verdict": Verdict.BROKEN_LINK.value,
                "reason": f"Chain broken at {broken_link}",
                "chain": chain,
                "confidence": 0.95
            }

        # Determine who to blame (last failed node in the chain)
        blame_target = None
        for node in reversed(chain):
            if node["status"] == "failed":
                blame_target = node["agent"]
                break

        return {
            "incident": incident_id,
            "verdict": blame_target or Verdict.CHAIN_INTACT.value,
            "reason": f"{blame_target} caused the failure" if blame_target else "Chain intact, no single point of failure",
            "chain": chain,
            "confidence": 0.94 if blame_target else 0.70
        }

    def _get_agent_public_key(self, agent_name: str) -> ed25519.Ed25519PublicKey:
        """Get public key for an agent."""
        import os
        key_file = os.path.join(self.storage, f"{agent_name}.key")
        if os.path.exists(key_file):
            with open(key_file, "rb") as f:
                private_bytes = f.read()
            private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
            return private_key.public_key()
        # Generate a temporary key for verification
        temp_key = ed25519.Ed25519PrivateKey.generate()
        return temp_key.public_key()

    def get_causality_tree(self, root_hash: str) -> Dict[str, Any]:
        """
        Build a causality tree starting from a root receipt.

        Args:
            root_hash: Hash of the root receipt

        Returns:
            Nested dictionary representing the causality tree
        """
        def build_tree(hash_val: str) -> Dict[str, Any]:
            receipt = self._load_receipt(hash_val)
            if not receipt:
                return {"hash": hash_val, "missing": True}

            node = {
                "hash": hash_val,
                "agent": receipt.who,
                "verb": receipt.verb.value,
                "timestamp": receipt.when,
                "children": []
            }

            # Find all receipts that have this as parent
            for child_hash, child_trace in self.traces.items():
                if child_trace.parent_task_hash == hash_val:
                    node["children"].append(build_tree(child_hash))

            return node

        return build_tree(root_hash)
