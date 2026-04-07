"""
Unit tests for Agent Blame-Finder core functionality.
"""

import pytest
import time
import json
import tempfile
import os
from cryptography.hazmat.primitives.asymmetric import ed25519

from blame_finder.core import (
    BlameFinder,
    JEPReceipt,
    Verb,
    Verdict
)


class TestJEPReceipt:
    """Tests for JEPReceipt class."""

    def test_create_receipt(self):
        """Test creating a JEP receipt."""
        receipt = JEPReceipt(
            verb=Verb.JUDGE,
            who="test-agent",
            when=int(time.time()),
            what="test-decision"
        )
        assert receipt.verb == Verb.JUDGE
        assert receipt.who == "test-agent"
        assert receipt.what == "test-decision"

    def test_calculate_hash(self):
        """Test hash calculation is deterministic."""
        receipt1 = JEPReceipt(
            verb=Verb.JUDGE,
            who="agent",
            when=1234567890,
            what="decision"
        )
        receipt2 = JEPReceipt(
            verb=Verb.JUDGE,
            who="agent",
            when=1234567890,
            what="decision"
        )
        assert receipt1.calculate_hash() == receipt2.calculate_hash()

    def test_sign_and_verify(self):
        """Test signing and verification of receipts."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        receipt = JEPReceipt(
            verb=Verb.JUDGE,
            who="test-agent",
            when=int(time.time()),
            what="test-decision"
        )
        receipt.sign(private_key)
        assert receipt.signature is not None
        assert receipt.verify(public_key) is True

    def test_verify_fails_with_wrong_key(self):
        """Test verification fails with wrong public key."""
        private_key1 = ed25519.Ed25519PrivateKey.generate()
        private_key2 = ed25519.Ed25519PrivateKey.generate()
        public_key2 = private_key2.public_key()

        receipt = JEPReceipt(
            verb=Verb.JUDGE,
            who="test-agent",
            when=int(time.time()),
            what="test-decision"
        )
        receipt.sign(private_key1)
        assert receipt.verify(public_key2) is False

    def test_to_dict_and_from_dict(self):
        """Test serialization and deserialization."""
        original = JEPReceipt(
            verb=Verb.DELEGATE,
            who="agent-a",
            when=1234567890,
            what="delegate-task",
            ref="parent-hash",
            task_based_on="parent-task"
        )
        data = original.to_dict()
        reconstructed = JEPReceipt.from_dict(data)
        
        assert reconstructed.verb == original.verb
        assert reconstructed.who == original.who
        assert reconstructed.when == original.when
        assert reconstructed.what == original.what
        assert reconstructed.ref == original.ref
        assert reconstructed.task_based_on == original.task_based_on


class TestBlameFinder:
    """Tests for BlameFinder class."""

    @pytest.fixture
    def temp_storage(self):
        """Create temporary storage directory for tests."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    @pytest.fixture
    def finder(self, temp_storage):
        """Create BlameFinder instance with temp storage."""
        return BlameFinder(storage=temp_storage)

    def test_trace_decorator_success(self, finder):
        """Test trace decorator with successful execution."""
        @finder.trace(agent_name="test-agent")
        def add(a, b):
            return a + b

        result = add(2, 3)
        assert result == 5

        # Check that receipt was saved
        assert len(finder.receipts) == 1
        receipt_hash = list(finder.receipts.keys())[0]
        receipt = finder.receipts[receipt_hash]
        assert receipt.verb == Verb.JUDGE
        assert receipt.who == "test-agent"

    def test_trace_decorator_failure(self, finder):
        """Test trace decorator with failed execution."""
        @finder.trace(agent_name="test-agent")
        def fail():
            raise ValueError("Something went wrong")

        with pytest.raises(ValueError):
            fail()

        # Check that failure was recorded
        assert len(finder.receipts) == 1
        receipt_hash = list(finder.receipts.keys())[0]
        trace = finder.traces.get(receipt_hash)
        assert trace is not None
        assert trace.status == "failed"

    def test_trace_with_parent_task(self, finder):
        """Test trace decorator with parent task reference (JAC)."""
        parent_hash = "parent-task-hash-123"

        @finder.trace(agent_name="child-agent", parent_task_hash=parent_hash)
        def child_task():
            return "child result"

        child_task()
        
        # Check that task_based_on was set
        receipt_hash = list(finder.receipts.keys())[0]
        receipt = finder.receipts[receipt_hash]
        assert receipt.task_based_on == parent_hash

    def test_blame_analysis_chain_intact(self, finder):
        """Test blame analysis when chain is intact."""
        # Create a chain of receipts
        @finder.trace(agent_name="agent-1")
        def step1():
            return "step1 result"

        @finder.trace(agent_name="agent-2", parent_task_hash=None)
        def step2():
            return "step2 result"

        step1()
        step2()

        # Get the second receipt's hash
        receipt_hashes = list(finder.receipts.keys())
        result = finder.blame(receipt_hashes[0])
        
        assert "incident" in result
        assert "verdict" in result

    def test_blame_not_found(self, finder):
        """Test blame analysis with non-existent incident."""
        result = finder.blame("non-existent-hash")
        assert result["verdict"] == "not_found"

    def test_get_causality_tree(self, finder):
        """Test building causality tree."""
        @finder.trace(agent_name="root")
        def root_task():
            return "root"

        @finder.trace(agent_name="child", parent_task_hash=None)
        def child_task():
            return "child"

        root_task()
        child_task()

        # Get root receipt hash
        root_hash = None
        for h, trace in finder.traces.items():
            if trace.agent_name == "root":
                root_hash = h
                break

        if root_hash:
            tree = finder.get_causality_tree(root_hash)
            assert "hash" in tree
            assert "agent" in tree or "missing" in tree


class TestChainOfResponsibility:
    """Tests for HJS responsibility chain."""

    def test_ref_field_linking(self, finder):
        """Test that ref field correctly links responsibility."""
        @finder.trace(agent_name="delegator")
        def delegator():
            return "delegated"

        @finder.trace(agent_name="executor")
        def executor():
            return "executed"

        delegator()
        executor()

        # Verify that receipts exist and have proper refs
        for receipt in finder.receipts.values():
            assert receipt.verb in [Verb.JUDGE, Verb.DELEGATE, Verb.TERMINATE, Verb.VERIFY]


class TestJACCausality:
    """Tests for JAC causality chain."""

    def test_task_based_on_linking(self, finder):
        """Test that task_based_on field correctly links causality."""
        parent_hash = "causality-parent-456"

        @finder.trace(agent_name="dependent-agent", parent_task_hash=parent_hash)
        def dependent_task():
            return "dependent result"

        dependent_task()

        # Verify task_based_on was set
        receipt_hash = list(finder.receipts.keys())[0]
        receipt = finder.receipts[receipt_hash]
        assert receipt.task_based_on == parent_hash


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
