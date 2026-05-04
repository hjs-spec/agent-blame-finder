# Agent Blackbox v0.2.0-alpha Release Notes

## Summary

This release reframes the project from "blame finder" into a JEP/HJS/JAC runtime blackbox recorder for incident review and chain reconstruction.

## Added

- AgentBlackbox core class.
- JEP v0.6-style event object.
- JEP event hashes.
- Detached JWS-shaped Ed25519 signatures.
- JAC v0.5 chain extension using `ext["https://jac.org/chain"]`.
- HJS evidence reference extension using input/output/error digests.
- Incident review report.
- Declared chain reconstruction.
- Boundary statements in reports and README.
- Tests for chain extension and review behavior.

## Changed

- Removed "find exactly who to blame" positioning.
- Replaced legal/factual blame language with incident review terminology.
- Deprecated top-level `task_based_on`; backward-compatible input maps to JAC extension.
- Renamed package to `agent_blackbox`.
- Kept `blame-finder` CLI alias for transition.

## Known Limitations

- Persistence reload from JSONL is not yet implemented.
- Dashboard is not implemented in this alpha.
- Review score is diagnostic only.
- This release does not claim production conformance.
