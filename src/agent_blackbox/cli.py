"""CLI for Agent Blackbox."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .core import AgentBlackbox


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Agent Blackbox incident review utility")
    parser.add_argument("--storage", default="./blackbox_logs", help="Blackbox log directory")

    sub = parser.add_subparsers(dest="command")

    review = sub.add_parser("review", help="Review an incident event hash")
    review.add_argument("event_hash")

    # Backward-compatible alias.
    blame = sub.add_parser("blame", help="Alias for review")
    blame.add_argument("event_hash")

    tree = sub.add_parser("tree", help="Show declared dependency tree")
    tree.add_argument("event_hash")

    verify = sub.add_parser("verify", help="Verify a locally recorded event")
    verify.add_argument("event_hash")

    return parser


def main() -> None:
    args = build_parser().parse_args()
    blackbox = AgentBlackbox(storage=args.storage)

    # This CLI operates on in-memory events in the current process for the alpha.
    # Future versions will load persisted JSONL logs into the index.
    if args.command in {"review", "blame"}:
        print(json.dumps(blackbox.review_incident(args.event_hash), indent=2))
    elif args.command == "tree":
        print(json.dumps(blackbox.get_causality_tree(args.event_hash), indent=2))
    elif args.command == "verify":
        print(json.dumps({"valid": blackbox.verify_event(args.event_hash)}, indent=2))
    else:
        build_parser().print_help()


if __name__ == "__main__":
    main()
