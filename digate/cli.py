"""Command-line interface."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from digate.config import Settings
from digate.demo import print_demo, run_demo
from digate.gateway import PromotionGateway
from digate.hashing import sha256_file, sha256_text
from digate.models import Candidate, PromotionRequest, ScanVerdict, VerdictOutcome


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="digate", description="Digest-bound release promotion gateway")
    parser.add_argument("--data-dir", default="data", help="Local state directory")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("demo", help="Run the ReleaseProof assertion demo")

    reg = sub.add_parser("register", help="Register a candidate digest")
    reg.add_argument("--release-id", required=True)
    reg.add_argument("--digest", help="sha256 hex digest")
    reg.add_argument("--file", help="Hash this file instead of --digest")
    reg.add_argument("--image-ref", default="")

    seal = sub.add_parser("seal", help="Issue a signed scan verdict")
    seal.add_argument("--release-id", required=True)
    seal.add_argument("--digest", required=True)
    seal.add_argument("--outcome", choices=["pass", "fail"], default="pass")
    seal.add_argument("--out", required=True, help="Write signed verdict JSON")

    promo = sub.add_parser("promote", help="Attempt promotion with a signed verdict")
    promo.add_argument("--release-id", required=True)
    promo.add_argument("--digest", required=True)
    promo.add_argument("--verdict", required=True, help="Path to signed verdict JSON")

    status = sub.add_parser("status", help="Show release state")
    status.add_argument("--release-id", required=True)

    digest = sub.add_parser("digest", help="Compute sha256 for text or file")
    digest.add_argument("--text")
    digest.add_argument("--file")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    settings = Settings(data_dir=Path(args.data_dir))

    if args.command == "demo":
        print_demo()
        return 0

    if args.command == "digest":
        if args.file:
            print(sha256_file(Path(args.file)))
        elif args.text is not None:
            print(sha256_text(args.text))
        else:
            parser.error("digest requires --text or --file")
        return 0

    gateway = PromotionGateway(settings)

    if args.command == "register":
        digest = args.digest
        if args.file:
            digest = sha256_file(Path(args.file))
        if not digest:
            parser.error("register requires --digest or --file")
        record = gateway.register_candidate(
            Candidate(release_id=args.release_id, digest=digest, image_ref=args.image_ref)
        )
        print(record.model_dump_json(indent=2))
        return 0

    if args.command == "seal":
        signed = gateway.issue_verdict(
            ScanVerdict(
                release_id=args.release_id,
                digest=args.digest,
                outcome=VerdictOutcome(args.outcome),
                scanner="cli-scanner",
            )
        )
        Path(args.out).write_text(signed.model_dump_json(indent=2) + "\n", encoding="utf-8")
        print(signed.model_dump_json(indent=2))
        return 0

    if args.command == "promote":
        verdict = json.loads(Path(args.verdict).read_text(encoding="utf-8"))
        from digate.models import SignedVerdict

        result = gateway.promote(
            PromotionRequest(
                release_id=args.release_id,
                candidate_digest=args.digest,
                verdict=SignedVerdict.model_validate(verdict),
            )
        )
        print(result.model_dump_json(indent=2))
        return 0 if result.accepted else 1

    if args.command == "status":
        record = gateway.status(args.release_id)
        if record is None:
            print("{}")
            return 1
        print(record.model_dump_json(indent=2))
        return 0

    return 1
