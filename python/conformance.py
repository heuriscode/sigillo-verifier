"""Runs the Python verifier against the conformance vectors. Exit 0 = conforms.

python conformance.py ../vectors/verify_vectors.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verisigillo_verify as v  # noqa: E402


def main(path: str) -> int:
    with open(path, encoding="utf8") as fh:
        V = json.load(fh)
    failures: list[str] = []

    def expect(ok: bool, what: str) -> None:
        if not ok:
            failures.append(what)

    ledger, checkpoint = {V["keys"]["ledger_did"]}, {V["keys"]["checkpoint_did"]}
    for c in V["canon"]:
        expect(
            v.canon_text(c["input"]) == c["canonical_text"], f"canon text: {c['name']}"
        )
        expect(v.canon_hash(c["input"]) == c["hash"], f"canon hash: {c['name']}")

    rows, prev = [], None
    for link in V["seal_chain"]:
        checks = dict(
            v.check_receipt(
                link["receipt"],
                link["projection"],
                prev,
                ledger,
                payload=link["payload"],
            )
        )
        expect(
            all(checks.values()), f"receipt v{link['projection']['version']}: {checks}"
        )
        rows.append((link["projection"], prev, link["receipt"]["seal_hash"]))
        prev = link["receipt"]["seal_hash"]
    expect(v.chain_ok(rows), "chain")
    expect(not v.chain_ok(rows[::-1]), "reversed chain must fail")
    expect(not v.chain_ok(rows[1:]), "gapped chain must fail")

    first = V["seal_chain"][0]
    bad = {**first["payload"], "amount": 41}
    expect(
        dict(v.check_receipt(first["receipt"], first["projection"], None, ledger, bad))[
            "content"
        ]
        is False,
        "tampered payload",
    )
    expect(
        not v.proof_ok({**first["receipt"], "version": 9}, ledger), "tampered receipt"
    )
    expect(not v.proof_ok(first["receipt"], {"did:key:z6MkNotOurs"}), "untrusted key")
    edited = {**first["projection"], "note": "added later"}
    expect(
        dict(v.check_receipt(first["receipt"], edited, None, ledger))["seal_hash"]
        is False,
        "edited projection",
    )

    m = V["merkle"]
    for size, root in m["roots"].items():
        expect(v.merkle_root(m["leaves"][: int(size)]) == root, f"root {size}")
    for p in m["inclusion"]:
        root = m["roots"][str(p["tree_size"])]
        leaf = m["leaves"][p["index"]]
        where = f"{p['index']}/{p['tree_size']}"
        expect(
            v.inclusion_ok(leaf, p["index"], p["tree_size"], p["proof"], root), where
        )
        expect(
            not v.inclusion_ok(
                leaf + "x", p["index"], p["tree_size"], p["proof"], root
            ),
            f"bad inclusion {where}",
        )
    for c in m["consistency"]:
        old, new = m["roots"][str(c["old_size"])], m["roots"][str(c["new_size"])]
        expect(
            v.consistency_ok(c["old_size"], old, c["new_size"], new, c["proof"]),
            f"consistency {c['old_size']}->{c['new_size']}",
        )
        expect(
            not v.consistency_ok(
                c["old_size"], "00" * 32, c["new_size"], new, c["proof"]
            ),
            f"bad consistency {c['old_size']}->{c['new_size']}",
        )

    note = V["checkpoint"]["signed_note"]
    expect(v.checkpoint_ok(note, checkpoint), "checkpoint")
    expect(
        not v.checkpoint_ok(note, ledger), "checkpoint under the ledger key must fail"
    )
    expect(
        not v.checkpoint_ok({**note, "tree_size": 8}, checkpoint), "edited checkpoint"
    )
    expect(
        v.ots_digest(note["root_hash"]) == V["checkpoint"]["ots_digest_hex"],
        "ots digest",
    )

    if failures:
        print(f"FAIL ({len(failures)}):\n" + "\n".join(failures), file=sys.stderr)
        return 1
    print("conforms")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
