"""The independent Verisigillo verifier — written from SPEC.md.

Shares no code with the Verisigillo service. Third-party: ``cryptography``
for Ed25519 only. Every function returns plain booleans or (name, ok) checks and
never raises on malformed input: a malformed input simply does not verify.

What it checks:
* canon-1 text and hashes (§2), the seal row hash and chain (§3);
* a receipt's ``eddsa-canon-1`` proof against a TRUSTED ledger DID (§4), and
  that it matches the record's projection and, if given, the payload;
* RFC 6962/9162 Merkle roots, inclusion and consistency proofs (§5);
* a signed checkpoint note against a TRUSTED checkpoint DID (§6).
Which DIDs to trust comes from the published key log, whose genesis note is
signed by the platform root pinned out of band (§7). This module does not
fetch anything; callers pass what they fetched.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from typing import Any

SCHEME = "canon-1"
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


# --------------------------------------------------------------------- §2 canon


def _project(v: Any) -> Any:
    if v is True or v is False:
        return v
    if v is None:
        return None
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return repr(v)
    if isinstance(v, str):
        return unicodedata.normalize("NFC", v)
    if isinstance(v, dict):
        return {unicodedata.normalize("NFC", str(k)): _project(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_project(x) for x in v]
    return unicodedata.normalize("NFC", str(v))


def canon_text(value: Any) -> str:
    return json.dumps(
        _project(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def canon_hash(value: Any) -> str:
    return (
        f"{SCHEME}:sha256:"
        + hashlib.sha256(canon_text(value).encode("utf-8")).hexdigest()
    )


# ------------------------------------------------------------------ §3 chains


def row_hash(projection: dict[str, Any], prev_hash: str | None) -> str:
    return canon_hash({"payload": projection, "prev_hash": prev_hash})


def chain_ok(rows: list[tuple[dict[str, Any], str | None, str]]) -> bool:
    """rows = [(projection, prev_seal_hash, seal_hash)] oldest first."""
    prev = None
    for projection, claimed_prev, claimed in rows:
        if claimed_prev != prev or row_hash(projection, claimed_prev) != claimed:
            return False
        prev = claimed
    return True


# --------------------------------------------------------------- §4 signatures


def _b58decode(s: str) -> bytes | None:
    n = 0
    for ch in s:
        i = _B58.find(ch)
        if i < 0:
            return None
        n = n * 58 + i
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    lead = len(s) - len(s.lstrip("1"))
    return b"\x00" * lead + body


def did_key_public_bytes(did: str) -> bytes | None:
    """did:key:z<base58btc(0xed 0x01 || 32-byte Ed25519 key)> → the key."""
    if not isinstance(did, str) or not did.startswith("did:key:z"):
        return None
    raw = _b58decode(did[len("did:key:z") :])
    if raw is None or len(raw) != 34 or raw[:2] != b"\xed\x01":
        return None
    return raw[2:]


def proof_ok(doc: dict[str, Any], trusted_dids: set[str]) -> bool:
    """An eddsa-canon-1 DataIntegrityProof by one of ``trusted_dids`` over
    canon_text(doc without "proof")."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        proof = doc["proof"]
        if (
            proof.get("type") != "DataIntegrityProof"
            or proof.get("cryptosuite") != "eddsa-canon-1"
        ):
            return False
        did = str(proof["verificationMethod"]).split("#", 1)[0]
        if did not in trusted_dids:
            return False
        pub = did_key_public_bytes(did)
        value = str(proof["proofValue"])
        sig = _b58decode(value[1:]) if value.startswith("z") else None
        if pub is None or sig is None:
            return False
        unsigned = {k: v for k, v in doc.items() if k != "proof"}
        Ed25519PublicKey.from_public_bytes(pub).verify(
            sig, canon_text(unsigned).encode("utf-8")
        )
        return True
    except (InvalidSignature, KeyError, TypeError, ValueError, AttributeError):
        return False


def check_receipt(
    receipt: dict[str, Any],
    projection: dict[str, Any],
    prev_seal_hash: str | None,
    trusted_ledger_dids: set[str],
    payload: Any = None,
) -> list[tuple[str, bool | None]]:
    """The receipt walk. ``None`` = not checked (no payload given)."""
    checks: list[tuple[str, bool | None]] = [
        ("signature", proof_ok(receipt, trusted_ledger_dids))
    ]
    same = all(
        receipt.get(k) == projection.get(k)
        for k in (
            "host",
            "subject",
            "kind",
            "kind_version",
            "version",
            "content_hash",
            "access",
            "recorded_at",
        )
    )
    checks.append(
        (
            "receipt_matches_projection",
            same and receipt.get("prev_seal_hash") == prev_seal_hash,
        )
    )
    checks.append(
        ("seal_hash", row_hash(projection, prev_seal_hash) == receipt.get("seal_hash"))
    )
    checks.append(
        (
            "content",
            None
            if payload is None
            else canon_hash(payload) == projection.get("content_hash"),
        )
    )
    return checks


# ------------------------------------------------------------------- §5 Merkle


def _leaf(leaf: str) -> bytes:
    return hashlib.sha256(b"\x00" + leaf.encode("utf-8")).digest()


def _node(a: bytes, b: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + a + b).digest()


def _mth(d: list[bytes]) -> bytes:
    if not d:
        return hashlib.sha256(b"").digest()
    if len(d) == 1:
        return d[0]
    k = 1 << ((len(d) - 1).bit_length() - 1)  # largest power of two < n
    return _node(_mth(d[:k]), _mth(d[k:]))


def merkle_root(leaves: list[str]) -> str:
    return _mth([_leaf(x) for x in leaves]).hex()


def inclusion_ok(leaf: str, index: int, size: int, proof: list[str], root: str) -> bool:
    """RFC 9162 §2.1.3.2."""
    try:
        if not 0 <= index < size:
            return False
        fn, sn, r = index, size - 1, _leaf(leaf)
        for p in (bytes.fromhex(x) for x in proof):
            if sn == 0:
                return False
            if fn & 1 or fn == sn:
                r = _node(p, r)
                if not fn & 1:
                    while fn and not fn & 1:
                        fn >>= 1
                        sn >>= 1
            else:
                r = _node(r, p)
            fn >>= 1
            sn >>= 1
        return sn == 0 and r.hex() == root
    except ValueError:
        return False


def consistency_ok(
    old: int, old_root: str, new: int, new_root: str, proof: list[str]
) -> bool:
    """RFC 9162 §2.1.4.2."""
    try:
        if old == new:
            return old_root == new_root and not proof
        if not 0 < old < new:
            return False
        path = [bytes.fromhex(x) for x in proof]
        if old & (old - 1) == 0:
            path = [bytes.fromhex(old_root)] + path
        if not path:
            return False
        fn, sn = old - 1, new - 1
        while fn & 1:
            fn >>= 1
            sn >>= 1
        fr = sr = path[0]
        for c in path[1:]:
            if sn == 0:
                return False
            if fn & 1 or fn == sn:
                fr, sr = _node(c, fr), _node(c, sr)
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
            else:
                sr = _node(sr, c)
            fn >>= 1
            sn >>= 1
        return sn == 0 and fr.hex() == old_root and sr.hex() == new_root
    except ValueError:
        return False


# --------------------------------------------------------------- §6 checkpoints


def checkpoint_ok(
    signed_note: dict[str, Any], trusted_checkpoint_dids: set[str]
) -> bool:
    return signed_note.get("type") == "SigilloCheckpoint" and proof_ok(
        signed_note, trusted_checkpoint_dids
    )


def ots_digest(root_hash: str) -> str:
    """§8: the digest anchored with OpenTimestamps for a checkpoint."""
    return hashlib.sha256(root_hash.encode("utf-8")).hexdigest()
