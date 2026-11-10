# Verisigillo verification specification

**Version 1 · 2026-11-06 · Licence: CC BY 4.0**

This document is enough to check a Verisigillo receipt without Verisigillo's code. Three implementations follow it and agree on every conformance vector: the Verisigillo service, and the two independent verifiers in this repository (`python/`, `js/`), which were written from this document and share no code with the service.

**Conformance vectors:** `vectors/verify_vectors.json`, produced by the Verisigillo service's own code. An implementation conforms when it reproduces every value in that file and rejects the tampered cases described in §9.

Words: MUST and MUST NOT are requirements. "Hash string" means `canon-1:sha256:<64 lowercase hex>`.

---

## 1. What a verifier checks

Given a receipt (from the person who holds it) and, optionally, the record's payload:

1. **Trust the keys.** Fetch the key log (`GET https://api.verisigillo.com/v1/public/keys`). Its `genesis` row carries a note signed by the platform root key. Check that the note's `root_did` equals the root ID published out of band (README "Trust root" and `https://verisigillo.com/docs#trust`), and that its signature verifies (§4). Trust the `ledger` and `checkpoint` keys the log publishes, within their `valid_from`/`valid_until` windows.
2. **The receipt is ours.** Its proof verifies against a trusted ledger key (§4).
3. **The receipt matches the record.** Fetch the record's projection (`GET /v1/public/records/{receipt_id}` → `projection`) and check the receipt's fields equal it, and that `seal_hash` equals the row hash of the projection and `prev_seal_hash` (§3).
4. **The content matches.** If you have the payload, its canon-1 hash equals `projection.content_hash` (§2). Without the payload this check is *not done*; never report it as passed.
5. **The history holds.** For a record with several versions, the chain of seal hashes is intact (§3).
6. **The ledger holds it.** Optionally, check the record's leaf is included under a signed checkpoint (§5, §6) and that checkpoints extend each other (consistency proofs).
7. **The time is independent.** Optionally, check the checkpoint's anchors: an RFC 3161 timestamp token and/or an OpenTimestamps proof over the digest in §8.

A result is VERIFIED only when every check that applies passed; PARTIAL when some could not be done; FAILED when any failed.

## 2. canon-1: the canonical text and its hash

`canon_text(v)` projects a JSON value, then serialises it:

| Input | Projection |
|---|---|
| `true` / `false` | unchanged (JSON booleans) |
| `null` | unchanged |
| integer | its decimal string: `42` → `"42"`, `-7` → `"-7"` |
| non-integer number | its **shortest round-trip** decimal string in Python `repr` form: `0.1` → `"0.1"`, `2.5` → `"2.5"`, `1e-07` → `"1e-07"`, `2.0` → `"2.0"` |
| string | Unicode NFC normalisation |
| object | keys NFC-normalised; values projected |
| array | each element projected, order kept |

Serialise the projection as JSON with **keys sorted** (by code point), **no whitespace** (`","` and `":"` separators) and **no ASCII escaping** (non-ASCII characters appear as themselves, UTF-8 encoded). The hash is `canon-1:sha256:` + lowercase hex SHA-256 of those UTF-8 bytes.

Two properties every implementer and every host must know:

- **D-8, a known collision.** Numbers become strings, so `{"v": 1}` and `{"v": "1"}` have the same canonical text and hash. A sealed hash therefore does not tell a number from its decimal string. Hosts that care MUST keep types fixed by schema. A future `canon-2` fixes this as a new major version.
- **Floats follow Python's `repr`.** Exponent form appears below `1e-4` and from `1e16` up, with a sign and at least two exponent digits (`1e-07`, `1e+16`); an integral float keeps `.0`. JSON cannot tell `2` from `2.0`, so a verifier that parses JSON treats integral numbers as integers. **Hosts should not seal floats**; use integers (e.g. grams, cents) or decimal strings.

## 3. Seals and chains

A seal's **projection** is the object (all keys present, `null` where absent):

`host`, `subject`, `kind`, `kind_version`, `version`, `content_hash`, `canon_scheme` (`"canon-1"`), `access`, `rests_on`, `note`, `actor_ref`, `meta_hash`, `recorded_at` (`YYYY-MM-DDTHH:MM:SSZ`).

`content_hash` is the canon-1 hash of the payload after the template's projection (the fields the template chooses to seal; without one, the whole payload). Private records' `subject` is a blinded value (`blind:<hex>`).

The **row hash** is `canon_hash({"payload": projection, "prev_hash": prev})`, where `prev` is the previous version's seal hash, or `null` for version 1. A chain of versions is intact when each version's `prev_seal_hash` equals the previous version's `seal_hash` and each `seal_hash` equals its row hash.

## 4. Receipts and signatures (`eddsa-canon-1`)

A receipt is a JSON object:

`type` (`"SigilloReceipt"`), `receipt_version` (`1`), `receipt_id` (`r_` + 32 hex), `host`, `subject`, `kind`, `kind_version`, `version`, `content_hash`, `prev_seal_hash`, `seal_hash`, `access`, `recorded_at`, `ledger` (the ledger key's DID), and `proof`.

`proof` is a W3C `DataIntegrityProof` with `cryptosuite: "eddsa-canon-1"`:
`{type, cryptosuite, created, verificationMethod: "<did>#<did suffix>", proofPurpose: "assertionMethod", proofValue: "z" + base58btc(signature)}`.

To verify: remove `proof`; compute `canon_text` of the rest (§2); verify the 64-byte Ed25519 signature over its UTF-8 bytes with the public key of `verificationMethod`'s DID (the part before `#`). This is deliberately **not** JSON Canonicalization Scheme (RFC 8785) and not RDF canonicalisation; the cryptosuite name says so.

**did:key**: `did:key:z` + base58btc(`0xed 0x01` + the 32-byte Ed25519 public key). Base58btc uses the Bitcoin alphabet; leading zero bytes are written as `1`.

The same proof format signs checkpoint notes (§6) and the key-log genesis note (§7).

## 5. The Merkle log

Every tree-included record (seals, attestations, keys, templates, host registrations) appends one **leaf**: its `leaf_hash` string, at a 1-based `ledger_index`. The tree is RFC 6962 / RFC 9162:

- leaf digest: `SHA-256(0x00 || UTF-8(leaf_hash string))`;
- node digest: `SHA-256(0x01 || left || right)`;
- the root of `n` leaves splits at the largest power of two smaller than `n`; the empty tree's root is `SHA-256("")`.

Inclusion proofs (`GET /v1/public/proof/{ledger_index}?checkpoint={seq}`) and consistency proofs (`GET /v1/public/consistency?old=&new=`) are lists of hex digests, verified exactly as RFC 9162 §2.1.3.2 and §2.1.4.2 describe. (The proof index is 0-based: `ledger_index - 1`.)

## 6. Checkpoints

Every few minutes the service signs a **checkpoint note**: `{type: "SigilloCheckpoint", seq, tree_size, root_hash, prev_root, ledger}` with an `eddsa-canon-1` proof by the published **checkpoint** key (not the ledger key). `GET /v1/public/checkpoints/latest` and `/{seq}` return it as `signed_note`, plus `key_id`, the id of the key-log row that signed it.

## 7. The key log and the trust root

`GET /v1/public/keys` lists the platform keys: `{id, identity_ref, kind, material (a did:key), status, valid_from, valid_until}`. The `genesis` row adds `genesis_note`: `{type: "SigilloKeyLogGenesis", root_did, ledger_did, checkpoint_did, published_at}` signed by `root_did`. A verifier MUST compare `root_did` with the copy published out of band; without that comparison, the signature only shows the API agrees with itself.

Current root (2026-11-04): `did:key:z6MkfzE9ShTSG5mGiY8oqa5qd1HqmFwJ8Z74Nqg2qyWHiA4H` (fingerprint, the first 16 hex of SHA-256 of the DID: `34f6fa43fd022cfc`).

## 8. Anchors

Each day the latest checkpoint is timestamped. The anchored digest is `SHA-256(UTF-8(root_hash))` (the root's hex text). `GET /v1/public/anchors/{seq}` names each anchor and its status; `GET /v1/public/anchors/{seq}/ots` returns the OpenTimestamps proof as a standard `.ots` file, checkable with `ots verify -d <digest hex> checkpoint-<seq>.ots`.

## 9. Conformance

An implementation conforms when, for `verify_vectors.json`:

- every `canon[].input` gives `canonical_text` and `hash` (implementations that cannot represent a case, such as a JavaScript verifier and `1e-07`, MUST refuse it rather than guess);
- both `seal_chain` receipts verify against `keys.ledger_did`, match their projections, have the right `seal_hash` and `content_hash`, and form an intact chain;
- every `merkle.roots`, `inclusion` and `consistency` entry verifies;
- `checkpoint.signed_note` verifies against `keys.checkpoint_did` and NOT against the ledger key, and `ots_digest_hex` matches §8;

and it rejects: a payload changed by one value; a receipt with any field changed; a proof by an untrusted key; a projection with any field changed; a reordered or gapped chain; a leaf or root changed by one character.
