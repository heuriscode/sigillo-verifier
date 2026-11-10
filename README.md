# Verisigillo verifier

Check a Verisigillo receipt yourself, without Verisigillo's code or servers.

This repository holds everything needed to do that:

| Path | What it is |
|---|---|
| [`SPEC.md`](SPEC.md) | The verification specification: canon-1 hashing, seals and chains, `eddsa-canon-1` receipts, the RFC 6962/9162 Merkle log, checkpoints, the key log and trust root, and anchors |
| [`vectors/verify_vectors.json`](vectors/verify_vectors.json) | The conformance vectors. An implementation conforms when it reproduces every value and rejects the tampered cases in SPEC §9 |
| [`python/`](python/) | A Python verifier (3.10+; needs `cryptography` for Ed25519) and its conformance runner |
| [`js/`](js/) | A browser and Node (22+) verifier with no dependencies (Web Crypto only) and its conformance runner |

Both verifiers were written from the spec alone and share no code with the Verisigillo service or with each other. Both agree with the service on every vector.

## Run the conformance checks

```
pip install cryptography
python python/conformance.py vectors/verify_vectors.json

node js/conformance.mjs vectors/verify_vectors.json
```

Each prints `conforms` and exits 0.

## Check a real receipt

1. Fetch the key log: `GET https://api.verisigillo.com/v1/public/keys`.
2. Check that the genesis note's `root_did` equals the trust root published outside the API (SPEC §7), and that its signature verifies.
3. Verify the receipt's proof against a published ledger key, then fetch `GET https://api.verisigillo.com/v1/public/records/{receipt_id}` and check that the receipt matches the projection (SPEC §1).
4. If you hold the payload, check its canon-1 hash. Without it, that check is not done; don't report it as passed.

## Known limits

- **12 and "12" hash alike** in canon-1 (SPEC §2, D-8). A sealed hash does not tell a number from its decimal string. A future `canon-2` fixes this as a new major version.
- **JavaScript cannot represent every number exactly.** The JS verifier refuses integers beyond 2^53 instead of guessing (SPEC §9).

## Licences

Code and vectors: [Apache License 2.0](LICENSE). Specification text (`SPEC.md`): [Creative Commons Attribution 4.0](LICENSE-SPEC).
