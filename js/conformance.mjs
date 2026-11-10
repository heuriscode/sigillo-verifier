// Runs the JS verifier against the conformance vectors. Exit 0 = conforms.
// Usage: node conformance.mjs <path to verify_vectors.json>
import { readFileSync } from "node:fs";
import * as v from "./verisigillo-verify.mjs";

const V = JSON.parse(readFileSync(process.argv[2], "utf8"));
const failures = [];
const expect = (ok, what) => { if (!ok) failures.push(what); };
const LEDGER = new Set([V.keys.ledger_did]);
const CHECKPOINT = new Set([V.keys.checkpoint_did]);

for (const c of V.canon) {
  // every current vector must be representable: a refusal is a failure here
  let text;
  try { text = v.canonText(c.input); } catch (e) {
    failures.push(`canon refused: ${c.name}: ${e.message}`);
    continue;
  }
  expect(text === c.canonical_text, `canon text: ${c.name}: ${text}`);
  expect((await v.canonHash(c.input)) === c.hash, `canon hash: ${c.name}`);
}

let prev = null;
const rows = [];
for (const link of V.seal_chain) {
  const r = await v.checkReceipt(link.receipt, link.projection, prev, LEDGER, link.payload);
  expect(r.signature && r.receipt_matches_projection && r.seal_hash && r.content === true, `receipt v${link.projection.version}: ${JSON.stringify(r)}`);
  rows.push([link.projection, prev, link.receipt.seal_hash]);
  prev = link.receipt.seal_hash;
}
expect(await v.chainOk(rows), "chain");
expect(!(await v.chainOk([...rows].reverse())), "reversed chain must fail");

const first = V.seal_chain[0];
expect((await v.checkReceipt(first.receipt, first.projection, null, LEDGER, { ...first.payload, amount: 41 })).content === false, "tampered payload");
expect(!(await v.proofOk({ ...first.receipt, version: 9 }, LEDGER)), "tampered receipt");
expect(!(await v.proofOk(first.receipt, new Set(["did:key:z6MkNotOurs"]))), "untrusted key");

const m = V.merkle;
for (const [size, root] of Object.entries(m.roots)) expect((await v.merkleRoot(m.leaves.slice(0, +size))) === root, `root ${size}`);
for (const p of m.inclusion) {
  const root = m.roots[String(p.tree_size)];
  expect(await v.inclusionOk(m.leaves[p.index], p.index, p.tree_size, p.proof, root), `inclusion ${p.index}/${p.tree_size}`);
  expect(!(await v.inclusionOk(m.leaves[p.index] + "x", p.index, p.tree_size, p.proof, root)), `bad inclusion ${p.index}/${p.tree_size}`);
}
for (const c of m.consistency) {
  expect(await v.consistencyOk(c.old_size, m.roots[String(c.old_size)], c.new_size, m.roots[String(c.new_size)], c.proof), `consistency ${c.old_size}->${c.new_size}`);
}

// refusals: values JSON cannot carry exactly are refused, never guessed
let refused = false;
try { v.canonText({ big: 2 ** 60 }); } catch (e) { refused = e instanceof v.CanonError; }
expect(refused, "integers beyond 2^53 must be refused");

const note = V.checkpoint.signed_note;
expect(await v.checkpointOk(note, CHECKPOINT), "checkpoint");
expect(!(await v.checkpointOk(note, LEDGER)), "checkpoint under the ledger key must fail");
expect((await v.otsDigest(note.root_hash)) === V.checkpoint.ots_digest_hex, "ots digest");

if (failures.length) {
  console.error(`FAIL (${failures.length}):\n` + failures.join("\n"));
  process.exit(1);
}
console.log("conforms");
