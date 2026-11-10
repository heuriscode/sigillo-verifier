// verisigillo-verify.mjs — a browser and Node (22+) verifier for Verisigillo
// receipts, written from SPEC.md. No
// dependencies: Web Crypto for SHA-256 and Ed25519. Shares no code with the
// service. Conformance: vectors/verify_vectors.json (js/conformance.mjs).
//
// Limits, stated by the spec (§2): JSON cannot tell 2 from 2.0, so integral
// numbers are treated as integers; integers beyond 2^53 cannot be read
// exactly from JSON and are refused (CanonError), never guessed.

const SCHEME = "canon-1";
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();

export class CanonError extends Error {}

// ---------------------------------------------------------------- §2 canon

function pyFloat(x) {
  // Python repr ('r' format) from JS's shortest round-trip digits.
  const [mant, expStr] = x.toExponential().split("e");
  const neg = mant.startsWith("-");
  const digits = mant.replace("-", "").replace(".", "");
  const exp = parseInt(expStr, 10);
  let out;
  if (exp >= -4 && exp < 16) {
    if (exp >= 0) {
      const intPart = digits.slice(0, exp + 1).padEnd(exp + 1, "0");
      const frac = digits.slice(exp + 1) || "0";
      out = `${intPart}.${frac}`;
    } else {
      out = `0.${"0".repeat(-exp - 1)}${digits}`;
    }
  } else {
    const m = digits.length > 1 ? `${digits[0]}.${digits.slice(1)}` : digits[0];
    const sign = exp < 0 ? "-" : "+";
    out = `${m}e${sign}${String(Math.abs(exp)).padStart(2, "0")}`;
  }
  return neg ? `-${out}` : out;
}

function cmpCodePoints(a, b) {
  const x = Array.from(a, (c) => c.codePointAt(0));
  const y = Array.from(b, (c) => c.codePointAt(0));
  for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i] - y[i];
  return x.length - y.length;
}

function ser(v) {
  if (v === true || v === false || v === null) return JSON.stringify(v);
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new CanonError("non-finite number");
    if (Number.isInteger(v)) {
      if (!Number.isSafeInteger(v)) throw new CanonError("integer too large to read exactly from JSON");
      return JSON.stringify(String(v));
    }
    return JSON.stringify(pyFloat(v));
  }
  if (typeof v === "string") return JSON.stringify(v.normalize("NFC"));
  if (Array.isArray(v)) return `[${v.map(ser).join(",")}]`;
  if (typeof v === "object") {
    const entries = Object.entries(v).map(([k, x]) => [k.normalize("NFC"), x]);
    entries.sort((a, b) => cmpCodePoints(a[0], b[0]));
    return `{${entries.map(([k, x]) => `${JSON.stringify(k)}:${ser(x)}`).join(",")}}`;
  }
  throw new CanonError(`cannot canonicalise ${typeof v}`);
}

export const canonText = (value) => ser(value);

const hex = (buf) => Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
const sha256 = async (bytes) => new Uint8Array(await subtle.digest("SHA-256", bytes));

export async function canonHash(value) {
  return `${SCHEME}:sha256:${hex(await sha256(enc.encode(canonText(value))))}`;
}

// --------------------------------------------------------------- §3 chains

export const rowHash = (projection, prevHash) => canonHash({ payload: projection, prev_hash: prevHash });

export async function chainOk(rows) {
  let prev = null;
  for (const [projection, claimedPrev, claimed] of rows) {
    if (claimedPrev !== prev || (await rowHash(projection, claimedPrev)) !== claimed) return false;
    prev = claimed;
  }
  return true;
}

// ----------------------------------------------------------- §4 signatures

function b58decode(s) {
  let n = 0n;
  for (const ch of s) {
    const i = B58.indexOf(ch);
    if (i < 0) return null;
    n = n * 58n + BigInt(i);
  }
  const bytes = [];
  while (n > 0n) {
    bytes.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  const lead = s.length - s.replace(/^1+/, "").length;
  return new Uint8Array([...new Array(lead).fill(0), ...bytes]);
}

export function didKeyPublicBytes(did) {
  if (typeof did !== "string" || !did.startsWith("did:key:z")) return null;
  const raw = b58decode(did.slice("did:key:z".length));
  if (!raw || raw.length !== 34 || raw[0] !== 0xed || raw[1] !== 0x01) return null;
  return raw.slice(2);
}

export async function proofOk(doc, trustedDids) {
  try {
    const proof = doc && doc.proof;
    if (!proof || proof.type !== "DataIntegrityProof" || proof.cryptosuite !== "eddsa-canon-1") return false;
    const did = String(proof.verificationMethod).split("#")[0];
    if (!trustedDids.has(did)) return false;
    const pub = didKeyPublicBytes(did);
    const value = String(proof.proofValue);
    const sig = value.startsWith("z") ? b58decode(value.slice(1)) : null;
    if (!pub || !sig) return false;
    const { proof: _omit, ...unsigned } = doc;
    const key = await subtle.importKey("raw", pub, { name: "Ed25519" }, false, ["verify"]);
    return await subtle.verify({ name: "Ed25519" }, key, sig, enc.encode(canonText(unsigned)));
  } catch {
    return false;
  }
}

const SAME = ["host", "subject", "kind", "kind_version", "version", "content_hash", "access", "recorded_at"];

export async function checkReceipt(receipt, projection, prevSealHash, trustedLedgerDids, payload) {
  const same = SAME.every((k) => receipt[k] === projection[k]) && receipt.prev_seal_hash === prevSealHash;
  return {
    signature: await proofOk(receipt, trustedLedgerDids),
    receipt_matches_projection: same,
    seal_hash: (await rowHash(projection, prevSealHash)) === receipt.seal_hash,
    content: payload === undefined ? null : (await canonHash(payload)) === projection.content_hash,
  };
}

// ---------------------------------------------------------------- §5 Merkle

const cat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let i = 0;
  for (const p of parts) {
    out.set(p, i);
    i += p.length;
  }
  return out;
};
const leafDigest = (leaf) => sha256(cat(new Uint8Array([0]), enc.encode(leaf)));
const nodeDigest = (a, b) => sha256(cat(new Uint8Array([1]), a, b));
const fromHex = (h) => {
  if (!/^([0-9a-f]{2})*$/.test(h)) throw new Error("bad hex");
  return new Uint8Array(h.match(/../g)?.map((x) => parseInt(x, 16)) || []);
};

async function mth(d) {
  if (d.length === 0) return sha256(new Uint8Array());
  if (d.length === 1) return d[0];
  let k = 1;
  while (k * 2 < d.length) k *= 2;
  return nodeDigest(await mth(d.slice(0, k)), await mth(d.slice(k)));
}

export async function merkleRoot(leaves) {
  return hex(await mth(await Promise.all(leaves.map(leafDigest))));
}

export async function inclusionOk(leaf, index, size, proof, root) {
  try {
    if (!(index >= 0 && index < size)) return false;
    let fn = index, sn = size - 1, r = await leafDigest(leaf);
    for (const p of proof.map(fromHex)) {
      if (sn === 0) return false;
      if (fn & 1 || fn === sn) {
        r = await nodeDigest(p, r);
        if (!(fn & 1)) while (fn && !(fn & 1)) { fn >>= 1; sn >>= 1; }
      } else {
        r = await nodeDigest(r, p);
      }
      fn >>= 1;
      sn >>= 1;
    }
    return sn === 0 && hex(r) === root;
  } catch {
    return false;
  }
}

export async function consistencyOk(oldSize, oldRoot, newSize, newRoot, proof) {
  try {
    if (oldSize === newSize) return oldRoot === newRoot && proof.length === 0;
    if (!(oldSize > 0 && oldSize < newSize)) return false;
    let path = proof.map(fromHex);
    if ((oldSize & (oldSize - 1)) === 0) path = [fromHex(oldRoot), ...path];
    if (path.length === 0) return false;
    let fn = oldSize - 1, sn = newSize - 1;
    while (fn & 1) { fn >>= 1; sn >>= 1; }
    let fr = path[0], sr = path[0];
    for (const c of path.slice(1)) {
      if (sn === 0) return false;
      if (fn & 1 || fn === sn) {
        fr = await nodeDigest(c, fr);
        sr = await nodeDigest(c, sr);
        while (fn && !(fn & 1)) { fn >>= 1; sn >>= 1; }
      } else {
        sr = await nodeDigest(sr, c);
      }
      fn >>= 1;
      sn >>= 1;
    }
    return sn === 0 && hex(fr) === oldRoot && hex(sr) === newRoot;
  } catch {
    return false;
  }
}

// ----------------------------------------------------- §6 checkpoints, §8 OTS

export async function checkpointOk(signedNote, trustedCheckpointDids) {
  return signedNote?.type === "SigilloCheckpoint" && proofOk(signedNote, trustedCheckpointDids);
}

export async function otsDigest(rootHash) {
  return hex(await sha256(enc.encode(rootHash)));
}
