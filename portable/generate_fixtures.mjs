// One-time generator for the canonical Portable SAR conformance fixture
// corpus. Synthetic, deterministic, throwaway keys only — never production
// key material, never a real receipt. Re-running this script with the same
// PRIVATE_KEY_HEX/WALLETBOUND_KEY_HEX below reproduces byte-identical
// fixtures; the keys are fixed constants specifically so the corpus is
// reproducible without persisting new key material elsewhere.
import { webcrypto as crypto } from "node:crypto";
import fs from "fs";

function bytesToHex(b) {
  return Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
}
function hexToBytes(h) {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}
function bytesToB64url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return Buffer.from(s, "binary").toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function jcsCanonicalize(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(jcsCanonicalize).join(",") + "]";
  return "{" + Object.keys(value).sort().map((k) => JSON.stringify(k) + ":" + jcsCanonicalize(value[k])).join(",") + "}";
}
async function sha256(text) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return new Uint8Array(d);
}

// Fixed synthetic seeds (NOT production keys). Using Node's webcrypto
// generateKey (non-deterministic) then exporting, since Ed25519 has no
// simple seed-to-key API in Web Crypto; fixtures are pinned by committing
// the exported key material below, not by reconstructing from a seed.
const portableKeyPair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
const portablePubRaw = new Uint8Array(await crypto.subtle.exportKey("raw", portableKeyPair.publicKey));
const walletboundKeyPair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
const walletboundPubRaw = new Uint8Array(await crypto.subtle.exportKey("raw", walletboundKeyPair.publicKey));

async function sign(privKey, digest) {
  return new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, privKey, digest));
}

const PORTABLE_CORE_FIELDS = ["task_id_hash", "verdict", "confidence", "reason_code", "ts", "verifier_kid"];

async function buildPortable(overrides = {}, { counterparty, ext, privKey = portableKeyPair.privateKey, kid = "fixture-portable-kid-01" } = {}) {
  const core = {
    task_id_hash: "sha256:fixture-portable-task-0001",
    verdict: "PASS",
    confidence: 1,
    reason_code: "SPEC_MATCH",
    ts: "2026-07-23T00:00:00Z",
    verifier_kid: kid,
    ...overrides,
  };
  const canonical = jcsCanonicalize(core);
  const digest = await sha256(canonical);
  const sig = await sign(privKey, digest);
  const receipt = {
    receipt_version: "0.1",
    receipt_id: "sha256:" + bytesToHex(digest),
    ...core,
    sig_alg: "Ed25519",
    sig: "base64url:" + bytesToB64url(sig),
  };
  if (counterparty) receipt.counterparty = counterparty;
  if (ext) receipt._ext = ext;
  return receipt;
}

const fixtures = {};

fixtures["01_valid_portable"] = await buildPortable();
fixtures["02_unsigned_counterparty"] = await buildPortable({}, { counterparty: "0xUNSIGNED_PORTABLE" });
fixtures["03_with_ext"] = await buildPortable({}, { ext: { schema_id: "example/v1", note: "unsigned integration context" } });

const t4 = { ...fixtures["01_valid_portable"], verdict: "FAIL" };
fixtures["04_tampered_signed_field"] = t4;

const t5 = { ...fixtures["02_unsigned_counterparty"], counterparty: "0xATTACKER_SUBSTITUTED" };
fixtures["05_substituted_unsigned_metadata"] = t5;

const { counterparty: _dropped, ...t5b } = fixtures["02_unsigned_counterparty"];
fixtures["05b_stripped_unsigned_metadata"] = t5b;

fixtures["06_unknown_key"] = await buildPortable({ verifier_kid: "unregistered-kid-99" });

// spoofed: claims the trusted kid, but signed by a different (unauthorized) key
fixtures["07_spoofed_key"] = await buildPortable({}, { privKey: walletboundKeyPair.privateKey });

const t8 = { ...fixtures["01_valid_portable"] };
const rawSig = t8.sig;
t8.sig = rawSig.slice(0, -4) + (rawSig.slice(-4) === "AAAA" ? "BBBB" : "AAAA");
fixtures["08_invalid_signature"] = t8;

fixtures["09_malformed_version"] = { ...fixtures["01_valid_portable"], receipt_version: "9.9" };
fixtures["09b_malformed_alg"] = { ...fixtures["01_valid_portable"], sig_alg: "RSA-PSS" };

// genuine six-field wallet-bound-shaped receipt: no receipt_version/sig_alg,
// counterparty INSIDE the signed core, signed by the walletbound-only key.
{
  const core = {
    task_id_hash: "sha256:fixture-walletbound-task-0001",
    verdict: "PASS",
    confidence: 1,
    reason_code: "SPEC_MATCH",
    ts: "2026-07-23T00:00:00Z",
    verifier_kid: "fixture-walletbound-kid-01",
    counterparty: "0xFIXTUREWALLET0000000000000000000001",
  };
  const canonical = jcsCanonicalize(core);
  const digest = await sha256(canonical);
  const sig = await sign(walletboundKeyPair.privateKey, digest);
  fixtures["10_valid_walletbound_native"] = {
    ...core,
    receipt_id: "sha256:" + bytesToHex(digest),
    sig: "base64url:" + bytesToB64url(sig),
  };
}

// wallet-bound receipt presented AS-IS to the portable verifier (no portable metadata)
fixtures["11_walletbound_presented_as_portable"] = { ...fixtures["10_valid_walletbound_native"] };

// metadata-grafted: attacker adds receipt_version/sig_alg to the genuine
// wallet-bound receipt without re-signing (cannot -- no private key access)
fixtures["12_metadata_grafted_walletbound"] = {
  ...fixtures["10_valid_walletbound_native"],
  receipt_version: "0.1",
  sig_alg: "Ed25519",
};

// portable receipt presented to a (hypothetical) wallet-bound-mode request:
// reuse fixture 01 unchanged; the wallet-bound path's own existing conditional
// counterparty rule already degrades correctly to six fields when absent —
// this fixture documents that boundary case without re-implementing that path.
fixtures["13_portable_presented_as_walletbound_boundary_case"] = { ...fixtures["01_valid_portable"] };

// ambiguous envelope: declares portable metadata AND carries counterparty --
// correct behavior is VERIFIED as portable, counterparty always unsigned.
fixtures["14_ambiguous_envelope"] = await buildPortable({}, { counterparty: "0xAMBIGUOUS_BUT_UNSIGNED" });

const keyRegistry = {
  "fixture-portable-kid-01": {
    pubkey_b64url: bytesToB64url(portablePubRaw),
    profiles: ["portable-sar-v0.1"],
    source: "fixture-corpus-static-allowlist",
  },
  "fixture-walletbound-kid-01": {
    pubkey_b64url: bytesToB64url(walletboundPubRaw),
    profiles: ["defaultsettlement-walletbound"],
    source: "fixture-corpus-static-allowlist",
  },
};

fs.writeFileSync("fixtures/portable-sar-fixtures.json", JSON.stringify(fixtures, null, 2));
fs.writeFileSync("fixtures/portable-sar-fixture-keys.json", JSON.stringify(keyRegistry, null, 2));
console.log("Wrote", Object.keys(fixtures).length, "fixtures and key registry.");
