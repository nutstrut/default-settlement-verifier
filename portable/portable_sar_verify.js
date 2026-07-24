/**
 * Canonical Portable SAR (six-field) inbound verifier — browser/Node-compatible.
 *
 * Source of truth: default-settlement-verifier/portable/portable_sar_verify.js
 * Consumers (defaultverifier-mcp, sar-explorer-prod) bundle a pinned copy of
 * this exact file and record the source commit hash they were pinned from.
 * Do not fork the logic independently.
 *
 * Uses only Web Crypto API primitives (crypto.subtle) so the identical logic
 * runs in a browser (SAR Explorer) and in Node 19+ (MCP) without a bundler.
 *
 * Invariants — see the Python twin (portable_sar_verify.py) and
 * reports/strategy/sar-portable-verification-remediation-20260723.md for the
 * full design:
 *   - Six-field signed core only. counterparty/_ext are always unsigned.
 *   - Never touches or duplicates the existing wallet-bound verification
 *     logic (buildSignedReceiptObject / _sar_core_without_sig and mirrors).
 *   - Profile candidacy (receipt_version + sig_alg) is necessary but not
 *     sufficient; a keyPolicy(kid) must additionally authorize the profile.
 *   - No trial-and-error canonicalization or fallback core reconstruction.
 *   - Distinct outcomes: malformed, unsupported profile, unknown key,
 *     profile not authorized, receipt_id mismatch, invalid signature.
 */

export const PORTABLE_PROFILE_ID = "portable-sar-v0.1";

export const PORTABLE_CORE_FIELDS = [
  "task_id_hash",
  "verdict",
  "confidence",
  "reason_code",
  "ts",
  "verifier_kid",
];

const PORTABLE_ENVELOPE_REQUIRED = [
  "receipt_version",
  "receipt_id",
  "sig_alg",
  "sig",
  ...PORTABLE_CORE_FIELDS,
];

const SUPPORTED_RECEIPT_VERSIONS = new Set(["0.1"]);
const SUPPORTED_SIG_ALG = "Ed25519";

export const STATUS = Object.freeze({
  VERIFIED: "VERIFIED",
  MALFORMED: "REJECTED_MALFORMED",
  UNSUPPORTED_PROFILE: "UNSUPPORTED_PROFILE",
  UNKNOWN_KEY: "REJECTED_UNKNOWN_KEY",
  PROFILE_NOT_AUTHORIZED: "REJECTED_PROFILE_NOT_AUTHORIZED",
  RECEIPT_ID_MISMATCH: "REJECTED_RECEIPT_ID_MISMATCH",
  INVALID_SIGNATURE: "REJECTED_INVALID_SIGNATURE",
  NOT_CANDIDATE: "REJECTED_NOT_PORTABLE_CANDIDATE",
});

function jcsCanonicalize(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map(jcsCanonicalize).join(",") + "]";
  }
  return (
    "{" +
    Object.keys(value)
      .sort()
      .map((key) => JSON.stringify(key) + ":" + jcsCanonicalize(value[key]))
      .join(",") +
    "}"
  );
}

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function base64urlToBytes(str) {
  const pad = (4 - (str.length % 4)) % 4;
  const b64 = str.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(pad);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function sha256Bytes(text) {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(digest);
}

function detectCandidateProfile(receipt) {
  if (receipt === null || typeof receipt !== "object") {
    return { candidate: null, err: "receipt is not an object" };
  }
  const hasVersion = Object.prototype.hasOwnProperty.call(receipt, "receipt_version");
  const hasAlg = Object.prototype.hasOwnProperty.call(receipt, "sig_alg");
  if (!hasVersion || !hasAlg) {
    return {
      candidate: null,
      err:
        "receipt does not declare portable-sar-v0.1 envelope metadata " +
        "(receipt_version + sig_alg); no other inbound profile is supported",
    };
  }
  if (!SUPPORTED_RECEIPT_VERSIONS.has(receipt.receipt_version)) {
    return { candidate: null, err: `unrecognized receipt_version: ${JSON.stringify(receipt.receipt_version)}` };
  }
  if (receipt.sig_alg !== SUPPORTED_SIG_ALG) {
    return { candidate: null, err: `unrecognized sig_alg: ${JSON.stringify(receipt.sig_alg)}` };
  }
  return { candidate: PORTABLE_PROFILE_ID, err: null };
}

function buildCore(receipt) {
  const core = {};
  for (const k of PORTABLE_CORE_FIELDS) core[k] = receipt[k];
  return core;
}

/**
 * keyPolicy(kid) -> Promise<{pubkey: Uint8Array, profiles: Set<string>, source: string} | null>
 */
export async function verifyPortableSarReceipt(receipt, keyPolicy, requestedProfile = null) {
  const { candidate, err } = detectCandidateProfile(receipt);

  if (requestedProfile !== null && candidate !== requestedProfile) {
    return {
      status: STATUS.NOT_CANDIDATE,
      reason: `requested profile ${JSON.stringify(requestedProfile)} disagrees with envelope-declared candidate ${JSON.stringify(candidate)}${err ? " (" + err + ")" : ""}`,
    };
  }
  if (candidate === null) {
    return { status: STATUS.NOT_CANDIDATE, reason: err };
  }
  if (candidate !== PORTABLE_PROFILE_ID) {
    return { status: STATUS.UNSUPPORTED_PROFILE, reason: `profile ${candidate} not implemented` };
  }

  const missing = PORTABLE_ENVELOPE_REQUIRED.filter((f) => !(f in receipt));
  if (missing.length) {
    return { status: STATUS.MALFORMED, reason: `missing required envelope fields: ${missing.join(", ")}` };
  }

  const core = buildCore(receipt);
  let canonical;
  try {
    canonical = jcsCanonicalize(core);
  } catch (e) {
    return { status: STATUS.MALFORMED, reason: `canonicalization failed: ${e.message}` };
  }
  const digest = await sha256Bytes(canonical);
  const expectedReceiptId = "sha256:" + bytesToHex(digest);

  const kid = receipt.verifier_kid;
  const entry = await keyPolicy(kid);
  if (!entry) {
    return { status: STATUS.UNKNOWN_KEY, reason: `unknown or untrusted key: ${kid}`, computedReceiptId: expectedReceiptId };
  }
  const profiles = entry.profiles instanceof Set ? entry.profiles : new Set(entry.profiles || []);
  if (!profiles.has(PORTABLE_PROFILE_ID)) {
    return {
      status: STATUS.PROFILE_NOT_AUTHORIZED,
      reason: `key ${kid} is known (source=${entry.source}) but not authorized for profile ${PORTABLE_PROFILE_ID} (authorized for: ${[...profiles].sort().join(", ")})`,
      computedReceiptId: expectedReceiptId,
    };
  }

  if (typeof receipt.receipt_id !== "string" || !receipt.receipt_id.startsWith("sha256:")) {
    return { status: STATUS.MALFORMED, reason: "receipt_id missing 'sha256:' prefix" };
  }
  if (receipt.receipt_id !== expectedReceiptId) {
    return {
      status: STATUS.RECEIPT_ID_MISMATCH,
      reason: `expected ${expectedReceiptId}, got ${receipt.receipt_id}`,
      computedReceiptId: expectedReceiptId,
    };
  }

  if (typeof receipt.sig !== "string" || !receipt.sig.startsWith("base64url:")) {
    return { status: STATUS.MALFORMED, reason: "sig missing 'base64url:' prefix" };
  }

  try {
    const rawPubKeyBytes =
      entry.pubkey instanceof Uint8Array ? entry.pubkey : base64urlToBytes(entry.pubkey);
    const publicKey = await crypto.subtle.importKey(
      "raw",
      rawPubKeyBytes,
      { name: "Ed25519" },
      false,
      ["verify"]
    );
    const sigBytes = base64urlToBytes(receipt.sig.slice("base64url:".length));
    const ok = await crypto.subtle.verify({ name: "Ed25519" }, publicKey, sigBytes, digest);
    if (!ok) {
      return { status: STATUS.INVALID_SIGNATURE, reason: "signature did not verify", computedReceiptId: expectedReceiptId };
    }
  } catch (e) {
    return { status: STATUS.INVALID_SIGNATURE, reason: `cryptographically invalid signature: ${e.message}`, computedReceiptId: expectedReceiptId };
  }

  const unsignedClaims = {};
  if (typeof receipt.counterparty === "string" && receipt.counterparty.trim()) {
    unsignedClaims.counterparty = receipt.counterparty.trim();
  }
  if ("_ext" in receipt) {
    unsignedClaims._ext = receipt._ext;
  }

  return {
    status: STATUS.VERIFIED,
    profile: PORTABLE_PROFILE_ID,
    signedFields: PORTABLE_CORE_FIELDS,
    keyKid: kid,
    trustSource: entry.source,
    unsignedClaims,
    walletBindingAttested: false,
    computedReceiptId: expectedReceiptId,
    note: "counterparty, if present, is unsigned metadata and is not an attested wallet binding under this profile",
  };
}

export { detectCandidateProfile, jcsCanonicalize, base64urlToBytes, bytesToHex };
