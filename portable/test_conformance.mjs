// Canonical JS conformance test for portable_sar_verify.js against the
// shared synthetic fixture corpus. Run with: node test_conformance.mjs
import { verifyPortableSarReceipt, STATUS } from "./portable_sar_verify.js";
import fs from "fs";

const fixtures = JSON.parse(fs.readFileSync(new URL("./fixtures/portable-sar-fixtures.json", import.meta.url)));
const keyRegistry = JSON.parse(fs.readFileSync(new URL("./fixtures/portable-sar-fixture-keys.json", import.meta.url)));

function b64urlToBytes(str) {
  const pad = (4 - (str.length % 4)) % 4;
  const b64 = str.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(pad);
  return new Uint8Array(Buffer.from(b64, "base64"));
}

async function keyPolicy(kid) {
  const entry = keyRegistry[kid];
  if (!entry) return null;
  return { pubkey: b64urlToBytes(entry.pubkey_b64url), profiles: new Set(entry.profiles), source: entry.source };
}

const expected = {
  "01_valid_portable": STATUS.VERIFIED,
  "02_unsigned_counterparty": STATUS.VERIFIED,
  "03_with_ext": STATUS.VERIFIED,
  "04_tampered_signed_field": STATUS.RECEIPT_ID_MISMATCH,
  "05_substituted_unsigned_metadata": STATUS.VERIFIED,
  "05b_stripped_unsigned_metadata": STATUS.VERIFIED,
  "06_unknown_key": STATUS.UNKNOWN_KEY,
  "07_spoofed_key": STATUS.INVALID_SIGNATURE,
  "08_invalid_signature": STATUS.INVALID_SIGNATURE,
  "09_malformed_version": STATUS.NOT_CANDIDATE,
  "09b_malformed_alg": STATUS.NOT_CANDIDATE,
  "11_walletbound_presented_as_portable": STATUS.NOT_CANDIDATE,
  "12_metadata_grafted_walletbound": STATUS.PROFILE_NOT_AUTHORIZED,
  "13_portable_presented_as_walletbound_boundary_case": STATUS.VERIFIED,
  "14_ambiguous_envelope": STATUS.VERIFIED,
};

let pass = 0, fail = 0;
for (const [name, expectedStatus] of Object.entries(expected)) {
  const receipt = fixtures[name];
  const result = await verifyPortableSarReceipt(receipt, keyPolicy);
  const ok = result.status === expectedStatus;
  if (ok) pass++; else fail++;
  console.log(`${ok ? "ok  " : "FAIL"}  ${name.padEnd(45)} expected=${expectedStatus} got=${result.status}${ok ? "" : "  reason=" + result.reason}`);
}

// wallet_binding_attested must never be true for this verifier
for (const [name, expectedStatus] of Object.entries(expected)) {
  if (expectedStatus !== STATUS.VERIFIED) continue;
  const result = await verifyPortableSarReceipt(fixtures[name], keyPolicy);
  const ok = result.walletBindingAttested === false;
  if (ok) pass++; else fail++;
  console.log(`${ok ? "ok  " : "FAIL"}  ${name.padEnd(45)} walletBindingAttested must be false, got=${result.walletBindingAttested}`);
}

// explicit-request-cannot-override-authorization, direct test
{
  const r = await verifyPortableSarReceipt(fixtures["12_metadata_grafted_walletbound"], keyPolicy, "portable-sar-v0.1");
  const ok = r.status === STATUS.PROFILE_NOT_AUTHORIZED;
  if (ok) pass++; else fail++;
  console.log(`${ok ? "ok  " : "FAIL"}  explicit_request_cannot_override_authorization got=${r.status}`);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
