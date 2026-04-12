const fs = require('fs');
const crypto = require('crypto');
const { canonicalize } = require('json-canonicalize');
const nacl = require('tweetnacl');

function b64urlToBuffer(s) {
  const pad = '='.repeat((4 - (s.length % 4)) % 4);
  const base64 = s.replace(/-/g, '+').replace(/_/g, '/') + pad;
  return Buffer.from(base64, 'base64');
}

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest();
}

function buildSignedObject(receipt) {
  const out = {
    task_id_hash: receipt.task_id_hash,
    verdict: receipt.verdict,
    confidence: receipt.confidence,
    reason_code: receipt.reason_code,
    ts: receipt.ts,
    verifier_kid: receipt.verifier_kid,
  };

  if (typeof receipt.counterparty === 'string' && receipt.counterparty.trim()) {
    out.counterparty = receipt.counterparty.trim();
  }

  return out;
}

function main() {
  if (process.argv.length < 4) {
    console.error('Usage: node verify.js <receipt.json> <jwks.json>');
    process.exit(1);
  }

  const receipt = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
  const jwks = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));

  const signedObject = buildSignedObject(receipt);
  const canonical = canonicalize(signedObject);
  const digest = sha256(Buffer.from(canonical, 'utf8'));
  const computedReceiptId = 'sha256:' + digest.toString('hex');

  if (receipt.receipt_id !== computedReceiptId) {
    console.error('FAIL: receipt_id mismatch');
    console.error('computed:', computedReceiptId);
    console.error('receipt :', receipt.receipt_id);
    process.exit(2);
  }

  const kid = receipt.verifier_kid;
  const key = (jwks.keys || []).find(k => k.kid === kid);

  if (!key) {
    console.error(`FAIL: key not found for kid ${kid}`);
    process.exit(3);
  }

  const sig = String(receipt.sig || '').replace(/^base64url:/, '');
  const sigBytes = b64urlToBuffer(sig);
  const pubKey = b64urlToBuffer(key.x);

  const ok = nacl.sign.detached.verify(
    new Uint8Array(digest),
    new Uint8Array(sigBytes),
    new Uint8Array(pubKey)
  );

  if (!ok) {
    console.error('FAIL: signature verification failed');
    process.exit(5);
  }

  console.log('PASS: signature verified');
  console.log('kid:', kid);
  console.log('verdict:', receipt.verdict);
  console.log('receipt_id:', receipt.receipt_id);
}

main();
