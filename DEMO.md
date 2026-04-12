# DefaultVerifier Demo (2 minutes)

This demo shows how to verify whether an AI agent completed a task.

## 1. Create a receipt

curl -X POST https://defaultverifier.com/settlement-witness \
  -H 'content-type: application/json' \
  -d '{
    "task_id":"demo-001",
    "spec":{"goal":"demo"},
    "output":{"goal":"demo"},
    "counterparty":"0x1234567890abcdef1234567890abcdef12345678"
  }'

Copy the `receipt_id` from the response.

---

## 2. Fetch the receipt

curl https://defaultverifier.com/settlement-witness/receipt/<receipt_id>

---

## 3. Verify locally (Node.js)

cd examples/node-verify
curl -s https://defaultverifier.com/.well-known/jwks.json > jwks.json

# paste receipt into receipt.json

node verify.js receipt.json jwks.json

Expected output:

PASS: signature verified
verdict: PASS

---

## 4. Verify locally (Python)

python3 examples/verify_receipt_python.py <receipt_id>

Expected output:

PASS: signature verified

---

## What this proves

- The receipt is deterministic
- The signature is valid
- The result is independently verifiable

If it matters — verify it.
