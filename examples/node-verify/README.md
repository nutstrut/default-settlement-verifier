# Node.js SAR Verifier Example

This example verifies a `receipt_v0_1` object against the public verifier key set.

## Install

npm install

## Usage

node verify.js receipt.json jwks.json

## Inputs

- receipt.json — the `receipt_v0_1` object
- jwks.json — verifier public keys from:

https://defaultverifier.com/.well-known/jwks.json

Alternative SAR protocol key registry:

https://defaultverifier.com/.well-known/sar-keys.json

## Verification flow

This implementation verifies:

1. Build the signed receipt object from:
   - task_id_hash
   - verdict
   - confidence
   - reason_code
   - ts
   - verifier_kid
   - counterparty (when present)

2. RFC 8785 canonicalize the object  
3. SHA-256 hash the canonical bytes  
4. Check that the computed digest matches receipt_id  
5. Verify the Ed25519 signature using verifier_kid  

## Expected output

PASS: signature verified
kid: sar-prod-ed25519-03
verdict: PASS
receipt_id: sha256:...
