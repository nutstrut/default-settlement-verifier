# defaultverifier Skill (internal, unpublished)

Helps an agent verify an **existing** Default Settlement receipt offline and state what
it does and does not establish. Verification only.

- **Does:** verify `0.2-candidate` receipts (profiles `settlement-witness-verified-v0.2`
  and `-counterparty-bound`) against a pinned bundled trust snapshot; map signed
  properties to established / contradicted / not established; report unsigned fields by name.
- **Does not:** issue or demo receipts, call hosted endpoints, enroll, pay, fetch keys,
  use the network or credentials, certify agents, or prove execution / payment / legal finality.
- **Versions:** v0.2-candidate only. v0.1 and portable receipts are rejected as
  `NOT_A_V02_RECEIPT`; the sibling `settlement-witness` Skill (untouched) covers v0.1.
- **One verifier:** `scripts/verify_v02.py` is a byte copy of defaultsettle-cli's core
  (hashes in `UPSTREAM.json`). `scripts/verify_receipt_v02.py` is only I/O and report rendering.
- **Requires:** python3 and `cryptography`.

Test (offline; includes the 187-vector parity suite):

```bash
python3 -m pytest openclaw/skills/defaultverifier/tests -q
```
