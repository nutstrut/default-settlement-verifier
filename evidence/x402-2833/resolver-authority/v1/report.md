# x402 #2833 — Resolver-authority conformance vector

Local fixture/test/report only. No production or scanner code, canonical
governance, upstream repository, GitHub thread, comment, issue, PR, or push was
modified.

## Hydration

- CWD: `C:\Users\green\.codex\worktrees\a70b\morpheus`
- Worktree/branch: detached `HEAD` (new local worktree)
- HEAD: `fd4ea905c0a59b48c6f1dbb6d2f1ea743747f537`
- `origin/main`: `fd4ea905c0a59b48c6f1dbb6d2f1ea743747f537`
- Ahead/behind: `0 / 0`
- Working tree at start: clean
- Preflight: `git fetch origin main`; exact expected `origin/main` confirmed.

## Model and schema

The JSON fixture keeps these dimensions separate: evidence validity, lifecycle
binding, internal resolution validity, resolver/check-set authorization, conflict
rule application, and transition authorization. Prior authority binds an exact
resolver/check-set/permitted-successor relationship in `authorized_resolutions`;
it does not authorize by independently intersecting allow-lists. A deterministic
SHA-256 over sorted-key compact JSON commits the authority configuration. It
commits the configuration only; it does not establish authority validity or prove
historical timing.

The evaluator receives the authority commitment ID as an input. The cases set
`committed_before_evidence: true` as a synthetic precondition. This demonstrates
behavior given prior commitment, not real-world temporal proof.

## Exact cases

1. **Only A authorized:** same valid evidence and lifecycle; A and B are both
   internally valid; only A's resolver/check-set is committed. A transitions;
   B is `RESOLVER_NOT_PREAUTHORIZED` and blocked.
2. **Both authorized with `prefer_A`:** both remain valid authorized candidates;
   the precommitted rule selects state A. The evaluator never derives the rule
   from the evidence or resolver output.
3. **Both authorized without a conflict rule:** A and B disagree; both remain
   valid and authorized, but the result is `BLOCKED_INDETERMINATE` and no
   transition occurs.

Negative controls mutate resolver identity and check-set identity after the
commitment. Both remain evidence-valid/lifecycle-bound but lose authority.
Cross-product controls also reject A/check-set-B/state-A,
B/check-set-A/state-B, and A/check-set-A/state-B even though each component
appears somewhere in the committed set.

## Evaluator logic

1. Validate evidence and lifecycle independently.
2. Validate each resolution independently.
3. Match the exact resolver identity + check-set identity + permitted successor
   state tuple in `authorized_resolutions`, together with the supplied
   commitment ID, against prior authority.
4. Permit one authorized valid candidate.
5. For multiple conflicting authorized candidates, apply only the precommitted
   rule; if absent, stop as indeterminate.
6. Never let evidence or resolution validity create authority.

## Verification

Exact command:

```text
python reports/fixtures/x402-2833-resolver-authority-verify-20260919.py
```

Result:

```text
....
----------------------------------------------------------------------
Ran 4 tests in 0.003s

OK
resolver_authority_vector=ok tests=4
```

## Public-thread fit

The artifact contains prior commitment, the same evidence, two internally valid
resolutions, A authorized/B blocked, both-authorized plus a conflict rule, and
both-authorized without a rule where transition stops.

Classification: **READY_TO_OFFER_TO_NSPG13**. This is a readiness classification
only; nothing was offered or posted.

## Strongest safe claim

THIS VECTOR DEMONSTRATES THAT TWO INTERNALLY VALID RESOLUTIONS OVER THE SAME
VALID, LIFECYCLE-BOUND EVIDENCE NEED NOT HAVE EQUAL TRANSITION AUTHORITY.

A RESOLVER/CHECK-SET MAY CONTROL THE SUCCESSOR STATE ONLY WHEN THAT AUTHORITY
DERIVES FROM PRECOMMITTED AUTHORITATIVE CONTEXT.

WHEN MULTIPLE AUTHORIZED RESOLUTIONS CONFLICT, ONLY A PRECOMMITTED CONFLICT RULE
MAY SELECT THE OPERATIVE RESULT; WITHOUT ONE, THE TRANSITION STOPS.

## Limitations and settlement mapping

The fixture is synthetic and does not prove real-world authority, historical
commitment timing, cryptographic provenance, or x402 adoption. It does not
replace evidence receipts, establish governance, or implement production logic.
The narrow mapping is `Capability != Authority != Execution != Verification`,
especially `VALID EVIDENCE != RESOLUTION AUTHORITY`, `POLICY PROVENANCE != PRIOR
POLICY-SELECTION AUTHORITY`, and `AUTHORITY-CONTEXT COMMITMENT != AUTHORITY
VALIDITY`.

Files changed:

- `reports/fixtures/x402-2833-resolver-authority-vector-20260919.json`
- `reports/fixtures/x402-2833-resolver-authority-verify-20260919.py`
- `reports/readiness/x402-2833-resolver-authority-conformance-vector-20260919.md`

External actions: NONE  
Public comments: NONE  
Commits: NONE  
Pushes: NONE

X402 #2833 RESOLVER-AUTHORITY VECTOR COMPLETE —
READY_TO_OFFER_TO_NSPG13
