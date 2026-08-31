# Signed policy bundles — gates before the build

**Registered 2026-08-31, before the code.**

---

## Why this is the last and least of the rows

This is operational, not a defence. OPA has it (bundles), and an organisation
distributing one policy across many agents wants: a version, so a rollout and a
rollback are named things; and a signature, so an agent enforces the policy the
org published and not one an attacker swapped on disk.

It is the least security-critical row because the gate already refuses anything
a policy does not permit. A tampered policy is caught the moment it fails to
verify; it is not a hole in enforcement, it is a supply-chain check on the
policy file itself.

## What a bundle is

The policy, its canonical digest, a version, and an HMAC over all of it under a
distribution key. Built on the pieces already here: `policy.encode` is canonical
and injective, so the digest is stable across key order and formatting, and
`hmac` is the same primitive the audit chain seals with.

```
{ "version": 3,
  "policy": { ... },
  "digest": "<hex sha256 of the canonical encoding>",
  "sig": "<hmac-sha256 over version||digest||policy-bytes>" }
```

The signature covers the version and the digest, not just the policy, so an
attacker cannot replay an old signed policy under a new version number, nor
present a policy whose digest does not match its bytes.

## Registered predictions

**P-BUN1 — a valid bundle verifies and loads.** `Guard.from_bundle` accepts a
bundle signed with the right key and enforces its policy.

**P-BUN2 — a tampered policy is refused.** Change one grant and the digest no
longer matches; change the digest too and the signature no longer matches.
Either way the bundle is rejected, not loaded.

**P-BUN3 — a wrong key is refused.** A bundle signed with a different key does
not verify.

**P-BUN4 — rollback is refused when a floor is set.** A bundle whose version is
below a caller-supplied minimum is rejected, so an attacker cannot force a known
older policy that happened to be signed.

**P-BUN5 — no key, no verification claim.** Loading a bundle without providing a
key loads the policy but records that it was NOT verified, rather than silently
implying it was.

## What it is not

Not asymmetric signing. HMAC means the verifier holds the same key the signer
did — fine for one organisation distributing to its own agents, which is the
case. A public-key scheme is a later change of primitive, not of shape, exactly
as the KMS custody swap was.

## Taxonomy

PASS-CLEAN · PASS-WITH-DRIFT · PARTIAL · FAIL · INCONCLUSIVE.

---

## Result — 2026-08-31, all PASS

- **P-BUN1** — a bundle signed with the right key verifies and `Guard.from_bundle`
  enforces its policy. `verified_bundle` is True.
- **P-BUN2** — a changed grant fails the digest; a digest-fixed change fails the
  signature. Both refused, neither loaded.
- **P-BUN3** — a bundle signed with a different key does not verify.
- **P-BUN4** — a version below the required floor is refused; the same floor
  passes the current version.
- **P-BUN5** — loading without a key returns the policy with `verified_bundle`
  False, so verification is never silently implied.

A reserialised bundle (sorted keys, reindented) still verifies, because the
signature is over the canonical encoding, not the JSON text. `warrantable bundle
sign` and `warrantable bundle verify` round-trip on the command line, and
conformance asserts sign-then-verify plus tamper-refusal: 16/16.
