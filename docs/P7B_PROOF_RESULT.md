# Phase 7b — the agent principal in the deposited model. Result.

**Run 2026-09-05 against `P7B_PROOF_GATES.md`, on branch
`phase7b-agent-principal` of the private `warrantable` crate (the current
home of the model; the local `auth_gate_th` copy is superseded). Verus
0.2026.06.07.cd03505, the pinned toolchain.**

## Verdict: PASS-CLEAN on the proof; the redeposit is the owner's act

| | |
|---|---|
| P-7B.1 the four theorems verify, `ASSUMED 0` | **PASS-CLEAN** |
| P-7B.2 the frames hold | **PASS-CLEAN** |
| P-7B.3 non-vacuity | **PASS-CLEAN** |
| P-7B.4 counterexamples rejected | **PASS-CLEAN**, 10/10 |
| P-7B.5 the Python matches the model at the joins | **PASS-CLEAN**, with one shape difference stated |
| P-7B.6 the record says what changed | **PASS** on the branch; not redeposited |

```
before   verification results:: 20 verified, 0 errors    counterexamples 6/6
after    verification results:: 31 verified, 0 errors    counterexamples 10/10
```

No `assume`, `admit`, `external_body` or `#[verifier::]` was added. The
assumptions of record stay at two: A1 now also covers `mac_agent`, per
epoch key; A2-residual is unchanged.

## What was added to the model

- `AgentId`, `Agent { id, sess, epoch, tag }`, `mac_agent` (uninterpreted,
  like `mac`), `expected_agent(s, id, sess)`: the record the gate demands.
- State: `agents: Set<Agent>`, `revoked: Set<AgentId>`.
- Transitions: `mint_agent` (sole writer of `agents`, tag under the current
  epoch's key), `revoke_agent` (sole writer of `revoked`, never shrinks).
- `Cap.agent`, folded into the capability tag; `govern_issue` requires the
  agent to be minted in the current epoch. `Presented.agent`: who presents,
  an argument of `ingest`, never read from the payload.
- Gate conjuncts (I) `agents.contains(expected_agent(s, p.agent, sess))`,
  (J) `!revoked.contains(p.agent)`, (K) `p.cap.agent == p.agent`.
- Invariant `inv_agents`: every minted agent bears the governance tag and
  an epoch no later than the current one.

## The theorems

| theorem | shape | how |
|---|---|---|
| `thm_forged_agent_rejected` | B | (I) by set membership |
| `thm_cap_bound_to_agent` | C | (K) by disequality |
| `thm_revoked_agent_rejected` | H | (J) by set membership, no MAC property |
| `thm_retired_agent_rejected` | F | every record for the principal has `epoch < gov_epoch`; (I) asks for `gov_epoch`; integer disequality |
| `thm_rotation_retires_agents` | F | one `govern_rotate` step kills every presentation, via `inv_agents` |
| `thm_gate_agent_governance` | — | an accepted presentation names a governance-minted, current, unrevoked agent bound to its capability |
| `lemma_frame_agents`, `lemma_frame_revoked` | — | sole writers, by case analysis over all seven transitions |
| `lemma_gate_satisfiable` | — | init → mint_agent → govern_issue → ingest, and the gate holds |

Every existing theorem verifies with its statement unchanged; the
witnesses in `lemma_reachable_nonempty` mint an agent first, since a
capability is now minted for one.

## P-7B.4 — the four new counterexamples

Each presents a capability with everything else in order and one thing
wrong, and asserts the gate accepts it. Each must fail to verify, and did:

```
correctly-rejected  ce7_forged_agent            (I) dropped -> anyone may name any agent
correctly-rejected  ce8_cap_presented_by_other_agent   (K) dropped -> capabilities transferable
correctly-rejected  ce9_revoked_agent           (J) dropped -> revocation is decoration
correctly-rejected  ce10_retired_agent          epoch dropped from expected_agent -> identity outlives rotation
```

The six earlier cases still fail with the wider `Cap` and `Presented`.

## P-7B.5 — the joins with the Python

| model | Python (`identity.py`, `guard.py`, `gate.py`) | held by |
|---|---|---|
| `mint_agent`, tag under `k_gov(gov_epoch)` | `AgentRegistry.mint`: `keys.mac(epoch, DOMAIN, name, role, session)` inside the key store | `test_p73_*`, conformance "forged / bare / foreign tag" |
| (I) membership of `expected_agent` | `AgentRegistry.verify`: `verify_mac` under the identity's epoch, and the epoch must be current | `test_pair2_rotation_in_one_process_retires_identities_in_another` |
| (K) `cap.agent == p.agent` | the capability is minted with `sess = agent.principal`, the integer derived from the verified tag; presented by another principal it fails the gate's (C) | `test_p72_capability_bound_to_agent_principal` |
| (J) `revoked.contains(p.agent)` | `revoke_agent`: the registry's name set (a file, re-read per check) and `gate.revoke_session(principal)` (the gate's own H) | `test_p74_revocation_is_local_and_structural`, conformance "a revoked agent is refused and no other agent is affected", `test_pair6_*` |
| `expected_agent(s, id, sess)` carries `sess` | `call.agent.session != call.session` refuses | `_check_identity`, conformance |

**The one shape difference, stated.** The model gives the capability a
separate `agent` field and a separate `revoked` set. The Python puts the
principal in the capability's *session* slot and revokes through the gate's
existing session-revocation set plus the registry's name file. Same
conjuncts, different slots. The model's shape was chosen so that the
existing theorems about sessions stay untouched in statement; the Python's
was chosen in Phase 7 so that no new primitive was needed. Neither is a
claim about the other beyond the table above.

## What this does not show

- **Not redeposited.** The branch is pushed to the private repository. The
  comparison row on the site stays *conformance-held* until the owner
  merges and redeposits; a row that says machine-checked before the deposit
  exists would be the kind of claim this project refuses.
- **No third-party verifiability**, as before: OAP consumption remains the
  follow-up.
- **A1 grew by one function.** Unforgeability is now assumed of `mac_agent`
  as well as `mac`, per epoch key. Same assumption, one more instance.
