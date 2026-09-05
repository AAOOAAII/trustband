# Phase 7b — the agent principal in the deposited model. Gates before the proof.

**Registered 2026-09-05, before any Verus is written. Phase 7 shipped local
agent identity held by the conformance suite and said so: "four refusals,
four conjunct shapes, none proved". This extends the `warrantable` Verus
model with the principal and proves the four shapes, so the comparison
row can read *machine-checked* instead of *conformance-held*.**

## What the Python does, restated as the thing to model

`AgentId(name, role, session, epoch, tag)`, `tag = MAC(k(epoch), name ‖
role ‖ session)`, minted inside the key store. The tag rides on every call;
the capability MAC binds it; `revoke_agent` refuses by set membership. Four
refusals, each the shape of an existing conjunct:

| refusal | Python check | conjunct shape |
|---|---|---|
| forged or absent tag | `verify_mac` fails or no tag | B (issuance) |
| capability minted for A, presented by B | agent in the capability MAC | C (this session, now this principal) |
| revoked agent | membership in the revocation set | H (structural, no MAC property) |
| tag minted before rotation | epoch on the identity | F (epoch currency) |

## The model extension

- A principal `AgentId = int`; a state set `agents: Set<Agent>` where
  `Agent { id, sess, epoch, tag }`, written only by a new transition
  `mint_agent`, whose tag is `mac_agent(k_gov(pre.gov_epoch), id, sess)`, an
  uninterpreted function with no algebraic properties, like `mac`.
- A state set `revoked: Set<AgentId>`, written only by `revoke_agent`.
- `Cap` gains `agent: AgentId`, and `govern_issue` folds it into the tag:
  `mac(k_gov(epoch), sess, tier, nonce, agent)`.
- `Presented` gains `agent: AgentId`: who presents. Stamped by `ingest`
  from its argument like `via`; the model does not read it from the payload.
- Four new conjuncts in `valid_system_token`:
  - (I) `s.agents.contains(Agent { id: p.agent, sess, epoch: s.gov_epoch, tag: mac_agent(k_gov(s.gov_epoch), p.agent, sess) })` — minted, current epoch
  - (J) `!s.revoked.contains(p.agent)`
  - (K) `p.cap.agent == p.agent`
  - (F) is unchanged and now also covers the agent through (I)'s epoch.

## Registered predictions

**P-7B.1 — the four theorems verify, with `ASSUMED 0` in the Verus sense.**
`thm_forged_agent_rejected` (an agent value not in `agents` fails the
gate), `thm_cap_bound_to_agent` (a cap with `agent = A` presented with
`agent = B ≠ A` fails), `thm_revoked_agent_rejected` (for reachable `s`, a
revoked id satisfies no `Presented`), `thm_retired_agent_rejected` (an
agent minted in an earlier epoch fails after rotation). No `assume`,
`admit`, `external_body` or `#[verifier::]` is added.

**P-7B.2 — the frames hold.** `lemma_frame_agents`: only `mint_agent` adds
to `agents`; `lemma_frame_revoked`: only `revoke_agent` adds to `revoked`;
`lemma_frame_issued` still holds with the wider `Cap`. Every existing
theorem (`thm_no_bypass`, `thm_retired_epoch_rejected`, the badge
theorems) still verifies unchanged in statement.

**P-7B.3 — non-vacuity.** A reachable state exists in which the gate
passes with a minted, unrevoked, current-epoch agent presenting its own
capability; `lemma_reachable_nonempty` is extended to exhibit it. A gate
that nothing satisfies proves everything.

**P-7B.4 — counterexamples are rejected.** For each of the four conjuncts,
a scratch variant with that conjunct deleted must FAIL to verify the
corresponding theorem, so the conjunct is shown to be load-bearing, in the
style of the existing 5/5 counterexamples. 9/9 after.

**P-7B.5 — the Python matches the model, at the joins.** For each new
conjunct, the conformance check that holds it in Python is named, and the
capability MAC in `gate.py` is confirmed to include the agent tag the way
the model's `govern_issue` does. A model that proves something the code
does not do is worse than no proof.

**P-7B.6 — the record says what changed.** `STATUS.txt` and the README's
"what it proves" gain the principal; VERIFY_LOG carries the run; the
verified count, the assumptions of record (still A1, A2-residual; A1 now
also covers `mac_agent`) and the date are updated. Redeposit is a separate
act by the owner and is not claimed here.

## Scope

In: the model, the theorems, the counterexamples, the records, and a
trustband result document. Out: OAP, Ed25519, hosted custody, any change
to the Python.
