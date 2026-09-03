"""Which tier this install is on, and what that does and does not change.

THE ONE PROPERTY THAT MATTERS
    **Enforcement never consults this module.** No tier check, no key check, no
    network call in the decision path. A user with no key, an expired key or a
    forged key gets byte-identical enforcement to a paying customer.

    A security tool that fails open on an unpaid invoice is worse than no
    security tool. `conformance.py` asserts this rather than documenting it.

WHY THERE IS NO LOCAL LICENCE CHECK
    The client is open source. Any key that verifies a licence locally ships in
    the source and can be forged by whoever reads it, so local licence
    enforcement here would be theatre.

    Paid features are HOSTED -- audit retention, approval routing, fleet policy,
    fleet inference -- so access control lives at the server. The client holds
    an API key and the endpoint accepts or rejects it. A forged local token
    buys nothing, because there is nothing local to unlock.

WHAT STOPS WHEN A KEY LAPSES
    The hosted parts, and only those. Local audit logging, shadow recording,
    inference and policy tests continue exactly as before. That is the whole
    difference between a lapsed subscription and a lapsed defence.

NO TELEMETRY
    Determining entitlement transmits nothing about the agent -- no usage, no
    policy content, no tool calls. For a product whose pitch is that decisions
    stay local, phoning home with usage would refute the pitch.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

#: Hosted capabilities. Each is a SERVICE, not a local feature to unlock.
HOSTED: Dict[str, str] = {
    "audit_retention": "the record retained and verified by a party who cannot edit it; "
                       "search across sessions and devices  (trustband sync, search)",
    "fleet_policy": "one signed policy pushed everywhere, verified on each device  "
                    "(push-policy, pull-policy)",
    "policy_regression": "what a policy change would have refused last week  (regress)",
    "per_client_reports": "spend caps per client that hard-stop, and a report to invoice from",
    "approval_routing": "a confirmation routed to a colleague or a client contact",
    "incident_pack": "a sealed, signed excerpt with the provenance of every argument",
    "hosted_custody": "zero key bytes in your process",
}

#: Enterprise adds services that touch a customer's own infrastructure.
ENTERPRISE_ONLY = {"byok_custody", "sso", "multi_tenancy"}

FREE, PRO, ENTERPRISE = "free", "pro", "enterprise"


@dataclass(frozen=True)
class Entitlement:
    """What this install may reach. Says nothing about what it may enforce."""

    tier: str = FREE
    #: None means never checked with the server (offline, or no key at all).
    verified: Optional[bool] = None
    reason: str = "no API key configured; self-hosted free tier"

    def has(self, capability: str) -> bool:
        """Is a HOSTED capability available. Never asked about enforcement."""
        if self.tier == ENTERPRISE:
            return capability in HOSTED or capability in ENTERPRISE_ONLY
        if self.tier == PRO:
            return capability in HOSTED
        return False

    def why_not(self, capability: str) -> str:
        """A refusal a person can act on, never a silent degradation."""
        if capability in ENTERPRISE_ONLY:
            return (f"{capability} is an Enterprise service (it touches your own "
                    f"infrastructure). Current tier: {self.tier}.")
        what = HOSTED.get(capability, capability)
        return (f"{capability} — {what} — needs a Pro key. Current tier: "
                f"{self.tier}. Enforcement, local audit and shadow are "
                f"unaffected and continue exactly as now.")


def from_config(cfg: Dict[str, Any]) -> Entitlement:
    """Read entitlement from config. Never raises, never blocks.

    A missing, malformed or unreachable key yields the free tier, because the
    only thing a key controls is access to hosted services -- and being unable
    to reach them must never look like a security state.
    """
    key = (cfg or {}).get("api_key")
    if not key or not isinstance(key, str):
        return Entitlement()
    # The key's SHAPE is a local hint for display only. Whether it actually
    # entitles anything is decided by the server on use, not here -- so this
    # never claims verified=True on its own authority.
    tier = ENTERPRISE if key.startswith("tb_ent_") else PRO
    return Entitlement(tier=tier, verified=None,
                       reason="key present; entitlement confirmed by the "
                              "hosted service when a hosted feature is used")


def upgrade_prompt(shadow_observations: List[Dict[str, Any]],
                   ent: Optional[Entitlement] = None) -> Optional[str]:
    """What Pro would add FOR THIS INSTALL, derived from real traffic.

    Returns None when the traffic gives no honest reason to upgrade. A prompt
    that fires regardless of what happened is an advertisement; one computed
    from the user's own calls is information. If nothing in the observations
    warrants it, say nothing.
    """
    ent = ent or Entitlement()
    if ent.tier != FREE or not shadow_observations:
        return None
    refused = [o for o in shadow_observations if not o.get("would_allow")]
    if not refused:
        return None
    # Refusals a human would have to answer are the approval-routing case: the
    # operator at the keyboard is not always the person who should decide.
    confirmable = [o for o in refused if o.get("confirmable")]
    lines = []
    if confirmable:
        lines.append(f"{len(confirmable)} of {len(refused)} would-be refusals "
                     f"are ones a person can approve. Pro routes those to "
                     f"someone other than whoever is at the keyboard.")
    if len(shadow_observations) >= 200:
        lines.append(f"This install has recorded {len(shadow_observations)} "
                     f"decisions locally. Pro retains and exports that history "
                     f"for review beyond the local log.")
    return " ".join(lines) if lines else None
