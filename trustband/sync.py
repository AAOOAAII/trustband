"""`trustband sync` and `trustband search`: the retained audit, from the client side.

STANDARD LIBRARY ONLY, LIKE EVERYTHING ELSE IN THE PACKAGE
    `urllib` and `json`. The service has dependencies; the client does not,
    and adding one here would make the free tier carry the paid tier's
    weight.

THE GUARD NEVER SEES THIS
    Nothing in `guard.py` imports or calls this module. Sync reads the local
    log after decisions were made and sends what it finds; it cannot delay,
    change or observe a decision. Asserted structurally by a test.

RESUMABLE, IDEMPOTENT, HONEST OFFLINE
    The service says where it is (`/head`); the client sends the gap in
    batches. Sending the same entries twice stores them once. No network:
    the command says so, exits non-zero, and nothing local changes.
"""
from __future__ import annotations

import json
import secrets
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

from trustband.audit import AuditLog

DEFAULT_URL = "https://api.trust.band"
BATCH = 200


class SyncError(Exception):
    """Could not sync. Never affects the local gate or log."""


def device_id(home: Path) -> str:
    """One stable id per home. Generated once, never derived from anything
    that could identify the machine to a third party."""
    p = Path(home) / "device.json"
    if p.exists():
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(d.get("device"), str) and len(d["device"]) >= 8:
                return d["device"]
        except Exception:
            pass
    did = "d_" + secrets.token_hex(12)
    p.write_text(json.dumps({"device": did}), encoding="utf-8")
    return did


class Client:
    def __init__(self, api_url: str, api_key: str, timeout: float = 15.0) -> None:
        if not api_key:
            raise SyncError("no api_key in config; this is a Pro feature. "
                            "The local gate and log work without it.")
        self.url = api_url.rstrip("/")
        self.key = api_key
        self.timeout = timeout

    def _call(self, method: str, path: str, body: Any = None,
              params: Optional[Dict[str, Any]] = None) -> Any:
        url = self.url + path
        if params:
            url += "?" + urllib.parse.urlencode(
                {k: v for k, v in params.items() if v is not None})
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            url, data=data, method=method,
            headers={"Authorization": f"Bearer {self.key}",
                     "Content-Type": "application/json",
                     "User-Agent": "trustband-sync"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            try:
                detail = json.load(e).get("detail", {})
            except Exception:
                detail = {}
            if isinstance(detail, dict) and "reason" in detail:
                raise SyncError(f"{e.code}: {detail['reason']}"
                                + (f" (broken at seq {detail['broken_at']})"
                                   if "broken_at" in detail else "")) from None
            raise SyncError(f"{e.code} from {url}") from None
        except urllib.error.URLError as e:
            raise SyncError(f"cannot reach {self.url}: {e.reason}. Nothing local "
                            f"changed; sync will resume next time.") from None

    def head(self, device: str) -> Dict[str, Any]:
        return self._call("GET", f"/v1/device/{device}/head")

    def ingest(self, device: str, entries: List[Dict[str, Any]],
               label: Optional[str] = None) -> Dict[str, Any]:
        return self._call("POST", "/v1/ingest",
                          {"device": device, "label": label, "entries": entries, "seals": []})

    def search(self, **params: Any) -> Dict[str, Any]:
        return self._call("GET", "/v1/search", params=params)

    def status(self) -> Dict[str, Any]:
        return self._call("GET", "/v1/status")

    def verify(self, device: str) -> Dict[str, Any]:
        return self._call("GET", f"/v1/verify/{device}")

    # -- Pro-2 -------------------------------------------------------------
    def push_policy(self, bundle: Dict[str, Any]) -> Dict[str, Any]:
        return self._call("POST", "/v1/policy", {"bundle": bundle})

    def latest_policy(self) -> Dict[str, Any]:
        return self._call("GET", "/v1/policy/latest")

    def regress(self, policy: Dict[str, Any], device: Optional[str] = None,
                limit: int = 5000) -> Dict[str, Any]:
        return self._call("POST", "/v1/regress",
                          {"policy": policy, "device": device, "limit": limit})


# --------------------------------------------------------------------------
# Pro-2 commands. The signature is verified HERE, with the key on the device.
# --------------------------------------------------------------------------

def main_push_policy(home: Path, cfg: Dict[str, Any], bundle_path: Path) -> int:
    try:
        bundle = json.loads(Path(bundle_path).read_text(encoding="utf-8"))
        c = Client(cfg.get("api_url") or DEFAULT_URL, cfg.get("api_key") or "")
        r = c.push_policy(bundle)
    except (SyncError, OSError, ValueError) as e:
        print(f"  push failed: {e}")
        return 1
    print(f"  version {r['version']} {'stored' if r.get('stored') else 'already held'}; "
          f"digest {r['digest'][:16]}…")
    return 0


def main_pull_policy(home: Path, cfg: Dict[str, Any]) -> int:
    """Fetch the latest bundle, verify it locally, adopt it, raise the floor.

    THE FLOOR IS ON THE DEVICE. `policy_version.json` beside the config
    records the last adopted version; a served bundle below it is refused
    here, whatever the service says -- pair 2. No key on the device means no
    adoption and no change to the policy file -- pair 3.
    """
    from trustband.bundle import BundleError, verify_bundle
    home = Path(home)
    key_ref = cfg.get("policy_key_file")
    if not key_ref:
        print("  pull refused: no policy_key_file in config, so a served bundle cannot "
              "be verified. The policy file is unchanged.")
        return 1
    key_path = home / key_ref
    if not key_path.exists():
        print(f"  pull refused: {key_path} does not exist. The policy file is unchanged.")
        return 1
    floor_file = home / "policy_version.json"
    floor = 0
    if floor_file.exists():
        try:
            floor = int(json.loads(floor_file.read_text(encoding="utf-8")).get("version", 0))
        except Exception:
            floor = 0
    try:
        c = Client(cfg.get("api_url") or DEFAULT_URL, cfg.get("api_key") or "")
        served = c.latest_policy()
        bundle = served["bundle"]
        policy = verify_bundle(bundle, key_path.read_bytes(), min_version=max(floor, 1))
    except SyncError as e:
        print(f"  pull failed: {e}")
        return 1
    except BundleError as e:
        print(f"  pull refused: {e}. The policy file is unchanged.")
        return 1
    ref = cfg.get("policy")
    if not isinstance(ref, str):
        print("  pull refused: config's policy is inline, not a file; nothing to write")
        return 1
    (home / ref).write_text(json.dumps(policy, indent=2), encoding="utf-8")
    floor_file.write_text(json.dumps({"version": bundle["version"],
                                      "digest": bundle["digest"]}), encoding="utf-8")
    print(f"  adopted version {bundle['version']} into {home / ref}; floor is now "
          f"{bundle['version']}")
    return 0


def main_regress(home: Path, cfg: Dict[str, Any], candidate_path: Path,
                 device: Optional[str] = None) -> int:
    try:
        policy = json.loads(Path(candidate_path).read_text(encoding="utf-8"))
        policy.pop("_pack", None); policy.pop("_inferred", None)
        c = Client(cfg.get("api_url") or DEFAULT_URL, cfg.get("api_key") or "")
        r = c.regress(policy, device=device)
    except (SyncError, OSError, ValueError) as e:
        print(f"  regress failed: {e}")
        return 1
    total_dec = total_ref = total_allow = 0
    for d in r["devices"]:
        tag = d["device"][:12]
        if "insufficient" in d:
            print(f"  {tag}  cannot replay: {d['insufficient']}")
            continue
        if "error" in d:
            print(f"  {tag}  error: {d['error']}")
            continue
        total_dec += d["decisions"]; total_ref += d["newly_refused"]; total_allow += d["newly_allowed"]
        print(f"  {tag}  {d['decisions']} decision(s): this change would refuse "
              f"{d['newly_refused']} it allowed, and allow {d['newly_allowed']} it refused")
        for ch in d["changes"][:12]:
            who = f"{ch['agent']} · " if ch.get("agent") else ""
            arrow = "allow -> REFUSE" if not ch["now_allowed"] else "refuse -> allow"
            print(f"      #{ch['seq']:<5} {who}{ch['tool']:<16} {arrow}   {ch['reason'][:60]}")
        if len(d["changes"]) > 12:
            print(f"      … {len(d['changes']) - 12} more")
    print(f"  over the newest {r['limit']} entries per device: {total_dec} decision(s), "
          f"{total_ref} newly refused, {total_allow} newly allowed")
    return 0


def sync(home: Path, api_url: str, api_key: str, label: Optional[str] = None
         ) -> Dict[str, Any]:
    """Push the local chain's new entries. Returns what the service retained."""
    home = Path(home)
    log = home / "audit.jsonl"
    if not log.exists():
        raise SyncError(f"no record at {log}; nothing to sync")
    entries = [e.as_dict() for e in AuditLog(log).entries]
    dev = device_id(home)
    c = Client(api_url, api_key)
    h = c.head(dev)
    start = int(h["last_seq"]) + 1
    todo = [e for e in entries if e["seq"] >= start]
    sent = 0
    last: Dict[str, Any] = {"retained_through": h["last_seq"], "stored": 0, "skipped": 0}
    for i in range(0, len(todo), BATCH):
        last = c.ingest(dev, todo[i:i + BATCH], label)
        sent += last.get("stored", 0)
    return {"device": dev, "local_entries": len(entries), "sent": sent,
            "retained_through": last.get("retained_through"),
            "already_retained": start}


def main_sync(home: Path, cfg: Dict[str, Any]) -> int:
    try:
        out = sync(home, cfg.get("api_url") or DEFAULT_URL, cfg.get("api_key") or "",
                   cfg.get("device_label"))
    except SyncError as e:
        print(f"  sync failed: {e}")
        return 1
    print(f"  device {out['device']}: {out['local_entries']} local entries, "
          f"{out['sent']} sent, retained through seq {out['retained_through']}")
    return 0


def main_search(home: Path, cfg: Dict[str, Any], **params: Any) -> int:
    try:
        c = Client(cfg.get("api_url") or DEFAULT_URL, cfg.get("api_key") or "")
        res = c.search(**params)
    except SyncError as e:
        print(f"  search failed: {e}")
        return 1
    for h in res["hits"]:
        b = h["body"]
        who = f"{b['agent']} · " if b.get("agent") else ""
        mark = ("NO " if b.get("event") == "decision" and not b.get("allowed") else
                "ok " if b.get("event") == "decision" else "   ")
        print(f"  {mark} {h['device'][:10]} #{h['seq']:<5} {who}{b.get('tool', b.get('event', '?'))}"
              f"  {b.get('reason', '')[:70]}")
    print(f"  {res['count']} hit(s)")
    return 0
