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
