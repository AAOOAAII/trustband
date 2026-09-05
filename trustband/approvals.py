"""The `queue` disposition's courier: post a rendered question, poll for the answer.

WHAT THIS IS ALLOWED TO DO
    Carry a question the gate already rendered to the hosted service, and carry
    back one of three answers: approved, denied, nobody answered. It cannot
    change what was asked, and the gate checks that what came back is bound to
    what it sent (the value digest) before it spends an approval.

WHAT IT MUST NOT DO
    Decide. Block without a bound. Be consulted when the policy did not choose
    `queue`. Send anything that has not been through redaction. A failure here
    is a refusal, never an allow, and never a hang past the deadline the gate
    chose before it asked.

stdlib only, like `sync.py`: this runs inside the agent's process.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional

DEFAULT_URL = "https://api.trust.band"

NO_KEY = ("no api_key is configured; queue needs the Unattended add-on "
          "(trust.band/add-ons). Enforcement and the local log are unaffected.")


class ApprovalError(Exception):
    """The question could not be asked or the answer could not be read.
    Always a refusal upstream; the message says why, for the record."""


class NoCourier:
    """What an install without a key holds when its policy chose `queue`.

    It refuses to ask, with a reason that names the add-on, at the first
    confirmable call -- never at construction, so nothing else about
    enforcement depends on a billing state.
    """

    def __init__(self, reason: str = NO_KEY) -> None:
        self.reason = reason

    def submit(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        raise ApprovalError(self.reason)

    def poll(self, approval_id: str) -> Dict[str, Any]:
        raise ApprovalError(self.reason)


def hosted_alert_target(home: Optional[str]) -> Optional[Dict[str, str]]:
    """Where a `hosted` alert goes and the key it carries, read NOW from the
    config beside the spool. None when there is no key. Lives here, not in
    alerts.py, so the alert module never reads a key (pair 6 of Phase 8a)."""
    if not home:
        return None
    try:
        from pathlib import Path
        cfg = json.loads((Path(home) / "config.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    key = cfg.get("api_key")
    if not key or not isinstance(key, str):
        return None
    return {"url": (cfg.get("api_url") or DEFAULT_URL).rstrip("/") + "/v1/alerts",
            "key": key}


def courier_from_config(cfg: Optional[Dict[str, Any]]) -> Any:
    """The courier for a config. THIS is the only place the key is read for
    approvals; the guard is handed the object and never sees the key."""
    cfg = cfg or {}
    key = cfg.get("api_key")
    if not key or not isinstance(key, str):
        return NoCourier()
    return ApprovalClient(cfg.get("api_url"), key)


class ApprovalClient:
    def __init__(self, api_url: Optional[str], api_key: Optional[str],
                 timeout: float = 10.0) -> None:
        if not api_key:
            raise ApprovalError(NO_KEY)
        self.url = (api_url or DEFAULT_URL).rstrip("/")
        self.key = api_key
        self.timeout = timeout

    def _call(self, method: str, path: str, body: Any = None) -> Dict[str, Any]:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            self.url + path, data=data, method=method,
            headers={"Authorization": f"Bearer {self.key}",
                     "Content-Type": "application/json",
                     "User-Agent": "trustband-approvals"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                out = json.load(r)
        except urllib.error.HTTPError as e:
            try:
                detail = json.load(e).get("detail", {})
            except Exception:
                detail = {}
            reason = detail.get("reason") if isinstance(detail, dict) else None
            raise ApprovalError(f"{e.code}: {reason or 'no reason given'}") from None
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise ApprovalError(f"cannot reach {self.url}: "
                                f"{getattr(e, 'reason', e)}") from None
        if not isinstance(out, dict):
            raise ApprovalError("malformed answer from the service")
        return out

    def submit(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Ask. Returns {id, expires}. Raises ApprovalError; never blocks past
        the connect timeout."""
        out = self._call("POST", "/v1/approvals", payload)
        if not isinstance(out.get("id"), str):
            raise ApprovalError("the service accepted the question but returned no id")
        return out

    def poll(self, approval_id: str) -> Dict[str, Any]:
        """One look. Returns {id, state, digest, decided_by}."""
        return self._call("GET", f"/v1/approvals/{urllib.parse.quote(approval_id)}")
