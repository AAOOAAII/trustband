"""Free local alerts: a webhook per event class, their destination, their wiring.

WHY A SPOOL AND NOT A SPAWN
    Two designs were measured. A notifier that blocked with a five-second
    timeout stalled every refused call by five seconds when the endpoint
    hung. A detached interpreter per event never waited on the endpoint --
    and cost 67 ms per refusal to start, on the decision path. Both fail the
    same gate: a decision does not pay for a side channel.

    So `fire()` writes one small file into a spool directory -- an atomic
    create, microseconds -- and returns. Delivery is someone else's problem:
    a daemon thread in a long-lived process, or the NEXT process to construct
    a Guard or run a command, which drains whatever an earlier process left.
    A subprocess-per-call adapter that exits the instant it decides loses
    nothing; its alert goes out one call later. Durability, not a race.

    The cost of that choice is stated: the deciding process cannot see
    whether delivery succeeded. Failures are written to `alerts_failed.jsonl`
    beside the audit log by whichever process attempted delivery, so an
    operator can find them, and the decision never does.

WHY FROM THE RECORD
    Every class fires from the entry `_record` wrote, classified after the
    fact. A class that needed its own branch to fire would drift from the
    log, and the log is the product.

WHY NOT IN SHADOW
    Shadow refuses nothing, and a channel that lights up on hypothetical
    refusals trains people to ignore it. Shadow produces one `shadow_digest`
    per `trustband shadow-report`, carrying counts and the top reasons, so
    the onboarding week still delivers *would have refused: recipient came
    from a web page* to the channel -- once.

THE PAYLOAD IS THE REDACTED RECORD
    `_record` redacts on the way in; this reads what it wrote. A webhook sees
    exactly what the audit log holds and never a raw argument.
"""
from __future__ import annotations

import atexit
import json
import os
import secrets
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

CLASSES = ("refusal", "runaway", "chain_break", "cost_threshold",
           "contract_failure", "agent_revoked", "lock_drift", "shadow_digest")
SPOOL_DIR = "alerts_spool"
FAILED_LOG = "alerts_failed.jsonl"
#: The one destination that is not a URL: our service, which carries the
#: event to the phone approvals already reach (the Unattended add-on). A
#: spooled job says only this word; the key is read from the config beside
#: the spool at delivery time and is never written into a spool file.
HOSTED = "hosted"
NO_KEY = ("hosted alerts need the Unattended add-on (trust.band/add-ons) and "
          "`trustband login`; no key in config. Other destinations are unaffected.")


class AlertConfigError(ValueError):
    """A malformed alerts section. Raised at adoption, never at delivery."""


def validate(cfg: Any) -> Dict[str, str]:
    """`alerts` in the policy: {class: url, ..., "*": url}. Returns the map."""
    if cfg is None:
        return {}
    if not isinstance(cfg, dict):
        raise AlertConfigError("policy.alerts must be a map of event class -> URL")
    out: Dict[str, str] = {}
    for k, v in cfg.items():
        if k != "*" and k not in CLASSES:
            raise AlertConfigError(
                f"policy.alerts: unknown event class {k!r}; one of {CLASSES} or '*'")
        if not isinstance(v, str) or not (v == HOSTED or v.startswith(("http://", "https://"))):
            raise AlertConfigError(f"policy.alerts[{k!r}] must be an http(s) URL or {HOSTED!r}")
        out[k] = v
    return out


def classify(body: Dict[str, Any]) -> Optional[str]:
    """Which class a recorded entry belongs to, or None. Reads the record only."""
    ev = body.get("event")
    if ev == "lock_drift":
        return "lock_drift"
    if ev == "result":
        if any(not c.get("held") for c in (body.get("contracts") or [])):
            return "contract_failure"
        return None
    if ev != "decision" or body.get("allowed"):
        return None
    reason = str(body.get("reason", ""))
    if "cap reached" in reason:
        return "runaway"
    if "is revoked" in reason or "failing closed" in reason:
        return "agent_revoked"
    return "refusal"


def _line(cls: str, body: Dict[str, Any]) -> str:
    """The one sentence a person reads in a channel."""
    tool = body.get("tool", "?")
    who = f"{body['agent']} · " if body.get("agent") else ""
    if cls == "shadow_digest":
        return (f"trustband shadow: {body.get('would_refuse', 0)} of "
                f"{body.get('observed', 0)} calls would have been refused")
    if cls == "chain_break":
        return f"trustband: audit chain broken at seq {body.get('seq')} — the record was edited"
    if cls == "cost_threshold":
        return f"trustband: session cost {body.get('cost')} crossed {body.get('threshold')}"
    if cls == "lock_drift":
        return f"trustband: {body.get('item', '?')} changed since it was pinned"
    if cls == "contract_failure":
        failed = [c["name"] for c in (body.get("contracts") or []) if not c.get("held")]
        return f"trustband: contract failed on {who}{tool}: {', '.join(failed)}"
    return f"trustband refused {who}{tool}: {body.get('reason', '')}"


# --------------------------------------------------------------------------
# delivery: one job, then the spool
# --------------------------------------------------------------------------

def _fail(job: Dict[str, Any], error: str) -> bool:
    log = job.get("failed_log")
    if log:
        try:
            with open(log, "a", encoding="utf-8") as fh:
                fh.write(json.dumps({
                    "ts": time.time(), "class": job["payload"].get("class"),
                    "url": job["url"], "error": error[:200],
                }) + "\n")
        except OSError:
            pass
    return False


def _hosted_target(job: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """Resolved at delivery time by the approvals module, which is the one
    place that reads the config for a hosted destination. This module never
    does (P-HA.2, and pair 6 of Phase 8a)."""
    from trustband.approvals import hosted_alert_target
    return hosted_alert_target(job.get("home"))


def deliver(job: Dict[str, Any], timeout: float = 5.0) -> bool:
    import urllib.error
    import urllib.request
    data = json.dumps(job["payload"]).encode()
    headers = {"Content-Type": "application/json", "User-Agent": "trustband-alerts"}
    url = job["url"]
    if job.get("hosted"):
        target = _hosted_target(job)
        if target is None:
            return _fail(job, NO_KEY)
        url = target["url"]
        headers["Authorization"] = f"Bearer {target['key']}"
    req = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return 200 <= r.status < 300
    except urllib.error.HTTPError as exc:
        # The service says why (402 names the add-on, 429 the cap); keep it.
        try:
            reason = json.load(exc).get("detail", {}).get("reason", "")
        except Exception:
            reason = ""
        return _fail(job, f"HTTP {exc.code}: {reason or exc.reason}")
    except Exception as exc:
        return _fail(job, f"{type(exc).__name__}: {exc}")


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def drain(home: Path, timeout: float = 5.0) -> int:
    """Deliver every spooled job under `home`. Returns how many were attempted.

    Each job is one file. It is CLAIMED by rename before delivery, so two
    drainers on one spool -- the daemon thread and a later process -- never
    deliver the same alert twice; the loser of the rename skips it.

    A claim carries the claimant's PID. A process that exits mid-delivery
    leaves its claim behind; the next drainer sees the PID is dead and takes
    the job back. Found by attacking the pair: the daemon thread claimed a
    job, the process exited, and the alert was orphaned where nothing looked.
    After a crash this is at-least-once, and that is the honest semantics.
    """
    spool = Path(home) / SPOOL_DIR
    if not spool.is_dir():
        return 0
    for c in spool.glob("*.claimed"):
        try:
            pid = int(c.name.rsplit(".", 2)[1])
        except (ValueError, IndexError):
            continue
        if not _alive(pid):
            try:
                os.rename(c, c.with_name(c.name.rsplit(".", 2)[0] + ".json"))
            except OSError:
                pass
    n = 0
    for f in sorted(spool.glob("*.json")):
        claimed = f.with_suffix(f".{os.getpid()}.claimed")
        try:
            os.rename(f, claimed)
        except OSError:
            continue                                  # someone else has it
        try:
            job = json.loads(claimed.read_text(encoding="utf-8"))
            deliver(job, timeout)
            n += 1
        except Exception:
            pass
        finally:
            try:
                claimed.unlink()
            except OSError:
                pass
    return n


class Alerter:
    """Classifies recorded entries and spools them; drains when it can."""

    def __init__(self, urls: Dict[str, str], mode: str = "shadow",
                 home: Optional[Path] = None, background: bool = True) -> None:
        self.urls = urls
        self.mode = mode
        self.home = Path(home) if home else None
        #: A long-lived host delivers from a daemon thread. A command with a
        #: person waiting delivers synchronously and must not start a thread
        #: that could claim the job first and then die with the process.
        self.background = background
        #: Jobs this process spooled. Not deliveries: see the module docstring.
        self.dispatched: List[str] = []
        #: Spool-write failures -- the only failure this process can see.
        self.errors: List[str] = []
        self._thread: Optional[threading.Thread] = None
        self._wake = threading.Event()
        #: True while the drainer is inside deliver(). Read at exit.
        self._busy = False
        #: With no home there is no spool; delivery is in-process only.
        self._inline: List[Dict[str, Any]] = []

    def url_for(self, cls: str) -> Optional[str]:
        return self.urls.get(cls) or self.urls.get("*")

    def consider(self, body: Dict[str, Any]) -> Optional[str]:
        """Fire for a recorded entry if it belongs to a configured class."""
        cls = classify(body)
        if cls is None:
            return None
        # SHADOW REFUSES NOTHING AND ALERTS ON NOTHING, per event.
        if self.mode == "shadow" and cls in ("refusal", "runaway",
                                             "agent_revoked", "contract_failure"):
            return None
        return self.fire(cls, body)

    def fire(self, cls: str, body: Dict[str, Any]) -> Optional[str]:
        url = self.url_for(cls)
        if not url:
            return None
        payload = {
            "class": cls,
            "text": _line(cls, body),          # Slack, ntfy, most others
            "content": _line(cls, body),       # Discord
            "event": body,                     # the redacted record, verbatim
            "sent_at": time.time(),
        }
        job = {"url": url, "payload": payload,
               "failed_log": str(self.home / FAILED_LOG) if self.home else None}
        if url == HOSTED:
            # The word, and where to look for the key later. Never the key.
            job["hosted"] = True
            job["home"] = str(self.home) if self.home else None
        try:
            if self.home is not None:
                spool = self.home / SPOOL_DIR
                spool.mkdir(parents=True, exist_ok=True)
                # An exclusive create: the file exists whole or not at all.
                name = f"{time.time_ns()}-{secrets.token_hex(4)}.json"
                fd = os.open(spool / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(json.dumps(job))
            else:
                self._inline.append(job)
            self.dispatched.append(cls)
        except Exception as exc:
            self.errors.append(f"{cls}: {type(exc).__name__}")
            return cls
        # The file is durable the moment it exists. The drainer is NOT woken
        # per event: measured, a wake on every refusal put the thread's
        # filesystem work on the GIL inside the decision loop (tail 3.8 ms
        # against a 0.16 ms write). It polls once a second instead.
        if self.background:
            self._ensure_thread()
        return cls

    # -- the in-process drainer ---------------------------------------------
    def _ensure_thread(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        t = threading.Thread(target=self._run, name="trustband-alerts", daemon=True)
        self._thread = t
        t.start()
        # A NORMAL exit must not kill a delivery in flight. Found by attacking
        # the pair: the drainer claimed a job, the process finished, and the
        # claim was orphaned until a third process. Bounded: at most one
        # second, and only at exit -- a hung endpoint costs a hook that much
        # once, never a decision. A hard exit skips this and the dead-PID
        # recovery in drain() takes over.
        atexit.register(self._flush_on_exit)

    def _run(self) -> None:
        # Drains once a second, or at once when woken (construction only).
        # Daemon: it dies with the process, and anything it had not reached
        # is still in the spool for the next one.
        while True:
            self._wake.wait(timeout=1.0)
            self._wake.clear()
            self._busy = True
            try:
                self.drain_now()
            finally:
                self._busy = False

    def _flush_on_exit(self) -> None:
        t = self._thread
        if t is not None and t.is_alive() and self._busy:
            t.join(timeout=1.0)

    def drain_now(self, timeout: float = 5.0) -> int:
        """Deliver everything pending, in this thread. Used by the daemon, by
        `alert-test`, and by tests that want determinism."""
        n = 0
        while self._inline:
            deliver(self._inline.pop(0), timeout)
            n += 1
        if self.home is not None:
            n += drain(self.home, timeout)
        return n


def main(argv: Optional[List[str]] = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["--drain"] and len(argv) == 2:
        n = drain(Path(argv[1]))
        print(f"  {n} alert(s) delivered or recorded as failed")
        return 0
    print("usage: python -m trustband.alerts --drain <home>", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
