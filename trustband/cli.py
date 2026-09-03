"""`trustband` — test a policy, explain a decision, check an adapter.

Deliberately small. The product is a library plus two hooks; this is the part
an operator touches.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _packs_dir() -> Path:
    return Path(__file__).resolve().parent / "packs"


def _export(a) -> int:
    """Ship the decision record to a collector, or write it out for one.

    WHY THIS COMMAND EXISTS AT ALL
        `otel.py` shipped in 0.2.0 as a library module that nothing called.
        Every claim made for it was true and none of it was reachable without
        writing your own driver, which is not a feature, it is a file.

    IT REPORTS WHAT WENT AND WHAT DID NOT
        The Exporter never raises: a collector that is down must not become a
        security event. That is right for the hot path and wrong for a command
        a person just ran, so the failure is printed here rather than swallowed.
    """
    from trustband.audit import AuditLog
    from trustband.otel import Exporter, payload

    home = _home(a)
    log = home / "audit.jsonl"
    if not log.exists():
        print(f"  no record at {log}")
        print("  run the agent with the hook installed, then export.")
        return 1

    events = [e.body for e in AuditLog(log).entries]
    if a.session:
        events = [b for b in events if b.get("session") == a.session]
    if not events:
        print("  nothing to export"
              + (f" for session {a.session}" if a.session else ""))
        return 1

    if not a.endpoint and not a.out:
        print("  give --endpoint to send, or --out to write the payload.")
        print("  Nothing was sent; refusing to guess a destination.")
        return 2

    exp = Exporter(endpoint=a.endpoint, path=a.out, service=a.service)
    ok = exp.export(events)
    where = a.endpoint or a.out
    if ok:
        print(f"  {len(events)} event(s) exported to {where}")
        return 0
    for err in exp.errors:
        print(f"  export failed: {err}")
    if not exp.errors:
        print(f"  export did not go to {where}, and reported no reason")
    return 1


def _report(a) -> int:
    """Token accounting. Cost only if the operator declared rates."""
    from trustband.tokens_report import main as _tok
    home = _home(a)
    t = a.transcript
    if t is None:
        cfgp = home / "config.json"
        cfg = (json.loads(cfgp.read_text(encoding="utf-8"))
               if cfgp.exists() else {})
        t = cfg.get("transcript_path")
        if not t:
            print("  no transcript given. Pass --transcript, or set "
                  "transcript_path in config.json.")
            print("  The host records per-turn usage there; trustband reads it "
                  "rather than estimating, because an estimate cannot see "
                  "caching and would be several times wrong.")
            return 1
    cfgp = home / "config.json"
    cfg = (json.loads(cfgp.read_text(encoding="utf-8"))
           if cfgp.exists() else {})
    return _tok(Path(t), cfg.get("cost"))


def _status(a) -> int:
    """Tier and hosted availability -- and what does not depend on either."""
    from trustband.entitlement import (from_config, upgrade_prompt, HOSTED,
                                       FREE)
    home = _home(a)
    cfg_path = home / "config.json"
    cfg = (json.loads(cfg_path.read_text(encoding="utf-8"))
           if cfg_path.exists() else {})
    ent = from_config(cfg)
    obs = _observations(home)

    print(f"  tier        {ent.tier}")
    print(f"              {ent.reason}")
    print(f"  mode        {cfg.get('mode', '(not configured)')}")
    print()
    # The part that must be unambiguous: none of this depends on the tier.
    print("  Unaffected by tier, always local, always on:")
    print("    enforcement, provenance, local audit log, shadow mode,")
    print("    policy inference, policy tests. A lapsed key never turns")
    print("    these off.")
    if ent.tier == FREE:
        print()
        print("  Hosted services (need a Pro key):")
        for name, what in HOSTED.items():
            print(f"    {name:18s} {what}")
    prompt = upgrade_prompt(obs, ent)
    if prompt:
        print()
        print(f"  For this install: {prompt}")
    elif ent.tier == FREE and obs:
        print()
        print(f"  For this install: {len(obs)} decisions recorded, nothing "
              f"yet that a hosted service would have changed.")
    return 0


def _packs() -> int:
    """Every pack, with the measurement behind it resolved to a real file.

    The citation used to be a repo-relative path in a private repository, so a
    user who wanted to check the number had nowhere to go. A citation that
    resolves nowhere is worse than none: it borrows the authority of evidence
    without supplying any.
    """
    d = _packs_dir()
    md = Path(__file__).resolve().parent / "measurements"
    for f in sorted(d.glob("*.json")):
        meta = json.loads(f.read_text(encoding="utf-8")).get("_pack", {})
        print(f"  {meta.get('name', f.stem)}")
        print(f"    {meta.get('description', '')}")
        for cite in (meta.get("measurement") or "").split(","):
            cite = cite.strip()
            if not cite.endswith(".md"):
                continue
            here = md / Path(cite).name
            print(f"    evidence: {here}" if here.exists()
                  else f"    evidence: {cite} (not shipped; see trust.band)")
    return 0


def _load_pack(name: str) -> dict:
    f = _packs_dir() / f"{name}.json"
    if not f.exists():
        raise FileNotFoundError(
            f"no pack {name!r}; try: trustband packs")
    return json.loads(f.read_text(encoding="utf-8"))


def _bundle(a) -> int:
    from trustband import bundle as B
    key = a.key_file.read_bytes()
    if a.op == "sign":
        pol = json.loads(a.policy.read_text(encoding="utf-8"))
        pol.pop("_pack", None); pol.pop("_inferred", None)
        out = B.make_bundle(pol, a.version, key)
        a.bundle.write_text(json.dumps(out, indent=2), encoding="utf-8")
        print(f"  signed v{a.version} -> {a.bundle}")
        return 0
    try:
        b = json.loads(a.bundle.read_text(encoding="utf-8"))
        B.verify_bundle(b, key, a.min_version)
    except Exception as e:
        print(f"  INVALID: {e}")
        return 1
    print(f"  valid: v{b['version']}, digest {b['digest'][:16]}...")
    return 0


def _home(a) -> Path:
    import os
    return a.home or Path(os.environ.get("TRUSTBAND_HOME",
                                         Path.home() / ".trustband"))


def _observations(home: Path) -> list:
    f = home / "shadow.jsonl"
    if not f.exists():
        return []
    out = []
    for line in f.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue          # a torn final line, not a reason to stop
    return out


def _shadow_report(a) -> int:
    """The number an operator actually wants: what would this have cost me."""
    import collections
    home = _home(a)
    obs = _observations(home)
    if not obs:
        print(f"  no observations yet in {home / 'shadow.jsonl'}")
        print("  use the agent for a while with mode = shadow, then look again.")
        return 0
    refused = [o for o in obs if not o.get("would_allow")]
    print(f"  {len(obs)} calls observed, "
          f"{len(refused)} would have been refused "
          f"({len(refused) / len(obs):.0%})")
    print("  SHADOW — nothing was blocked. This is measurement, not protection.")
    if refused:
        print()
        by_tool = collections.Counter(o.get("tool", "?") for o in refused)
        for tool, n in by_tool.most_common(8):
            print(f"    {n:4d}  {tool}")
        print()
        seen = set()
        for o in refused:
            r = o.get("reason", "")[:100]
            if r not in seen:
                seen.add(r)
                print(f"    {r}")
            if len(seen) >= 4:
                break

    cfg_path = home / "config.json"
    cfg = (json.loads(cfg_path.read_text(encoding="utf-8"))
           if cfg_path.exists() else {})

    # ONE digest per report, never per observation. Shadow alerts on nothing
    # per event; this is the one message the onboarding week delivers.
    try:
        from trustband.alerts import Alerter, validate as _aval
        pol = _policy_from_config(home, cfg)
        urls = _aval(pol.get("alerts")) if pol else {}
        if urls:
            import collections as _c
            top = [r for r, _ in _c.Counter(
                o.get("reason", "")[:100] for o in refused).most_common(3)]
            al = Alerter(urls, mode="shadow", home=home, background=False)
            al.fire("shadow_digest", {
                "event": "shadow_digest", "observed": len(obs),
                "would_refuse": len(refused), "top_reasons": top})
            al.drain_now()
            print(f"  digest sent to the shadow_digest webhook")
    except Exception as e:
        print(f"  (alert not sent: {e})")

    # The conversion moment, computed from THIS traffic or not shown at all.
    # An upsell that fires regardless of what happened is an advertisement.
    from trustband.entitlement import from_config, upgrade_prompt
    prompt = upgrade_prompt(obs, from_config(cfg))
    if prompt:
        print()
        print(f"  {prompt}")
    return 0


def _policy_from_config(home: Path, cfg: dict) -> dict:
    """The policy the config points at, or {} if there is none."""
    ref = cfg.get("policy")
    if ref is None:
        return {}
    if isinstance(ref, dict):
        return ref
    p = home / ref
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}


def _alert_test(a) -> int:
    """Send one synthetic event of a class, to prove the wiring end to end."""
    from trustband.alerts import Alerter, CLASSES, validate as _aval
    home = _home(a)
    cfgp = home / "config.json"
    cfg = json.loads(cfgp.read_text(encoding="utf-8")) if cfgp.exists() else {}
    urls = _aval(_policy_from_config(home, cfg).get("alerts"))
    if not urls:
        print("  no alerts configured. Add to the policy:")
        print('    "alerts": {"*": "https://hooks.slack.com/services/..."}')
        print(f"  classes: {', '.join(CLASSES)}")
        return 1
    al = Alerter(urls, mode="enforce", home=home, background=False)
    body = {"event": "decision", "tool": "example", "allowed": False,
            "reason": "test alert from `trustband alert-test`; nothing was refused",
            "session": "test"}
    if a.cls == "shadow_digest":
        body = {"event": "shadow_digest", "observed": 0, "would_refuse": 0}
    sent = al.fire(a.cls, body)
    if not sent:
        print(f"  no URL for class {a.cls!r} and no '*' default")
        return 1
    n = al.drain_now()
    print(f"  {a.cls} -> {al.url_for(a.cls)}  ({n} delivered or recorded as failed)")
    print(f"  delivery failures, if any, land in {home / 'alerts_failed.jsonl'}")
    return 0


def _infer(a) -> int:
    """A policy permitting exactly what was observed, replay-checked."""
    from trustband.gate import Gate
    from trustband.issuance import Issuer
    home = _home(a)
    obs = _observations(home)
    if not obs:
        print(f"  nothing to infer from in {home / 'shadow.jsonl'}")
        return 1

    # A CALL THAT WOULD HAVE BEEN REFUSED IS NOT TRAINING DATA.
    #
    # Shadow executes everything, so a poisoned command sitting in the
    # observation window would otherwise teach the floor to permit exactly the
    # class it was refusing. Measured on the first run of this loop: one
    # tool-derived command widened `command` to `tool`, and the inferred policy
    # then permitted every tool-derived command.
    #
    # The refused ones are the REVIEW QUEUE -- shadow-report shows them, and a
    # person decides. --include-refused widens the floor deliberately, which is
    # a different act from doing it by accident.
    learn = obs if getattr(a, "include_refused", False) else [
        o for o in obs if o.get("would_allow")]
    skipped = len(obs) - len(learn)
    if not learn:
        print("  every observed call would have been refused; nothing to "
              "infer a floor from. Review shadow-report first.")
        return 1

    RANK = {"governance": 0, "session": 1, "tool": 2, "user": 3}
    tools, bands = set(), {}
    for o in learn:
        t = o.get("tool")
        if not t:
            continue
        tools.add(t)
        for arg, b in (o.get("bands") or {}).items():
            cur = bands.get((t, arg))
            if cur is None or RANK.get(b, 0) > RANK.get(cur, 0):
                bands[(t, arg)] = b

    grants = []
    for t in sorted(tools):
        g = {"sess": "*", "max_tier": 2, "actions": [t]}
        ab = {arg: b for (tt, arg), b in sorted(bands.items()) if tt == t}
        if ab:
            g["arg_bands"] = ab
            # Inference sees which arguments were passed, never which are
            # required, and an inferred refusal is a judgement a person should
            # be allowed to make.
            g["bands_when_present"] = True
            g["confirmable"] = True
        grants.append(g)
    policy = {"version": 1,
              "_inferred": {"from_calls": len(learn),
                            "warning": "A floor, not a policy. It permits what "
                                       "was observed and is exactly as good as "
                                       "the traffic it saw. Review before "
                                       "enforcing."},
              "grants": grants}

    # REPLAY: a floor that refuses its own traffic is not a floor.
    probe = Issuer(Gate(budget=1))
    checkable = {k: v for k, v in policy.items() if k != "_inferred"}
    adopted = probe.adopt(checkable)
    if not adopted:
        print(f"  inferred policy rejected: {adopted.reason}")
        return 2
    from trustband.taint import Tainted
    from trustband.gate import Band
    broken = []
    for o in learn:
        args = {k: Tainted(None, Band(v)) for k, v in (o.get("bands") or {}).items()}
        ok, why = probe.evaluate(0 if False else _sess_any(), 2, o["tool"], args)
        if not ok:
            broken.append((o["tool"], why))
    if broken:
        print(f"  REFUSING TO WRITE: would refuse {len(broken)} call(s) it was "
              f"inferred from.")
        for t, why in broken[:3]:
            print(f"    {t}: {why[:100]}")
        return 3

    out = a.out or (home / "inferred.policy.json")
    out.write_text(json.dumps(policy, indent=2), encoding="utf-8")
    print(f"  {len(learn)} permitted call(s) -> {len(grants)} grant(s)")
    if skipped:
        print(f"  {skipped} call(s) that would have been refused were NOT "
              f"learned from; see shadow-report and decide on them.")
    print(f"  written to {out}")
    print(f"  review it, then point config.json at it and set mode to enforce.")
    return 0


def _sess_any() -> int:
    return 12345          # any session; grants use "*"


def _init(a) -> int:
    """Write config and a starter policy, then print what to register.

    SHADOW BY DEFAULT, and the printed registration says so. An install that
    starts refusing before anyone has seen what it would refuse is the fastest
    way to be uninstalled -- and it is the thing the competitor's
    enforce-from-the-first-call default gets wrong.
    """
    import os
    home = a.home or Path(os.environ.get("TRUSTBAND_HOME",
                                         Path.home() / ".trustband"))
    home.mkdir(parents=True, exist_ok=True)

    if a.pack == "list":
        return _packs()
    policy_path = home / "policy.json"
    if not policy_path.exists():
        pack = _load_pack(a.pack)
        pack.pop("_pack", None)
        policy_path.write_text(json.dumps(pack, indent=2), encoding="utf-8")

    cfg_path = home / "config.json"
    if not cfg_path.exists():
        cfg_path.write_text(json.dumps({
            "policy": "policy.json",
            "mode": a.mode,
            # The marker detector ships ON by default. It is safe to: a
            # detector can only LOWER trust, so worst case it over-refuses, and
            # in shadow (the install default) it only flags. Measured false
            # positives on 2,483 real coding arguments: 0 that were not this
            # very session building injection tooling. Replace "marker" with
            # your own detector, or remove it, in this file.
            "detectors": ["marker"],
            "provenance_max_entries": 4096}, indent=2), encoding="utf-8")

    hook = {"hooks": {
        "PreToolUse": [{"hooks": [{"type": "command",
                                   "command": "trustband-hook pre",
                                   "timeout": 10}]}],
        "PostToolUse": [{"hooks": [{"type": "command",
                                    "command": "trustband-hook post",
                                    "timeout": 10}]}]}}

    print(f"  pack     {a.pack}")
    print(f"  config   {cfg_path}")
    print(f"  policy   {policy_path}")
    print(f"  detector marker (on; a detector can only refuse more, never less)")
    print(f"  mode     {a.mode}"
          + ("   (refuses nothing; records what it would have)"
             if a.mode == "shadow" else "   (REFUSING)"))
    print()
    print("  Add to ~/.claude/settings.json:")
    print()
    for line in json.dumps(hook, indent=2).splitlines():
        print("    " + line)
    print()
    print("  Then: trustband shadow-report   to see what it would have refused.")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="trustband")
    sub = ap.add_subparsers(dest="cmd", required=True)

    t = sub.add_parser("test", help="run policy unit tests")
    t.add_argument("files", nargs="+", type=Path)

    e = sub.add_parser("explain", help="why a policy decides as it does")
    e.add_argument("--policy", required=True, type=Path)
    e.add_argument("--action", required=True)
    e.add_argument("--session", type=int, default=7)
    e.add_argument("--tier", type=int, default=2)
    e.add_argument("--args", default="{}",
                   help='{"recipient": ["UK12...", "tool"]}')
    e.add_argument("--context", default="{}")

    sub.add_parser("conformance", help="check this build against the interface")

    r = sub.add_parser("shadow-report",
                       help="what shadow mode would have refused")
    r.add_argument("--home", type=Path, default=None)

    f = sub.add_parser("infer",
                       help="write a policy permitting the traffic observed")
    f.add_argument("--home", type=Path, default=None)
    f.add_argument("--out", type=Path, default=None)
    f.add_argument("--include-refused", action="store_true",
                   help="widen the floor to permit calls that would have been "
                        "refused (you almost certainly do not want this)")

    i = sub.add_parser("init", help="set up config, a starter policy, and print "
                                    "the hook registration")
    i.add_argument("--home", type=Path, default=None)
    i.add_argument("--mode", default="shadow", choices=["shadow", "enforce"])
    i.add_argument("--pack", default="coding-agent",
                   help="starter policy pack (or 'list' to see them)")

    sub.add_parser("packs", help="list the bundled policy packs")

    at = sub.add_parser("alert-test",
                        help="send one synthetic event to a configured webhook")
    at.add_argument("cls", nargs="?", default="refusal")
    at.add_argument("--home", type=Path, default=None)

    ra = sub.add_parser("revoke-agent",
                        help="refuse every later call by a named agent")
    ra.add_argument("name")
    ra.add_argument("--home", type=Path, default=None)

    tr = sub.add_parser("trace",
                        help="what happened in a session, from the record")
    tr.add_argument("session", nargs="?", default=None)
    tr.add_argument("--home", type=Path, default=None)
    tr.add_argument("--also", type=Path, action="append", default=[],
                    help="another audit.jsonl to merge, e.g. a second "
                         "process of the same swarm; repeatable")
    tr.add_argument("--last", type=int, default=None,
                    help="show only the last N events")

    rp = sub.add_parser("report",
                        help="token accounting from the host's transcript")
    rp.add_argument("--transcript", type=Path, default=None,
                    help="path to the session .jsonl the host records usage in")
    rp.add_argument("--tokens", action="store_true", default=True)
    rp.add_argument("--home", type=Path, default=None)

    rpl = sub.add_parser("replay",
                         help="what a candidate policy would have done")
    rpl.add_argument("policy", type=Path, help="the candidate policy file")
    rpl.add_argument("--home", type=Path, default=None)

    ex = sub.add_parser("export",
                        help="ship the record to an OTLP/JSON collector")
    ex.add_argument("--endpoint", default=None,
                    help="OTLP/HTTP traces endpoint, e.g. "
                         "http://localhost:4318/v1/traces")
    ex.add_argument("--out", type=Path, default=None,
                    help="write the payload to a file instead of sending it")
    ex.add_argument("--service", default="trustband")
    ex.add_argument("--session", default=None,
                    help="export one session rather than the whole log")
    ex.add_argument("--home", type=Path, default=None)

    st = sub.add_parser("status",
                        help="tier, what is available, and what enforcement does")
    st.add_argument("--home", type=Path, default=None)

    bs = sub.add_parser("bundle", help="sign or verify a policy bundle")
    bs.add_argument("op", choices=["sign", "verify"])
    bs.add_argument("--policy", type=Path, help="policy to sign")
    bs.add_argument("--bundle", type=Path, help="bundle to verify or write")
    bs.add_argument("--version", type=int, default=1)
    bs.add_argument("--key-file", type=Path, required=True,
                    help="file holding the distribution key bytes")
    bs.add_argument("--min-version", type=int, default=None)

    a = ap.parse_args(argv)

    if a.cmd == "packs":
        return _packs()

    if a.cmd == "replay":
        from trustband.replay import render, InsufficientRecord
        home = _home(a)
        cfgp = home / "config.json"
        cfg = (json.loads(cfgp.read_text(encoding="utf-8"))
               if cfgp.exists() else {})
        rec = cfg.get("policy")
        recorded = (json.loads((home / rec).read_text(encoding="utf-8"))
                    if isinstance(rec, str) else rec)
        cand = json.loads(a.policy.read_text(encoding="utf-8"))
        try:
            for line in render(home / "audit.jsonl", cand, recorded):
                print(line)
        except InsufficientRecord as exc:
            print(f"  cannot replay: {exc}")
            return 1
        return 0

    if a.cmd == "export":
        return _export(a)

    if a.cmd == "report":
        return _report(a)

    if a.cmd == "trace":
        from trustband.trace import main as _trace
        return _trace(_home(a) / "audit.jsonl", a.session, a.last, a.also)

    if a.cmd == "alert-test":
        return _alert_test(a)

    if a.cmd == "revoke-agent":
        # Writes the name into the revocation file beside the audit log.
        # Every process sharing that directory refuses the agent on its next
        # call -- pair 6. No key is touched.
        from trustband.identity import AgentRegistry
        home = _home(a)
        AgentRegistry(None, revocations_path=home / "revoked_agents.json"
                      ).revoke(a.name)
        print(f"  agent {a.name!r} revoked; recorded in "
              f"{home / 'revoked_agents.json'}")
        return 0

    if a.cmd == "status":
        return _status(a)

    if a.cmd == "bundle":
        return _bundle(a)

    if a.cmd == "init":
        return _init(a)

    if a.cmd == "shadow-report":
        return _shadow_report(a)

    if a.cmd == "infer":
        return _infer(a)

    if a.cmd == "test":
        from trustband.policytest import run_files
        return run_files(a.files)

    if a.cmd == "conformance":
        from trustband.conformance import main as cmain
        return cmain()

    if a.cmd == "explain":
        from trustband.gate import Gate
        from trustband.issuance import Issuer
        from trustband.policytest import _args
        policy = json.loads(a.policy.read_text(encoding="utf-8"))
        policy.pop("_inferred", None)
        issuer = Issuer(Gate(budget=1))
        adopted = issuer.adopt(policy)
        if not adopted:
            print(f"policy rejected: {adopted.reason}")
            return 2
        ctx = {k: (set(v) if isinstance(v, list) else v)
               for k, v in json.loads(a.context).items()}
        ok, why = issuer.evaluate(a.session, a.tier, a.action,
                                  _args(json.loads(a.args)), ctx)
        print(f"  {'ALLOW' if ok else 'DENY'}  {a.action}")
        print(f"  because: {why}")
        if not ok and getattr(issuer, "confirmable_failures", []):
            print("  a human may answer this refusal")
        return 0 if ok else 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
