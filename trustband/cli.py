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


def _packs() -> int:
    d = _packs_dir()
    for f in sorted(d.glob("*.json")):
        meta = json.loads(f.read_text(encoding="utf-8")).get("_pack", {})
        print(f"  {meta.get('name', f.stem)}")
        print(f"    {meta.get('description', '')}")
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
