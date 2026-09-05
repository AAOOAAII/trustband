"""Benign drift: how often a legitimate MCP server release moves a lockfile pin.

Gates: docs/BENIGN_DRIFT_GATES.md. Every catalogue comes from a RUNNING
server (npx <pkg>@<version>, initialize, tools/list), never from source, and
every digest is the package's own `trustband.lock.observe` (P-BD.5).

    python measure/benign_drift.py collect    # resumable; caches per version
    python measure/benign_drift.py stability  # newest version x3 per server
    python measure/benign_drift.py report     # classification, rates, cost

Results: results/benign_drift/<package>.json and summary.json / summary.md.
"""
from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
import time
import urllib.request
from collections import Counter
from pathlib import Path
from statistics import median
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from trustband.lock import observe  # noqa: E402  (P-BD.5)

OUT = Path(__file__).resolve().parents[1] / "results" / "benign_drift"
MAX_VERSIONS = 30
START_TIMEOUT = 150

#: package -> startup args. Everything else is the default invocation.
SERVERS: Dict[str, List[str]] = {
    "@modelcontextprotocol/server-filesystem": ["/private/tmp"],
    "@modelcontextprotocol/server-memory": [],
    "@modelcontextprotocol/server-everything": [],
    "@modelcontextprotocol/server-sequential-thinking": [],
    "@playwright/mcp": [],
    "@upstash/context7-mcp": [],
    "chrome-devtools-mcp": [],
    "@supabase/mcp-server-supabase": [],
    "@notionhq/notion-mcp-server": [],
}


def versions_of(pkg: str) -> List[Tuple[str, str]]:
    """(version, published date) for non-prerelease versions, oldest first,
    newest MAX_VERSIONS only."""
    d = json.load(urllib.request.urlopen(f"https://registry.npmjs.org/{pkg.replace('/', '%2f')}", timeout=30))
    t = d.get("time", {})
    vs = [(v, t.get(v, "")[:10]) for v in d.get("versions", {}) if "-" not in v and v in t]
    vs.sort(key=lambda x: x[1])
    return vs[-MAX_VERSIONS:]


def catalog(pkg: str, version: str, args: List[str]) -> Dict[str, Any]:
    """Start one version and ask it for its tools. Returns {tools|error, seconds}."""
    t0 = time.time()
    env = {**os.environ, "NPM_CONFIG_LOGLEVEL": "error", "NO_COLOR": "1"}
    try:
        p = subprocess.Popen(["npx", "-y", f"{pkg}@{version}", *args], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd="/private/tmp")
    except OSError as e:
        return {"error": f"spawn: {e}", "seconds": 0}

    def send(o: Dict[str, Any]) -> None:
        p.stdin.write((json.dumps(o) + "\n").encode()); p.stdin.flush()

    tools: Optional[List[Dict[str, Any]]] = None
    err = ""
    try:
        send({"jsonrpc": "2.0", "id": 1, "method": "initialize",
              "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                         "clientInfo": {"name": "trustband-measure", "version": "0"}}})
        deadline = time.time() + START_TIMEOUT
        import select
        while time.time() < deadline:
            r, _, _ = select.select([p.stdout], [], [], 1.0)
            if p.poll() is not None and not r:
                err = "exited before answering"
                break
            if not r:
                continue
            line = p.stdout.readline()
            if not line:
                err = "stdout closed"
                break
            try:
                msg = json.loads(line.decode("utf-8", "replace"))
            except ValueError:
                continue
            if msg.get("id") == 1:
                send({"jsonrpc": "2.0", "method": "notifications/initialized"})
                send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
            elif msg.get("id") == 2:
                if "result" in msg:
                    tools = msg["result"].get("tools", [])
                else:
                    err = f"tools/list error: {msg.get('error')}"
                break
        else:
            err = "timed out"
    finally:
        try:
            p.kill()
        except Exception:
            pass
        try:
            stderr = p.stderr.read().decode("utf-8", "replace")[-300:]
        except Exception:
            stderr = ""
    if tools is None:
        return {"error": err or "no answer", "stderr": stderr, "seconds": round(time.time() - t0, 1)}
    items = [observe("tool", t.get("name", "?"), t.get("description", ""), t.get("inputSchema"))
             for t in tools]
    return {"tools": items, "seconds": round(time.time() - t0, 1)}


def collect() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for pkg, args in SERVERS.items():
        f = OUT / (pkg.replace("/", "__") + ".json")
        data = json.loads(f.read_text()) if f.exists() else {"package": pkg, "args": args, "versions": {}}
        try:
            vs = versions_of(pkg)
        except Exception as e:
            print(f"  {pkg}: registry error {e}", flush=True)
            continue
        for v, date in vs:
            if v in data["versions"] and "tools" in data["versions"][v]:
                continue
            res = catalog(pkg, v, args)
            res["date"] = date
            data["versions"][v] = res
            f.write_text(json.dumps(data, indent=1))
            status = f"{len(res['tools'])} tools" if "tools" in res else f"FAILED {res['error']}"
            print(f"  {pkg}@{v} ({date}): {status} in {res['seconds']}s", flush=True)


def stability(runs: int = 3) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    out = {}
    for pkg, args in SERVERS.items():
        f = OUT / (pkg.replace("/", "__") + ".json")
        if not f.exists():
            continue
        data = json.loads(f.read_text())
        good = [v for v, r in data["versions"].items() if "tools" in r]
        if not good:
            continue
        newest = sorted(good, key=lambda v: data["versions"][v]["date"])[-1]
        digests = []
        for i in range(runs):
            res = catalog(pkg, newest, args)
            digests.append({t["name"]: t["digest"] for t in res.get("tools", [])} if "tools" in res else None)
        ok = all(d is not None and d == digests[0] for d in digests)
        diff = []
        if not ok:
            names = set().union(*(d.keys() for d in digests if d))
            diff = sorted(n for n in names if len({(d or {}).get(n) for d in digests}) > 1)
        out[pkg] = {"version": newest, "runs": runs, "stable": ok, "differing_tools": diff}
        print(f"  {pkg}@{newest}: {'stable' if ok else 'UNSTABLE ' + str(diff)} over {runs} starts", flush=True)
    (OUT / "stability.json").write_text(json.dumps(out, indent=1))


def classify(prev: List[Dict[str, Any]], cur: List[Dict[str, Any]]) -> Dict[str, Any]:
    a = {t["name"]: t for t in prev}
    b = {t["name"]: t for t in cur}
    added = sorted(set(b) - set(a)); removed = sorted(set(a) - set(b))
    desc_only, schema = [], []
    for n in set(a) & set(b):
        if a[n]["digest"] == b[n]["digest"]:
            continue
        sa, sb = a[n]["summary"], b[n]["summary"]
        if sa["schema"] == sb["schema"] and sa["version"] == sb["version"]:
            desc_only.append(n)
        else:
            schema.append(n)
    changed = len(desc_only) + len(schema) + len(added) + len(removed)
    if not changed:
        kind = "none"
    elif desc_only and not schema and not added and not removed:
        kind = "description-only"
    elif schema and not added and not removed:
        kind = "schema"
    else:
        kind = "tools-added-or-removed"
    return {"kind": kind, "description_only": desc_only, "schema": schema, "added": added,
            "removed": removed, "refused_tools": len(desc_only) + len(schema) + len(removed)}


def report() -> None:
    per: Dict[str, Any] = {}
    pooled = Counter(); pooled_refused: List[int] = []; failures = 0; total_versions = 0
    months_pooled = 0.0
    for f in sorted(OUT.glob("*.json")):
        if f.name in ("stability.json", "summary.json"):
            continue
        data = json.loads(f.read_text())
        vs = sorted(data["versions"].items(), key=lambda kv: (kv[1]["date"], kv[0]))
        total_versions += len(vs)
        good = [(v, r) for v, r in vs if "tools" in r]
        failures += len(vs) - len(good)
        rel = []
        for (v0, r0), (v1, r1) in zip(good, good[1:]):
            c = classify(r0["tools"], r1["tools"])
            c.update({"from": v0, "to": v1, "date": r1["date"]})
            rel.append(c)
        kinds = Counter(r["kind"] for r in rel)
        drifting = [r for r in rel if r["kind"] != "none"]
        span_days = 0
        if len(good) >= 2:
            d0, d1 = good[0][1]["date"], good[-1][1]["date"]
            span_days = (time.mktime(time.strptime(d1, "%Y-%m-%d")) - time.mktime(time.strptime(d0, "%Y-%m-%d"))) / 86400
        months = max(span_days / 30.4, 0.1)
        months_pooled += months
        per[data["package"]] = {
            "versions": len(vs), "started": len(good), "failed_to_start": len(vs) - len(good),
            "first": good[0][1]["date"] if good else None, "last": good[-1][1]["date"] if good else None,
            "releases_compared": len(rel), "kinds": dict(kinds),
            "drift_rate_per_release": round(len(drifting) / len(rel), 3) if rel else None,
            "drifts_per_month": round(len(drifting) / months, 2) if rel else None,
            "refused_tools_median": median([r["refused_tools"] for r in drifting]) if drifting else 0,
            "refused_tools_max": max([r["refused_tools"] for r in drifting]) if drifting else 0,
            "releases": rel,
        }
        pooled.update(kinds); pooled_refused += [r["refused_tools"] for r in drifting]
    n_rel = sum(pooled.values()); n_drift = n_rel - pooled.get("none", 0)
    stab = json.loads((OUT / "stability.json").read_text()) if (OUT / "stability.json").exists() else {}
    summary = {
        "run": time.strftime("%Y-%m-%d"), "machine": f"{platform.system()} {platform.machine()}, node {_node()}",
        "servers": len(per), "versions": total_versions, "failed_to_start": failures,
        "releases_compared": n_rel, "pooled_kinds": dict(pooled),
        "pooled_drift_rate_per_release": round(n_drift / n_rel, 3) if n_rel else None,
        "pooled_drifts_per_month": round(n_drift / months_pooled, 2) if months_pooled else None,
        "refused_tools_median": median(pooled_refused) if pooled_refused else 0,
        "refused_tools_max": max(pooled_refused) if pooled_refused else 0,
        "stability": stab, "per_server": per,
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=1))
    lines = [f"# benign drift — {summary['run']} — {summary['machine']}", "",
             f"servers {summary['servers']} · versions {total_versions} · failed to start {failures} · "
             f"releases compared {n_rel}", "",
             "| server | versions | compared | none | description-only | schema | added/removed | drift/release | drifts/month | refused tools (median/max) | stable ×3 |",
             "|---|---|---|---|---|---|---|---|---|---|---|"]
    for pkg, p in per.items():
        k = p["kinds"]; s = stab.get(pkg, {})
        lines.append(f"| {pkg} | {p['started']}/{p['versions']} | {p['releases_compared']} | {k.get('none', 0)} | "
                     f"{k.get('description-only', 0)} | {k.get('schema', 0)} | {k.get('tools-added-or-removed', 0)} | "
                     f"{p['drift_rate_per_release']} | {p['drifts_per_month']} | {p['refused_tools_median']}/{p['refused_tools_max']} | "
                     f"{'yes' if s.get('stable') else ('NO ' + ','.join(s.get('differing_tools', [])) if s else '?')} |")
    lines += ["", f"pooled: drift on {n_drift}/{n_rel} releases = {summary['pooled_drift_rate_per_release']}; "
                  f"{summary['pooled_drifts_per_month']} drifts per server-month; refused tools per drifting release "
                  f"median {summary['refused_tools_median']} max {summary['refused_tools_max']}",
              f"kinds pooled: {dict(pooled)}"]
    (OUT / "summary.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


def _node() -> str:
    try:
        return subprocess.run(["node", "-v"], capture_output=True, text=True).stdout.strip()
    except Exception:
        return "?"


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "report"
    {"collect": collect, "stability": stability, "report": report}[cmd]()
