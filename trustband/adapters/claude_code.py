"""Claude Code hooks adapter — the first real one, and the one we dogfood.

`PreToolUse` and `PostToolUse` map onto the two hooks almost exactly, which is
why this is the first adapter rather than MCP: we run inside it, so we are the
first users and the first to be inconvenienced by our own refusals.

HOW IT RUNS
    Claude Code invokes a hook as a subprocess, passing a JSON event on stdin
    and reading a JSON response from stdout. So this is a CLI, configured once
    in settings and never imported by anything.

    Register it with two entries pointing at:

        trustband-hook pre
        trustband-hook post

THE PROBLEM THIS ADAPTER HAS TO SOLVE
    A hook is a SUBPROCESS. It starts, answers, and exits. Nothing survives
    between calls, and provenance that does not survive between calls is not
    provenance at all -- the whole point is that a value returned by one call
    is recognised when it comes back as an argument to the next.

    So the store is persisted to disk, keyed by Claude Code's session id. That
    is the session boundary the interface requires, and it is supplied by the
    host rather than invented here.

THE CONTRACT, VERIFIED 2026-08-31
    Checked against two official plugins on this machine rather than assumed:
    `hookify` and `security-guidance`.

      in   `tool_name`, `tool_input`, `hook_event_name`  (confirmed)
      out  {"hookSpecificOutput": {"hookEventName": ...,
                                   "permissionDecision": "allow|ask|deny"},
            "systemMessage": "..."}

    The MESSAGE goes in top-level `systemMessage`. An earlier version of this
    file put it in `permissionDecisionReason` inside hookSpecificOutput, which
    the official plugins do not use -- so every refusal would have been silent
    about why, and the reason is the part of this product worth having.

    `session_id` is NOT confirmed present. It is read if supplied and falls
    back to `cwd`, because provenance must be scoped to something stable and a
    working directory is a better guess than a shared bucket. Verify against a
    live event before relying on cross-session isolation.
"""
from __future__ import annotations

import json
import os
import pickle
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from trustband.gate import Band
from trustband.guard import Guard, GuardConfigError, ToolCall
from trustband.provenance import ProvenanceStore

#: Where config and per-session provenance live. Overridable for testing.
HOME = Path(os.environ.get("TRUSTBAND_HOME",
                           Path.home() / ".trustband"))
#: What this hook can see of the catalog. It cannot see `tools/list`, so it
#: pins the MCP server ENTRIES and the skill FILES, and says so.
CLAUDE_SETTINGS = Path(os.environ.get("TRUSTBAND_CLAUDE_SETTINGS",
                                      Path.home() / ".claude" / "settings.json"))
CLAUDE_SKILLS = Path(os.environ.get("TRUSTBAND_CLAUDE_SKILLS",
                                    Path.home() / ".claude" / "skills"))


def _event() -> Dict[str, Any]:
    """The hook event, or an empty one. Never raises: a hook that throws
    blocks the agent, and blocking on our own bug is worse than passing."""
    try:
        raw = sys.stdin.read()
        return json.loads(raw) if raw.strip() else {}
    except Exception:
        return {}


def _fields(ev: Dict[str, Any]) -> Tuple[str, str, Dict[str, Any], Any]:
    """Read defensively. Field names are assumed, so alternatives are tried."""
    # session_id is not confirmed present in the event. cwd is the fallback:
    # provenance must be scoped to something stable, and one project directory
    # is a far better boundary than one shared store for every conversation.
    session = str(ev.get("session_id") or ev.get("sessionId")
                  or ev.get("session") or ev.get("cwd") or "")
    tool = str(ev.get("tool_name") or ev.get("toolName") or ev.get("tool") or "")
    args = (ev.get("tool_input") or ev.get("toolInput")
            or ev.get("input") or {})
    result = ev.get("tool_response", ev.get("toolResponse", ev.get("result")))
    return session, tool, (args if isinstance(args, dict) else {}), result


def _store_path(session: str) -> Path:
    safe = "".join(c for c in session if c.isalnum() or c in "-_")[:64]
    return HOME / "provenance" / f"{safe or 'default'}.pkl"


def _load_store(session: str, max_entries: int) -> ProvenanceStore:
    p = _store_path(session)
    if p.exists():
        try:
            st = pickle.loads(p.read_bytes())
            if isinstance(st, ProvenanceStore):
                return st
        except Exception:
            # A corrupt or stale store is discarded rather than trusted. The
            # cost is provenance for this session starting over, which reads
            # values as model-authored -- the safe-to-be-wrong direction is
            # over-refusal, so this is the one that is not.
            pass
    return ProvenanceStore(max_entries=max_entries)


def _save_store(session: str, store: ProvenanceStore) -> None:
    p = _store_path(session)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_bytes(pickle.dumps(store))
    tmp.replace(p)                       # atomic: a torn store is a lost store


def _agent(ev: Dict[str, Any], g: Guard, session: str):
    """A named identity for this call. Re-minted every invocation rather than
    persisted: this hook is a fresh process per call, and the tag is
    deterministic under the shared key file, so the same (name, role,
    session) is the same tag each time -- pair 7. Never raises: an identity
    that cannot be minted is no identity, and the call carries none."""
    try:
        name = str(ev.get("agent_name") or ev.get("agentName") or "claude-code")
        role = str(ev.get("subagent_type") or ev.get("agent_type")
                   or ev.get("agentType") or "main")
        return g.mint_agent(name, role, session)
    except Exception:
        return None


def _observe(g: Guard, session: str) -> None:
    """Pin what the hook can see: server entries and skill files.

    Env VALUES are never pinned -- they are secrets -- only the key names,
    so a rotated token is not drift and an added variable is. A skill is
    pinned by the hash of its file. Never raises: an unreadable settings
    file is not the agent's problem.
    """
    import hashlib
    from trustband.lock import observe as _obs
    items = []
    try:
        if CLAUDE_SETTINGS.exists():
            data = json.loads(CLAUDE_SETTINGS.read_text(encoding="utf-8"))
            for name, spec in (data.get("mcpServers") or {}).items():
                if not isinstance(spec, dict):
                    continue
                items.append(_obs("server", str(name), "", {
                    "command": spec.get("command"), "args": spec.get("args"),
                    "url": spec.get("url"),
                    "env_keys": sorted((spec.get("env") or {}).keys())}))
    except Exception:
        pass
    try:
        if CLAUDE_SKILLS.is_dir():
            for d in sorted(CLAUDE_SKILLS.iterdir()):
                f = d / "SKILL.md"
                if f.is_file():
                    text = f.read_text(encoding="utf-8", errors="replace")
                    items.append(_obs("skill", d.name, text[:600],
                                      {"sha256": hashlib.sha256(text.encode()).hexdigest()}))
    except Exception:
        pass
    if items:
        try:
            g.observe_catalog(session, "server", items, full=False)
        except Exception:
            pass


def _guard(session: str) -> Optional[Guard]:
    cfg = HOME / "config.json"
    if not cfg.exists():
        return None
    try:
        g = Guard.from_file(cfg)
    except GuardConfigError:
        raise
    g._stores[session] = _load_store(session, g._max_entries)
    _observe(g, session)
    return g


def _record_shadow(entries: list) -> None:
    """Append shadow observations so a LATER process can infer from them.

    A hook is a subprocess: `Guard.shadow_log` dies with it. Without this the
    whole install path -- observe, infer, review, enforce -- has no observations
    to infer from, and shadow mode is a log line rather than a workflow.
    """
    if not entries:
        return
    f = HOME / "shadow.jsonl"
    f.parent.mkdir(parents=True, exist_ok=True)
    with f.open("a", encoding="utf-8") as fh:
        for e in entries:
            fh.write(json.dumps(e) + "\n")


def _respond(event_name: str, decision: str, reason: str) -> None:
    """The verified shape. `systemMessage` is what actually surfaces the
    reason; hookSpecificOutput carries the decision."""
    print(json.dumps({
        "hookSpecificOutput": {"hookEventName": event_name,
                               "permissionDecision": decision},
        "systemMessage": reason}))


def pre() -> int:
    ev = _event()
    session, tool, args, _ = _fields(ev)
    if not session or not tool:
        _respond("PreToolUse", "allow", "trustband: no session or tool in event")
        return 0
    try:
        g = _guard(session)
    except GuardConfigError as e:
        # A broken policy stops the agent. That is the interface's failure
        # policy: a configuration error is not something to pass calls through.
        _respond("PreToolUse", "deny", f"trustband config error: {e}")
        return 0
    if g is None:
        _respond("PreToolUse", "allow", "trustband: not configured")
        return 0

    d = g.before_tool_call(ToolCall(session=session, tool=tool, args=args,
                                    agent=_agent(ev, g, session)))
    if g.mode == "shadow":
        _record_shadow(g.shadow_log)
    if d.allowed:
        _respond("PreToolUse", "allow", d.reason)
    elif d.confirmable:
        # "ask" rather than "deny": the policy said a human may answer this,
        # and Claude Code already knows how to put a decision to the user.
        _respond("PreToolUse", "ask", d.reason)
    else:
        _respond("PreToolUse", "deny", d.reason)
    return 0


def post() -> int:
    ev = _event()
    session, tool, args, result = _fields(ev)
    if not session or not tool:
        return 0
    try:
        g = _guard(session)
    except GuardConfigError:
        return 0
    if g is None:
        return 0
    call = ToolCall(session=session, tool=tool, args=args,
                    agent=_agent(ev, g, session))
    g.after_tool_result(call, result, Band.TOOL)
    _save_store(session, g._stores[session])
    return 0


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    # A hook must never emit a traceback. The host reads stdout for a decision;
    # a crash gives it nothing, which is worse than any answer we could give.
    try:
        if argv and argv[0] == "pre":
            return pre()
        if argv and argv[0] == "post":
            return post()
    except Exception as e:
        if argv and argv[0] == "pre":
            _respond("PreToolUse", "deny", f"trustband failed: {e}")
        return 0
    print("usage: trustband-hook {pre|post}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
