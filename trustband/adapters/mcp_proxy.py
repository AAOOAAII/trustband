"""An MCP stdio proxy that gates tool calls and bands their results.

WHAT IT IS
    A transparent proxy on the MCP stdio wire. It launches the real MCP server
    as a subprocess and sits between it and the client:

        client  <->  trustband proxy  <->  real MCP server

    Every message is forwarded unchanged EXCEPT a `tools/call` request, which
    is gated before it reaches the server, and its result, whose text is banded
    on the way back. Nothing else in the protocol is touched.

WHY A PROXY AND NOT A LIBRARY CALL
    MCP servers are separate processes speaking JSON-RPC over stdio. A host
    that connects to one cannot import a Python guard into it. A proxy is the
    one interception point that needs no cooperation from either side and no
    change to the server -- the same condition the Claude Code adapter meets
    with hooks.

    It is stdlib only. No `mcp` package, so it runs wherever Python does, and
    the wire format it depends on is two field names confirmed against the SDK:
    a request's `params.name` / `params.arguments`, and a result's `content`.

THE SESSION BOUNDARY
    One proxy process is one client connection is one session. Provenance is
    scoped to it and dies with it. That is the correct boundary: two clients
    get two proxy processes and cannot taint each other, which is exactly what
    the interface requires and what a shared in-process store would violate.

    Persistence across a restart is deliberately NOT done here. An MCP session
    is a live connection; when it ends the provenance is meant to end with it.

THE TOOL-DESCRIPTION SURFACE, NAMED NOT CLOSED
    A malicious MCP server can put an injection in a tool's DESCRIPTION, which
    the model reads. This proxy bands tool RESULTS, not descriptions. Banding
    descriptions is a real and separate layer (the MCP-Scan surface) and is
    marked as the next build, not silently skipped.
"""
from __future__ import annotations

import json
import subprocess
import sys
import threading
from typing import Any, Dict, List, Optional

from trustband.gate import Band
from trustband.guard import Guard, GuardConfigError, ToolCall


def _read_messages(stream, on_message) -> None:
    """Read newline-delimited JSON-RPC messages until the stream closes.

    MCP stdio framing is one JSON object per line. A line that does not parse
    is forwarded verbatim rather than dropped -- the proxy is not the place to
    decide a peer's framing is wrong.
    """
    for raw in stream:
        line = raw.rstrip(b"\n")
        if not line.strip():
            continue
        try:
            msg = json.loads(line)
        except Exception:
            on_message(None, line)
            continue
        on_message(msg, line)


class McpProxy:
    """Gate a single MCP stdio session."""

    def __init__(self, guard: Guard, server_cmd: List[str],
                 session: str = "mcp", strict_descriptions: bool = False
                 ) -> None:
        self.guard = guard
        self.session = session
        #: refuse to proxy a server whose tool DESCRIPTIONS trip the detectors.
        #: The one place description injection can be PREVENTED: strip the
        #: poisoned response before the model ever reads it.
        self.strict_descriptions = strict_descriptions
        self.server = subprocess.Popen(
            server_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=sys.stderr.buffer)
        #: request id -> (tool, args) for a tools/call awaiting its result, so
        #: the result can be banded against the call that produced it.
        self._inflight: Dict[Any, ToolCall] = {}
        self._lock = threading.Lock()

    # -- client -> server: gate a tools/call before it is sent --------------
    def _from_client(self, msg: Optional[Dict[str, Any]], raw: bytes) -> None:
        if msg is None or msg.get("method") != "tools/call":
            self._to_server(raw)
            return
        params = msg.get("params") or {}
        tool = params.get("name", "")
        args = params.get("arguments") or {}
        call = ToolCall(session=self.session, tool=tool,
                        args=args if isinstance(args, dict) else {})
        d = self.guard.before_tool_call(call)
        if d.allowed:
            with self._lock:
                self._inflight[msg.get("id")] = call
            self._to_server(raw)
        else:
            # Refuse without ever reaching the server. The client gets a
            # JSON-RPC result carrying isError, which is how MCP surfaces a
            # tool failure -- the agent sees it and can react, exactly as a
            # real denial would read.
            self._to_client(json.dumps({
                "jsonrpc": "2.0", "id": msg.get("id"),
                "result": {"isError": True, "content": [
                    {"type": "text",
                     "text": f"trustband refused: {d.reason}"}]}}).encode())

    # -- tool descriptions: detect the injected-instruction surface ---------
    def _scan_descriptions(self, result: Dict[str, Any]) -> Optional[bytes]:
        """Run detectors over each tool description in a tools/list result.

        A description is untrusted text the model reads as instructions, and a
        malicious server can inject one. This DETECTS -- warns the operator and
        records it -- and in strict mode PREVENTS, by replacing the whole
        response with an error so the model never reads the poisoned text.

        Descriptions are not banded into the store: a description is not a value
        that flows into an argument, and storing it would false-match on every
        later call.
        """
        from trustband.detector import run_detectors
        from trustband.gate import Band
        if not self.guard.detectors:
            return None
        flagged = []
        for tool in (result.get("tools") or []):
            desc = tool.get("description", "")
            if not isinstance(desc, str):
                continue
            # a detector fires by LOWERING the band below SESSION; on a
            # description that is the signal it looks injected.
            if run_detectors(self.guard.detectors, desc, Band.SESSION) \
                    is not Band.SESSION:
                flagged.append(tool.get("name", "?"))
        if not flagged:
            return None
        note = (f"trustband: tool description(s) look injected: "
                f"{', '.join(flagged)}")
        sys.stderr.write(note + "\n")
        sys.stderr.flush()
        if self.strict_descriptions:
            # PREVENTION, the one place it is possible: the client never sees
            # the poisoned descriptions.
            return json.dumps({
                "jsonrpc": "2.0",
                "error": {"code": -32001, "message": note}}).encode()
        return None

    # -- server -> client: band a tool result on the way back ---------------
    def _from_server(self, msg: Optional[Dict[str, Any]], raw: bytes) -> None:
        if msg is None or "result" not in msg:
            self._to_client(raw)
            return
        # a tools/list result carries descriptions, not a tool's output
        result = msg.get("result") or {}
        if isinstance(result, dict) and "tools" in result:
            replacement = self._scan_descriptions(result)
            self._to_client(replacement if replacement is not None else raw)
            return
        with self._lock:
            call = self._inflight.pop(msg.get("id"), None)
        if call is not None:
            # Band every text fragment the result carries. The content list is
            # banded elementwise for the same reason the harness does it: the
            # model reads content[0].text, and a top-level band would be gone
            # before it reached an argument.
            self.guard.after_tool_result(call, msg.get("result"), Band.TOOL)
        self._to_client(raw)

    # -- wire ---------------------------------------------------------------
    def _to_server(self, raw: bytes) -> None:
        self.server.stdin.write(raw + b"\n")
        self.server.stdin.flush()

    def _to_client(self, raw: bytes) -> None:
        sys.stdout.buffer.write(raw + b"\n")
        sys.stdout.buffer.flush()

    def run(self) -> int:
        """Pump both directions until either side closes."""
        t = threading.Thread(
            target=_read_messages,
            args=(self.server.stdout, self._from_server), daemon=True)
        t.start()
        _read_messages(sys.stdin.buffer, self._from_client)
        self.server.terminate()
        try:
            return self.server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.server.kill()
            return 1


def main(argv=None) -> int:
    """`trustband-mcp -- <server command...>`

    Config and policy come from the same place the other adapters read, so a
    user configures the gate once and points every host at it.
    """
    import os
    from pathlib import Path
    argv = sys.argv[1:] if argv is None else argv
    strict = "--strict-descriptions" in argv
    argv = [a for a in argv if a != "--strict-descriptions"]
    if "--" in argv:
        argv = argv[argv.index("--") + 1:]
    if not argv:
        print("usage: trustband-mcp -- <mcp server command>", file=sys.stderr)
        return 2
    home = Path(os.environ.get("TRUSTBAND_HOME",
                               Path.home() / ".trustband"))
    cfg = home / "config.json"
    if not cfg.exists():
        print(f"trustband: no config at {cfg}; run `trustband init`",
              file=sys.stderr)
        # Fail OPEN to a bare passthrough here: with no config the user has not
        # asked for a gate, and a proxy that refuses to start would break every
        # MCP server behind it. This is the one place open is right, because
        # nothing was configured to protect.
        proxy = subprocess.run(argv)
        return proxy.returncode
    try:
        guard = Guard.from_file(cfg)
    except GuardConfigError as e:
        print(f"trustband: {e}", file=sys.stderr)
        return 2
    return McpProxy(guard, argv, strict_descriptions=strict).run()


if __name__ == "__main__":
    raise SystemExit(main())
