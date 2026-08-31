"""Bring-your-own detector adapters — plug an external classifier in.

Each is a thin wrapper that speaks to a real detector (Prompt Guard, Lakera,
LlamaFirewall, your own service) and returns a BAND FLOOR. The safety property
is unchanged: whatever the external service says, the result can only lower
trust, and a failure to reach it is a no-op -- so an outage of your detector
never opens a bypass, it just stops tightening.

Point `detectors` in config at one of these by dotted name, e.g.
    "detectors": ["trustband.detectors_byo:CommandDetector"]
after setting the command it should run.
"""
from __future__ import annotations

import json
import subprocess
from typing import Optional

from trustband.gate import Band


class CommandDetector:
    """Run an external program that reads text on stdin and prints a verdict.

    The program prints `INJECTION` (case-insensitive) to flag, anything else to
    pass. A non-zero exit, a timeout, or an unreadable answer is treated as
    "no opinion" -- a no-op -- because a detector that cannot be reached must
    not become a refusal of every call.

    This is the shape a real Prompt Guard / Lakera CLI or a curl to an HTTP
    endpoint drops into. Set `cmd` to your detector's invocation.
    """

    def __init__(self, cmd=None, floor: Band = Band.TOOL, timeout: float = 2.0):
        self.cmd = cmd or ["cat"]           # replace with your detector
        self.floor = floor
        self.timeout = timeout

    def assess(self, text: str, current: Band) -> Optional[Band]:
        try:
            p = subprocess.run(self.cmd, input=text, capture_output=True,
                               text=True, timeout=self.timeout)
        except Exception:
            return None                     # unreachable detector is a no-op
        if p.returncode == 0 and "injection" in (p.stdout or "").lower():
            return self.floor
        return None


class HttpDetector:
    """POST the text to an HTTP endpoint that returns {"injection": bool}.

    Kept dependency-free with urllib. A network failure is a no-op. Set `url`.
    """

    def __init__(self, url: str = "", floor: Band = Band.TOOL,
                 timeout: float = 2.0):
        self.url = url
        self.floor = floor
        self.timeout = timeout

    def assess(self, text: str, current: Band) -> Optional[Band]:
        if not self.url:
            return None
        import urllib.request
        try:
            req = urllib.request.Request(
                self.url, data=json.dumps({"text": text}).encode(),
                headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                verdict = json.loads(r.read())
        except Exception:
            return None                     # unreachable endpoint is a no-op
        return self.floor if verdict.get("injection") else None
