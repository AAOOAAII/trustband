"""One listener per band. The band comes from the accepting socket.

WHAT THIS CLOSES
================
A2-residual was: *the `PhysicalIngress` value handed to `demux_stamp()` is the
channel the bytes actually arrived on* — an unverified claim by the caller, with
no transport property consulted anywhere. Any caller could name their own band.

Here the band is a property of **which listener accepted the connection**. A
caller cannot name a band; they can only connect somewhere. There is no header,
no query parameter, and no request field that participates.

WHAT IT DOES NOT CLOSE, STATED RATHER THAN ENGINEERED AROUND
============================================================
**Anything that can reach the governance listener can present as governance.**
Restricting who can reach it is a NETWORK property — firewall rules, bind
address, socket file permissions — and this code neither performs nor proves it.
Unix domain sockets are used partly because filesystem permissions are the
natural place for that restriction to live, but setting them is the operator's
job and no assertion here covers it.

THE STRUCTURAL FORM
===================
`band_from_accepting_listener(listener)` takes the LISTENER and nothing else. A
band cannot be passed to it, because it has no such parameter — the same
device as `_band_for_channel(channel)`, and `structural_selftest()` asserts
both signatures so a later edit adding one fails a test rather than passing
review.
"""
from __future__ import annotations

import os
import socket
import socketserver
import struct
import threading
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional

from trustband.gate import Band, Channel, _band_for_channel


class TransportMisconfigured(Exception):
    """Raised at STARTUP. A band/listener mismatch must be loud at boot."""


class BoundListener:
    """A listener bound to exactly one channel at construction.

    The channel is set once and is read-only. The BAND is not stored — it is
    derived on demand by the single band derivation in `trustband.gate`, so
    there is no second copy that could drift.
    """

    __slots__ = ("_channel", "_path", "_server", "_allowed_uids")

    def __init__(self, channel: Channel, path: str,
                 allowed_uids: Optional[frozenset] = None) -> None:
        # allowed_uids narrows WHO may connect. None keeps the previous
        # behaviour (any peer), which is what the battery constructs. See the
        # peer-identity section below for what this does and does not buy.
        if not isinstance(channel, Channel):
            raise TransportMisconfigured(
                f"a listener must be bound to a Channel, got {type(channel).__name__}")
        object.__setattr__(self, "_channel", channel)
        object.__setattr__(self, "_path", path)
        object.__setattr__(self, "_server", None)
        object.__setattr__(self, "_allowed_uids",
                           None if allowed_uids is None else frozenset(allowed_uids))

    def __setattr__(self, *_a: Any) -> None:
        raise TransportMisconfigured(
            "a listener's channel is fixed at bind time and cannot be reassigned")

    @property
    def allowed_uids(self) -> Optional[frozenset]:
        """Fixed at bind time like the channel. None means any peer."""
        return self._allowed_uids

    @property
    def channel(self) -> Channel:
        return self._channel

    @property
    def path(self) -> str:
        return self._path

    @property
    def band(self) -> Band:
        """Derived, never stored. Single source: gate._band_for_channel."""
        return _band_for_channel(self._channel)

    def __repr__(self) -> str:
        return f"BoundListener(channel={self._channel.value}, band={self.band.value})"


def band_from_accepting_listener(listener: BoundListener) -> Band:
    """THE INGRESS BAND DERIVATION. One parameter, and it is the listener.

    There is no band parameter and no request parameter. Nothing about the
    bytes that arrived can influence the answer, because nothing about them is
    in scope. `structural_selftest()` asserts this signature.
    """
    if not isinstance(listener, BoundListener):
        raise TransportMisconfigured(
            f"band must come from a BoundListener, got {type(listener).__name__}")
    return listener.band


# ---------------------------------------------------------------------------
# PEER IDENTITY — narrowing route 8, not closing it
#
# Route 8 of the battery records an honest failure: reaching the governance
# listener IS presenting as governance, because the band is the socket. Reach
# is a NETWORK property -- firewall, bind address, namespace -- and this code
# neither performs nor proves it. That remains true.
#
# What a process CAN check is WHO connected. On a unix socket the kernel will
# tell you the peer's uid, and the peer cannot lie about it: it is not in the
# bytes. So the claim narrows from
#     "anything that can reach the governance listener presents as governance"
# to
#     "anything that can reach it AND runs as an allowed uid".
#
# That is a narrowing and not a closure, and the difference matters:
#   * root can setuid to an allowed uid. This check does not stop root.
#   * it says nothing about reach, which is still the operator's job.
#   * where the platform cannot report a peer uid, `peer_uid` returns None and
#     `check_peer` REFUSES rather than allowing -- an unmeasurable peer is not
#     an authorised one.
# ---------------------------------------------------------------------------

_SOL_LOCAL = 0
_LOCAL_PEERCRED = 0x001


def peer_uid(conn: Any) -> Optional[int]:
    """The connecting process's uid, from the kernel, or None if unavailable.

    MEASURED per platform, not assumed: Linux SO_PEERCRED (struct ucred),
    macOS/BSD LOCAL_PEERCRED (struct xucred). Nothing here reads the payload,
    because the peer's own claim about its identity is exactly what must not
    be trusted.
    """
    try:
        if hasattr(socket, "SO_PEERCRED"):                       # Linux
            raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                  struct.calcsize("3i"))
            _pid, uid, _gid = struct.unpack("3i", raw)
            return int(uid)
        raw = conn.getsockopt(_SOL_LOCAL, _LOCAL_PEERCRED, 64)   # macOS/BSD
        _version, uid = struct.unpack_from("ii", raw, 0)
        return int(uid)
    except Exception:
        return None


class PeerRefused(Exception):
    """The connecting process is not permitted on this listener."""


def check_peer(listener: "BoundListener", conn: Any) -> int:
    """Return the peer uid, or raise. Refuses when the uid is unavailable.

    A listener with no `allowed_uids` accepts any peer, which is the previous
    behaviour and is what the battery's routes construct.
    """
    allowed = getattr(listener, "allowed_uids", None)
    uid = peer_uid(conn)
    if allowed is None:
        return uid if uid is not None else -1
    if uid is None:
        raise PeerRefused(
            f"peer uid unavailable on this platform for listener "
            f"{listener.channel.name}; an unmeasurable peer is not an "
            f"authorised one, so the connection is refused")
    if uid not in allowed:
        raise PeerRefused(
            f"peer uid {uid} is not permitted on the "
            f"{listener.channel.name} listener (allowed: {sorted(allowed)}). "
            f"This narrows reach; it does not replace it — root can still "
            f"setuid, and restricting who can reach the socket at all remains "
            f"a network property this code does not perform.")
    return uid


class Ingress:
    """Owns the listener/band bindings, and refuses to start if they are wrong.

    STARTUP CHECKS, loud at boot rather than silent at runtime:
      * every listener is bound to a Channel that has a band
      * no two listeners share a band
    """

    def __init__(self, bindings: Mapping[Channel, str]) -> None:
        self._listeners: List[BoundListener] = []
        seen_bands: Dict[Band, Channel] = {}
        for channel, path in bindings.items():
            listener = BoundListener(channel, path)
            band = listener.band                       # raises if the channel has no band
            if band in seen_bands:
                raise TransportMisconfigured(
                    f"two listeners share band {band.value!r}: "
                    f"{seen_bands[band].value!r} and {channel.value!r}. A band "
                    f"must identify its listener uniquely or the accepting "
                    f"socket no longer determines provenance.")
            seen_bands[band] = channel
            self._listeners.append(listener)
        if not self._listeners:
            raise TransportMisconfigured("no listeners bound; nothing can arrive")
        self._servers: List[socketserver.BaseServer] = []
        self._threads: List[threading.Thread] = []

    @property
    def listeners(self) -> List[BoundListener]:
        return list(self._listeners)

    def serve(self, handler: Callable[[BoundListener, bytes], bytes]) -> None:
        """Start one Unix-domain server per listener.

        `handler(listener, request_bytes) -> response_bytes`. The listener is
        passed FIRST and the request second, so a handler that wants a band asks
        the listener for it; the request cannot supply one.
        """
        for listener in self._listeners:
            path = listener.path
            if os.path.exists(path):
                os.unlink(path)
            Path(path).parent.mkdir(parents=True, exist_ok=True)

            # BOUND AS A CLASS ATTRIBUTE, NOT A CLOSURE VARIABLE. A closure over
            # `listener` would be late-binding: every handler class shares this
            # function's scope, so all of them would see the LAST listener and
            # every connection would report the same band. That bug was present
            # and made every socket answer `user`; it survives a suite that only
            # checks refusals, because the wrong band is refused too.
            class _Handler(socketserver.BaseRequestHandler):
                accepting_listener = listener

                def handle(self) -> None:               # noqa: D401
                    data = self.request.recv(65536)
                    # The band is taken from the ACCEPTING listener, never `data`.
                    self.request.sendall(
                        handler(type(self).accepting_listener, data))

            class _Server(socketserver.ThreadingUnixStreamServer):
                allow_reuse_address = True
                daemon_threads = True

            srv = _Server(path, _Handler)
            os.chmod(path, 0o600)      # a gesture, NOT the network restriction
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            self._servers.append(srv)
            self._threads.append(t)

    def shutdown(self) -> None:
        for srv in self._servers:
            try:
                srv.shutdown()
                srv.server_close()
            except Exception:
                pass
        for listener in self._listeners:
            try:
                os.unlink(listener.path)
            except OSError:
                pass
        self._servers.clear()


def connect_and_send(path: str, payload: bytes, timeout: float = 5.0) -> bytes:
    """A client. It chooses WHERE to connect; it cannot choose what that means."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(path)
        s.sendall(payload)
        return s.recv(65536)
    finally:
        s.close()
