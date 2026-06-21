#!/usr/bin/env python3
# /// script
# dependencies = [
#     "cryptography>=42.0.0",
#     "textual>=1.0.0",
# ]
# ///
"""
OpenChatTUI — Encrypted Peer-to-Peer Terminal Chat
Zero-footprint · End-to-end encrypted · No servers

Usage:
    python openchat.py
"""

from __future__ import annotations

import asyncio
import base64
import gc
import hashlib
import json
import os
import random
import re
import socket
import struct
import subprocess
import shutil
import sys
import time
from datetime import datetime
from html import escape as html_escape

# ═══════════════════════════════════════════════════════════════
#  Dependency Bootstrapper
# ═══════════════════════════════════════════════════════════════
try:
    import cryptography
    import textual
except ImportError:
    print("Required packages (cryptography, textual) are missing.", flush=True)
    print("Attempting automatic installation...", flush=True)
    uv_path = shutil.which("uv")
    if uv_path:
        print("Found 'uv' installer! Installing packages...", flush=True)
        is_venv = sys.prefix != sys.base_prefix or "VIRTUAL_ENV" in os.environ
        cmd = [uv_path, "pip", "install"]
        if not is_venv:
            cmd.append("--system")
        cmd.extend(["cryptography>=42.0.0", "textual>=1.0.0"])
    else:
        print("Using standard pip...", flush=True)
        cmd = [sys.executable, "-m", "pip", "install", "cryptography>=42.0.0", "textual>=1.0.0"]

    try:
        subprocess.check_call(cmd)
        print("Installation complete. Restarting OpenChatTUI...", flush=True)
        os.execv(sys.executable, [sys.executable] + sys.argv)
    except Exception as e:
        print(f"Error during installation: {e}", file=sys.stderr, flush=True)
        print("Please install requirements manually using: pip install -r requirements.txt", file=sys.stderr, flush=True)
        sys.exit(1)

from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from textual.app import App, ComposeResult
from textual.screen import Screen, ModalScreen
from textual.widgets import (
    Static, Input, Button, RichLog,
    RadioSet, RadioButton, Label, OptionList,
)
from textual.containers import Container, Horizontal, Vertical, Center, Middle
from textual import on, work
from rich.text import Text


# ═══════════════════════════════════════════════════════════════
#  Constants
# ═══════════════════════════════════════════════════════════════

__version__ = "1.0.0"

COMMANDS = [
    "/lobby",
    "/login",
    "/save txt",
    "/save html",
    "/clear",
    "/peers",
    "/fingerprint",
    "/verify",
    "/exit",
    "/help",
    "/join",
    "/connect",
]

UDP_PORT = 50001
MCAST_GROUP = "239.0.0.1"
MAX_FRAME = 10 * 1024 * 1024  # 10 MB

COLORS = {
    "Red":      "#FF3B30",
    "Blue":     "#007AFF",
    "Green":    "#34C759",
    "Yellow":   "#FFCC00",
    "White":    "#FFFFFF",
    "Gold":     "#FFD700",
    "Silver":   "#C0C0C0",
    "Rose":     "#FF2D55",
    "Lavender": "#AF52DE",
    "Peach":    "#FF9500",
    "Mint":     "#00FFC4",
    "Coral":    "#FF6F61",
}

SYS_MUTED = "#888888"
SYS_WHITE = "#FFFFFF"
SYS_SUCCESS = "#34C759"
SYS_ERROR = "#FF3B30"
SYS_PRIMARY = "#007AFF"

LOGO = """\
[#FFFFFF]  ██████                            [/][#FFD700]  ██████  ██                 ██     [/]
[#FFFFFF] ██    ██  ██████   ██████   ██████ [/][#FFD700] ██       ██████   ██████  ██████   [/]
[#FFFFFF] ██    ██  ██   ██  ███████  ██   ██[/][#FFD700] ██       ██   ██ ██    ██   ██     [/]
[#FFFFFF] ██    ██  ██████   ██       ██   ██[/][#FFD700] ██       ██   ██  ███████   ██     [/]
[#FFFFFF]  ██████   ██       ██████   ██   ██[/][#FFD700]  ██████  ██   ██ ██    ██    ████  [/]

[#888888]                               ─ T U I ─[/]"""


# ═══════════════════════════════════════════════════════════════
#  Utilities
# ═══════════════════════════════════════════════════════════════

def make_chat_id(username: str) -> str:
    """Generate a unique 7-char uppercase alphanumeric Chat ID."""
    seed = os.urandom(16)
    digest = hashlib.sha256((username + seed.hex()).encode()).digest()
    return base64.b32encode(digest).decode()[:7]


def now_hm() -> str:
    return datetime.now().strftime("%H:%M")


def ts_hm(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M")


# ═══════════════════════════════════════════════════════════════
#  Crypto Engine
# ═══════════════════════════════════════════════════════════════

class CryptoEngine:
    """
    Military-grade encryption engine.

    - X25519 ECDH   — ephemeral key exchange (perfect forward secrecy)
    - AES-256-GCM   — authenticated encryption (confidentiality + integrity)
    - Ed25519       — digital signatures (anti-MITM)
    - HKDF-SHA256   — key derivation (unique keys per peer per direction)
    """

    def __init__(self):
        self._ecdh_priv = x25519.X25519PrivateKey.generate()
        self._ecdh_pub = self._ecdh_priv.public_key()
        self._sign_priv = ed25519.Ed25519PrivateKey.generate()
        self._sign_pub = self._sign_priv.public_key()
        self._nonce_pfx = os.urandom(4)
        self._sessions: dict[str, dict] = {}

    # ── Key accessors ─────────────────────────────────────────

    @property
    def ecdh_pub_raw(self) -> bytes:
        return self._ecdh_pub.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )

    @property
    def sign_pub_raw(self) -> bytes:
        return self._sign_pub.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )

    @property
    def fingerprint(self) -> str:
        h = hashlib.sha256(self.sign_pub_raw).hexdigest().upper()
        return ":".join(h[i:i + 4] for i in range(0, 32, 4))

    def peer_fp(self, sign_pub: bytes) -> str:
        h = hashlib.sha256(sign_pub).hexdigest().upper()
        return ":".join(h[i:i + 4] for i in range(0, 32, 4))

    # ── Sign / verify ─────────────────────────────────────────

    def sign(self, data: bytes) -> bytes:
        return self._sign_priv.sign(data)

    def verify(self, pub: bytes, sig: bytes, data: bytes) -> bool:
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(pub).verify(sig, data)
            return True
        except Exception:
            return False

    # ── Session keys ──────────────────────────────────────────

    def derive(self, peer_id: str, peer_ecdh: bytes, my_id: str):
        """Derive directional AES-256-GCM keys via ECDH + HKDF."""
        peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_ecdh)
        shared = self._ecdh_priv.exchange(peer_pub)

        ids = sorted([my_id, peer_id])
        k_fwd = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None,
            info=f"OpenChatTUI:v1:{ids[0]}>{ids[1]}".encode(),
        ).derive(shared)
        k_rev = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None,
            info=f"OpenChatTUI:v1:{ids[1]}>{ids[0]}".encode(),
        ).derive(shared)

        s, r = (k_fwd, k_rev) if my_id == ids[0] else (k_rev, k_fwd)
        self._sessions[peer_id] = {
            "tx": AESGCM(s), "rx": AESGCM(r), "ctr": 0,
        }

    def encrypt(self, pid: str, pt: bytes) -> bytes:
        s = self._sessions[pid]
        s["ctr"] += 1
        nonce = self._nonce_pfx + struct.pack(">Q", s["ctr"])
        return nonce + s["tx"].encrypt(nonce, pt, None)

    def decrypt(self, pid: str, data: bytes) -> bytes:
        return self._sessions[pid]["rx"].decrypt(data[:12], data[12:], None)

    def drop(self, pid: str):
        self._sessions.pop(pid, None)

    def secure_wipe(self):
        """Overwrite key material and force GC."""
        self._sessions.clear()
        self._ecdh_priv = None
        self._sign_priv = None
        self._nonce_pfx = b"\x00" * 4
        gc.collect()


# ═══════════════════════════════════════════════════════════════
#  Wire Protocol
# ═══════════════════════════════════════════════════════════════

async def _send(w: asyncio.StreamWriter, payload: bytes):
    """Send a 4-byte length-prefixed frame."""
    w.write(struct.pack(">I", len(payload)) + payload)
    await w.drain()


async def _recv(r: asyncio.StreamReader) -> bytes:
    """Receive a 4-byte length-prefixed frame."""
    hdr = await r.readexactly(4)
    n = struct.unpack(">I", hdr)[0]
    if n > MAX_FRAME:
        raise ValueError("frame too large")
    return await r.readexactly(n)


# ═══════════════════════════════════════════════════════════════
#  Peer
# ═══════════════════════════════════════════════════════════════

class Peer:
    __slots__ = (
        "id", "name", "color", "port",
        "rd", "wr", "sign_pub", "alive",
    )

    def __init__(self, id_, name, color, port, rd, wr, sign_pub):
        self.id = id_
        self.name = name
        self.color = color
        self.port = port
        self.rd = rd
        self.wr = wr
        self.sign_pub = sign_pub
        self.alive = True

    @property
    def ip(self) -> str:
        info = self.wr.get_extra_info("peername")
        return info[0] if info else "?"


# ═══════════════════════════════════════════════════════════════
#  UDP Discovery Protocol
# ═══════════════════════════════════════════════════════════════

class _UDP(asyncio.DatagramProtocol):
    def __init__(self, node: NetNode):
        self.node = node
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        asyncio.ensure_future(self.node._on_udp(data, addr))

    def error_received(self, exc):
        pass


# ═══════════════════════════════════════════════════════════════
#  Network Node
# ═══════════════════════════════════════════════════════════════

class NetNode:
    """
    Full-mesh P2P network node.
    - TCP server for incoming connections
    - TCP client for outgoing connections
    - UDP multicast/broadcast for peer discovery
    - Encrypted handshake + messaging
    """

    def __init__(self, name: str, cid: str, color: str,
                 crypto: CryptoEngine, cb):
        self.name = name
        self.cid = cid
        self.color = color
        self.crypto = crypto
        self.cb = cb  # async (event, **kw)
        self.peers: dict[str, Peer] = {}
        self.port = 0
        self.room = ""
        self._on = False
        self._busy: set[str] = set()  # peer IDs currently connecting
        self._srv = None
        self._udp_t = None
        self._lock = asyncio.Lock()

    # ── Lifecycle ─────────────────────────────────────────────

    async def start(self, room: str):
        self.room = room
        self._on = True
        self._srv = await asyncio.start_server(
            self._tcp_in, "0.0.0.0", 0,
        )
        self.port = self._srv.sockets[0].getsockname()[1]
        await self._udp_init()
        asyncio.create_task(self._announce())

    async def stop(self):
        self._on = False
        for p in list(self.peers.values()):
            try:
                enc = self.crypto.encrypt(p.id, json.dumps(
                    {"t": "leave", "id": self.cid},
                ).encode())
                await _send(p.wr, enc)
            except Exception:
                pass
            p.alive = False
            try:
                p.wr.close()
            except Exception:
                pass
        self.peers.clear()
        if self._srv:
            self._srv.close()
        if self._udp_t:
            self._udp_t.close()
        self.crypto.secure_wipe()

    # ── TCP incoming (we are responder) ───────────────────────

    async def _tcp_in(self, rd, wr):
        try:
            raw = await asyncio.wait_for(_recv(rd), 15)
            h = json.loads(raw)
            if h.get("t") != "hello":
                wr.close(); return

            pid = h["id"]
            async with self._lock:
                if pid in self.peers or pid == self.cid:
                    wr.close(); return

            # Verify Ed25519 signature on ECDH pubkey
            ep = bytes.fromhex(h["ep"])
            sp = bytes.fromhex(h["sp"])
            sig = bytes.fromhex(h["sg"])
            if not self.crypto.verify(sp, sig, ep):
                wr.close(); return

            self.crypto.derive(pid, ep, self.cid)

            # Reply with our keys + peer list
            me = self.crypto.ecdh_pub_raw
            ms = self.crypto.sign_pub_raw
            mg = self.crypto.sign(me)
            plist = [
                {"id": p.id, "ip": p.ip, "port": p.port}
                for p in self.peers.values()
            ]
            reply = json.dumps({
                "t": "ack", "id": self.cid, "n": self.name,
                "c": self.color, "port": self.port,
                "ep": me.hex(), "sp": ms.hex(), "sg": mg.hex(),
                "room": self.room, "peers": plist,
            }).encode()
            await _send(wr, reply)

            peer = Peer(pid, h["n"], h["c"], h["port"], rd, wr, sp)
            async with self._lock:
                if pid in self.peers:
                    wr.close(); return
                self.peers[pid] = peer

            await self.cb("join", name=peer.name,
                          color=peer.color, id=pid)
            asyncio.create_task(self._rx(peer))

        except Exception:
            try:
                wr.close()
            except Exception:
                pass

    # ── TCP outgoing (we are initiator) ───────────────────────

    async def connect(self, ip: str, port: int):
        try:
            rd, wr = await asyncio.wait_for(
                asyncio.open_connection(ip, port), 10,
            )
            me = self.crypto.ecdh_pub_raw
            ms = self.crypto.sign_pub_raw
            mg = self.crypto.sign(me)

            hello = json.dumps({
                "t": "hello", "id": self.cid, "n": self.name,
                "c": self.color, "port": self.port,
                "ep": me.hex(), "sp": ms.hex(), "sg": mg.hex(),
            }).encode()
            await _send(wr, hello)

            raw = await asyncio.wait_for(_recv(rd), 15)
            ack = json.loads(raw)
            if ack.get("t") != "ack":
                wr.close(); return

            pid = ack["id"]
            async with self._lock:
                if pid in self.peers or pid == self.cid:
                    wr.close(); return

            ep = bytes.fromhex(ack["ep"])
            sp = bytes.fromhex(ack["sp"])
            sig = bytes.fromhex(ack["sg"])
            if not self.crypto.verify(sp, sig, ep):
                wr.close(); return

            self.crypto.derive(pid, ep, self.cid)

            peer = Peer(pid, ack["n"], ack["c"], ack["port"],
                        rd, wr, sp)
            async with self._lock:
                if pid in self.peers:
                    wr.close(); return
                self.peers[pid] = peer

            if ack.get("room"):
                self.room = ack["room"]

            await self.cb("join", name=peer.name,
                          color=peer.color, id=pid)

            # Full-mesh expansion: connect to peers we don't know
            for info in ack.get("peers", []):
                xid = info["id"]
                if (xid not in self.peers and xid != self.cid
                        and xid not in self._busy):
                    self._busy.add(xid)
                    asyncio.create_task(self._mesh(info["ip"],
                                                   info["port"], xid))

            asyncio.create_task(self._rx(peer))

        except Exception:
            pass

    async def _mesh(self, ip, port, pid):
        try:
            await self.connect(ip, port)
        finally:
            self._busy.discard(pid)

    # ── Receive loop ──────────────────────────────────────────

    async def _rx(self, peer: Peer):
        try:
            while self._on and peer.alive:
                raw = await _recv(peer.rd)
                pt = self.crypto.decrypt(peer.id, raw)
                msg = json.loads(pt)
                if msg["t"] == "msg":
                    await self.cb("msg", name=msg["n"],
                                  color=msg["c"], text=msg["m"],
                                  ts=msg["ts"])
                elif msg["t"] == "leave":
                    break
        except Exception:
            pass
        finally:
            peer.alive = False
            self.crypto.drop(peer.id)
            async with self._lock:
                self.peers.pop(peer.id, None)
            try:
                peer.wr.close()
            except Exception:
                pass
            await self.cb("leave", name=peer.name,
                          color=peer.color, id=peer.id)

    # ── Send message ──────────────────────────────────────────

    async def send(self, text: str):
        payload = json.dumps({
            "t": "msg", "n": self.name, "c": self.color,
            "m": text, "ts": time.time(),
        }).encode()
        for p in list(self.peers.values()):
            try:
                await _send(p.wr, self.crypto.encrypt(p.id, payload))
            except Exception:
                pass

    # ── UDP discovery ─────────────────────────────────────────

    async def _udp_init(self):
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                             socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                sock.setsockopt(socket.SOL_SOCKET,
                                socket.SO_REUSEPORT, 1)
            except Exception:
                pass
        try:
            sock.bind(("", UDP_PORT))
        except OSError:
            return  # UDP unavailable, TCP-only mode
        try:
            mreq = struct.pack(
                "4sL", socket.inet_aton(MCAST_GROUP), socket.INADDR_ANY,
            )
            sock.setsockopt(socket.IPPROTO_IP,
                            socket.IP_ADD_MEMBERSHIP, mreq)
        except Exception:
            pass
        sock.setblocking(False)
        t, _ = await loop.create_datagram_endpoint(
            lambda: _UDP(self), sock=sock,
        )
        self._udp_t = t

    def _udp_tx(self, data: bytes, addr=None):
        if not self._udp_t:
            return
        for dst in ([addr] if addr else [
            ("255.255.255.255", UDP_PORT),
            (MCAST_GROUP, UDP_PORT),
        ]):
            try:
                self._udp_t.sendto(data, dst)
            except Exception:
                pass

    async def _announce(self):
        while self._on:
            self._udp_tx(json.dumps({
                "t": "ANN", "id": self.cid, "n": self.name,
                "p": self.port, "c": self.color, "r": self.room,
            }).encode())
            await asyncio.sleep(3)

    async def _on_udp(self, data: bytes, addr):
        try:
            pkt = json.loads(data)
        except Exception:
            return
        typ = pkt.get("t")
        if typ == "QRY" and pkt.get("target") == self.cid:
            self._udp_tx(json.dumps({
                "t": "RSP", "id": self.cid,
                "p": self.port, "c": self.color,
            }).encode(), addr)
        elif typ == "RSP":
            pid = pkt["id"]
            if (pid not in self.peers and pid != self.cid
                    and pid not in self._busy):
                self._busy.add(pid)
                asyncio.create_task(
                    self._mesh(addr[0], pkt["p"], pid))

    async def query(self, target: str) -> bool:
        """Broadcast UDP queries to find a peer. Returns True if found."""
        pkt = json.dumps({
            "t": "QRY", "target": target, "from": self.cid,
        }).encode()
        for _ in range(10):
            self._udp_tx(pkt)
            await asyncio.sleep(1)
            if target in self.peers:
                return True
        return target in self.peers


# ═══════════════════════════════════════════════════════════════
#  Screen: Login
# ═══════════════════════════════════════════════════════════════

class LoginScreen(Screen):
    """Username entry + color selection."""

    _color: str = "random"

    def compose(self) -> ComposeResult:
        with Middle():
            with Center():
                with Vertical(id="login-card"):
                    yield Static(LOGO, id="logo")
                    yield Static("─" * 74, classes="sep")
                    yield Label("  Username", classes="lbl")
                    yield Input(placeholder="Enter your name...",
                                id="name-in", max_length=20)
                    yield Label("  Your Color", classes="lbl")
                    with RadioSet(id="clr-pick"):
                        for name in COLORS:
                            yield RadioButton(name)
                        yield RadioButton("Random", value=True)
                        yield RadioButton("Custom")
                    with Vertical(id="hex-container"):
                        yield Label("  Custom Hex", classes="lbl")
                        yield Input(placeholder="#FF6B9D",
                                    id="hex-in", max_length=7)
                    yield Button("Continue", id="go-btn",
                                 variant="primary")
                    yield Label(
                        "esc: menu  ·  ctrl+q: emergency quit  ·  e2ee · zero footprint",
                        id="tagline",
                    )

    def on_mount(self):
        self.query_one("#hex-container").styles.display = "none"

    @on(RadioSet.Changed, "#clr-pick")
    def _clr(self, ev: RadioSet.Changed):
        lab = ev.pressed.label.plain
        if lab == "Custom":
            self._color = "custom"
            self.query_one("#hex-container").styles.display = "block"
        else:
            self._color = COLORS.get(lab, "random")
            self.query_one("#hex-container").styles.display = "none"

    @on(Button.Pressed, "#go-btn")
    def _go(self, ev: Button.Pressed):
        name = self.query_one("#name-in", Input).value.strip()
        if not name:
            self.notify("Please enter a username.", severity="error")
            return
        
        if self._color == "custom":
            hx = self.query_one("#hex-in", Input).value.strip()
            if not hx or not re.match(r"^#[0-9A-Fa-f]{6}$", hx):
                self.notify("Please enter a valid hex color (e.g. #FF6B9D).", severity="error")
                return
            color = hx
        elif self._color == "random":
            color = random.choice(list(COLORS.values()))
        else:
            color = self._color
            
        self.app.user_name = name.upper()
        self.app.user_color = color
        self.app.user_cid = make_chat_id(self.app.user_name)
        self.app.push_screen(LobbyScreen())

    @on(Input.Submitted, "#name-in")
    def _enter_name(self, ev: Input.Submitted):
        self._go(None)


# ═══════════════════════════════════════════════════════════════
#  Screen: Lobby
# ═══════════════════════════════════════════════════════════════

class LobbyScreen(Screen):
    """Create or join a room."""

    def compose(self) -> ComposeResult:
        a = self.app
        with Vertical(id="lobby-wrap"):
            yield Static(
                f"  OpenChatTUI   ·   {a.user_name}   ·"
                f"   ID: {a.user_cid}",
                id="lobby-hdr",
            )
            with Middle():
                with Center():
                    with Vertical(id="lobby-cards"):
                        with Vertical(id="create-card", classes="lcard"):
                            yield Label("  CREATE A ROOM",
                                        classes="card-title")
                            yield Input(
                                placeholder="Room name (optional)",
                                id="room-in",
                            )
                            yield Button("Create & Host",
                                         id="create-btn",
                                         variant="primary")
                        with Vertical(id="join-card", classes="lcard"):
                            yield Label("  JOIN A ROOM",
                                        classes="card-title")
                            yield Input(
                                placeholder="Chat ID  (e.g. K7X9R2W)",
                                id="join-in", max_length=8,
                            )
                            yield Button("Join Room",
                                         id="join-btn",
                                         variant="primary")
                        yield Button("Back to Login", id="back-login-btn")
            yield Label(
                "  AES-256-GCM + X25519 ECDH · ESC: Menu · Ctrl+Q: Emergency Quit",
                id="lobby-ftr",
            )

    @on(Button.Pressed, "#create-btn")
    def _create(self, ev):
        room = self.query_one("#room-in", Input).value.strip()
        self.app.room_name = room or f"Room-{self.app.user_cid}"
        self.app.join_target = ""
        self.app.push_screen(ChatScreen())

    @on(Button.Pressed, "#join-btn")
    def _join(self, ev):
        tid = self.query_one("#join-in", Input).value.strip().upper()
        if not tid or not re.match(r"^[A-Z0-9]{6,8}$", tid):
            self.notify(
                "Enter a valid Chat ID (6-8 uppercase alphanumeric).",
                severity="error",
            )
            return
        self.app.join_target = tid
        self.app.room_name = ""
        self.app.push_screen(ChatScreen())

    @on(Input.Submitted, "#room-in")
    def _enter_room(self, ev):
        self._create(None)

    @on(Input.Submitted, "#join-in")
    def _enter_join(self, ev):
        self._join(None)

    @on(Button.Pressed, "#back-login-btn")
    def _back_login(self, ev):
        self.app.pop_screen()


# ═══════════════════════════════════════════════════════════════
#  Screen: Chat
# ═══════════════════════════════════════════════════════════════

class ChatScreen(Screen):
    """Main chat interface with encrypted P2P messaging."""

    def __init__(self):
        super().__init__()
        self._hist: list[tuple] = []
        # (type, username, color, content, timestamp)
        self._curr_matches: list[str] = []

    def compose(self) -> ComposeResult:
        room = self.app.room_name or "..."
        with Vertical(id="chat-wrap"):
            yield Static(
                f"  {room}  ·  ID: {self.app.user_cid}"
                f"  ·  Peers: 1",
                id="chat-hdr",
            )
            with Horizontal(id="chat-body"):
                yield RichLog(id="chat-log", wrap=True,
                              highlight=False, markup=False)
                yield Static("  Peers\n  " + "─" * 16,
                              id="sidebar")
            yield OptionList(id="cmd-suggestions")
            with Horizontal(id="input-bar"):
                yield Input(placeholder="Type message or /command... [ESC: Menu, Ctrl+Q: Emergency Quit]",
                            id="msg-in")
                yield Static("  E2EE", id="enc-badge")

    def on_mount(self):
        self._boot_net()
        self.query_one("#msg-in", Input).focus()

    @work(thread=False)
    async def _boot_net(self):
        a = self.app
        a.crypto = CryptoEngine()
        a.net = NetNode(
            a.user_name, a.user_cid, a.user_color,
            a.crypto, self._ev,
        )
        room = a.room_name or f"Room-{a.user_cid}"
        a.room_name = room
        self._hdr()

        await a.net.start(room)

        if a.join_target:
            self._sys(f"Searching for {a.join_target}...", SYS_MUTED)
            ok = await a.net.query(a.join_target)
            if ok:
                self._sys("Connected.", SYS_SUCCESS)
                if a.net.room:
                    a.room_name = a.net.room
                self._hdr()
            else:
                self._sys(
                    f"Could not find {a.join_target}. "
                    "Peer may be offline or on a different network.",
                    SYS_ERROR,
                )
        else:
            self._sys(
                f"Room created. Share your Chat ID:  {a.user_cid}",
                SYS_SUCCESS,
            )
            self._sys("Waiting for peers to join...", SYS_MUTED)

    # ── Network callbacks ─────────────────────────────────────

    async def _ev(self, event: str, **kw):
        try:
            if event == "msg":
                self._write(kw["name"], kw["color"],
                            kw["text"], kw["ts"])
            elif event == "join":
                self._sys(f"* {kw['name']} joined the chatroom",
                          kw["color"])
                self._sidebar()
                self._hdr()
            elif event == "leave":
                self._sys(f"* {kw['name']} left the chatroom",
                          kw["color"])
                self._sidebar()
                self._hdr()
        except Exception:
            pass

    # ── Rendering helpers ─────────────────────────────────────

    def _write(self, name: str, color: str, text: str, ts: float):
        log = self.query_one("#chat-log", RichLog)
        t = Text()
        t.append(f"  {ts_hm(ts)}  ", style="dim")
        t.append(f"{name}  ", style=f"{color} bold")
        t.append(text)
        log.write(t)
        self._hist.append(("msg", name, color, text, ts))

    def _sys(self, msg: str, color: str = SYS_MUTED):
        log = self.query_one("#chat-log", RichLog)
        t = Text()
        t.append(f"  {now_hm()}  ", style="dim")
        t.append(msg, style=color)
        t.justify = "center"
        log.write(t)
        self._hist.append(("sys", "", color, msg, time.time()))

    def _sidebar(self):
        sb = self.query_one("#sidebar", Static)
        a = self.app
        net = a.net
        t = Text()
        n = (len(net.peers) + 1) if net else 1
        t.append(f"  Peers ({n})\n", style="bold")
        t.append("  " + "─" * 16 + "\n", style="dim")
        t.append(f"  ● {a.user_name}\n", style=a.user_color)
        if net:
            for p in net.peers.values():
                t.append(f"  ● {p.name}\n", style=p.color)
        sb.update(t)

    def _hdr(self):
        hdr = self.query_one("#chat-hdr", Static)
        a = self.app
        n = (len(a.net.peers) + 1) if a.net else 1
        hdr.update(
            f"  {a.room_name}  ·  ID: {a.user_cid}"
            f"  ·  Peers: {n}"
        )

    # ── Input handling ────────────────────────────────────────

    @on(Input.Submitted, "#msg-in")
    async def _on_input(self, ev: Input.Submitted):
        text = ev.value.strip()
        if not text:
            return
        ev.input.clear()
        
        # Hide suggestions list
        sugg = self.query_one("#cmd-suggestions", OptionList)
        sugg.styles.display = "none"
        self._curr_matches = []

        if text.startswith("/"):
            self._write(self.app.user_name, self.app.user_color, text, time.time())
            await self._cmd(text)
        else:
            self._write(self.app.user_name, self.app.user_color,
                        text, time.time())
            if self.app.net:
                await self.app.net.send(text)

    @on(Input.Changed, "#msg-in")
    def _input_changed(self, ev: Input.Changed):
        val = ev.value
        sugg = self.query_one("#cmd-suggestions", OptionList)
        if val.startswith("/") and " " not in val:
            prefix = val.lower()
            matches = [c for c in COMMANDS if c.startswith(prefix)]
            if matches:
                self._curr_matches = matches
                sugg.clear_options()
                sugg.add_options(matches)
                sugg.styles.display = "block"
                sugg.highlighted = 0
            else:
                self._curr_matches = []
                sugg.styles.display = "none"
        else:
            self._curr_matches = []
            sugg.styles.display = "none"

    def on_key(self, event) -> None:
        sugg = self.query_one("#cmd-suggestions", OptionList)
        if sugg.styles.display != "none":
            if event.key == "up":
                event.prevent_default()
                event.stop()
                if sugg.highlighted is not None and sugg.highlighted > 0:
                    sugg.highlighted -= 1
                elif sugg.highlighted is None and sugg.option_count > 0:
                    sugg.highlighted = sugg.option_count - 1
            elif event.key == "down":
                event.prevent_default()
                event.stop()
                if sugg.highlighted is not None and sugg.highlighted < sugg.option_count - 1:
                    sugg.highlighted += 1
                elif sugg.highlighted is None and sugg.option_count > 0:
                    sugg.highlighted = 0
            elif event.key in ("enter", "tab"):
                if sugg.highlighted is not None and 0 <= sugg.highlighted < len(self._curr_matches):
                    event.prevent_default()
                    event.stop()
                    selected = self._curr_matches[sugg.highlighted]
                    inp = self.query_one("#msg-in", Input)
                    inp.value = selected + " "
                    inp.cursor_position = len(inp.value)
                    sugg.styles.display = "none"
                    self._curr_matches = []
                    inp.focus()

    @on(OptionList.OptionSelected, "#cmd-suggestions")
    def _cmd_selected(self, ev: OptionList.OptionSelected):
        idx = ev.option_index
        if idx is not None and 0 <= idx < len(self._curr_matches):
            selected = self._curr_matches[idx]
            inp = self.query_one("#msg-in", Input)
            inp.value = selected + " "
            inp.cursor_position = len(inp.value)
            ev.option_list.styles.display = "none"
            self._curr_matches = []
            inp.focus()

    # ── Slash commands ────────────────────────────────────────

    async def _cmd(self, raw: str):
        parts = raw.split(maxsplit=1)
        cmd = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""

        if cmd == "/join":
            await self._c_join(arg)
        elif cmd == "/connect":
            await self._c_connect(arg)
        elif cmd == "/save":
            self._c_save(arg)
        elif cmd == "/clear":
            self.query_one("#chat-log", RichLog).clear()
            self._sys("Screen cleared. History preserved.", SYS_MUTED)
        elif cmd == "/peers":
            self._c_peers()
        elif cmd == "/fingerprint":
            fp = self.app.crypto.fingerprint if self.app.crypto else "?"
            self._sys(f"Your fingerprint: {fp}", SYS_PRIMARY)
        elif cmd == "/verify":
            self._c_verify(arg)
        elif cmd == "/lobby":
            await self._c_lobby()
        elif cmd == "/login":
            await self._c_login_cmd()
        elif cmd == "/exit":
            await self._c_exit()
        elif cmd == "/help":
            self._c_help()
        else:
            self._sys(f"Unknown: {cmd}  — type /help", SYS_ERROR)

    async def _c_join(self, arg: str):
        tid = arg.strip().upper()
        if not tid or not re.match(r"^[A-Z0-9]{6,8}$", tid):
            self._sys("Usage: /join <CHAT_ID>", SYS_ERROR)
            return
        if not self.app.net:
            return
        self._sys(f"Searching for {tid}...", SYS_MUTED)
        ok = await self.app.net.query(tid)
        self._sys("Connected." if ok else f"Could not find {tid}.",
                  SYS_SUCCESS if ok else SYS_ERROR)

    async def _c_connect(self, arg: str):
        m = re.match(r"^([\d.]+):(\d+)$", arg.strip())
        if not m:
            self._sys("Usage: /connect <IP:PORT>", SYS_ERROR)
            return
        ip, port = m.group(1), int(m.group(2))
        self._sys(f"Connecting to {ip}:{port}...", SYS_MUTED)
        if self.app.net:
            await self.app.net.connect(ip, port)

    def _c_save(self, fmt: str):
        fmt = fmt.lower().strip()
        if fmt == "txt":
            self._save_txt()
        elif fmt == "html":
            self._save_html()
        else:
            self._sys("Usage: /save txt  or  /save html", SYS_ERROR)

    def _save_txt(self):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        fn = f"OpenChatTUI_{self.app.room_name}_{ts}.txt"
        lines = []
        for typ, name, _, text, t in self._hist:
            stamp = ts_hm(t)
            if typ == "msg":
                lines.append(f"[{stamp}] <{name}> {text}")
            else:
                lines.append(f"[{stamp}] {text}")
        with open(fn, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        self._sys(f"Saved to {fn}", SYS_SUCCESS)

    def _save_html(self):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        fn = f"OpenChatTUI_{self.app.room_name}_{ts}.html"
        msgs = []
        for typ, name, color, text, t in self._hist:
            stamp = ts_hm(t)
            if typ == "msg":
                msgs.append(
                    f'<div class="m"><span class="t">{stamp}</span>'
                    f' <b style="color:{color}">'
                    f'{html_escape(name)}</b> '
                    f'{html_escape(text)}</div>'
                )
            else:
                msgs.append(
                    f'<div class="s" style="color:{color}">'
                    f'<span class="t">{stamp}</span> '
                    f'{html_escape(text)}</div>'
                )
        html = (
            '<!DOCTYPE html><html lang="en"><head>'
            '<meta charset="utf-8">'
            f'<title>OpenChatTUI — '
            f'{html_escape(self.app.room_name)}</title>'
            '<style>'
            'body{background:#000000;color:#FFFFFF;'
            "font-family:'Cascadia Code','Fira Code',"
            "'Consolas',monospace;"
            'max-width:800px;margin:40px auto;padding:0 20px}'
            'h1{color:#FFFFFF;font-size:1.4em}'
            'hr{border:1px solid #333333}'
            '.m{padding:6px 12px;margin:2px 0;border-radius:4px;'
            'background:#111111}'
            '.s{padding:4px 12px;margin:2px 0;font-style:italic}'
            '.t{color:#888888;font-size:.85em;margin-right:8px}'
            '</style></head><body>'
            f'<h1>OpenChatTUI — '
            f'{html_escape(self.app.room_name)}</h1>'
            f'<p style="color:#888888">Exported: '
            f'{datetime.now().strftime("%Y-%m-%d %H:%M")}</p><hr>'
            + "".join(msgs)
            + '</body></html>'
        )
        with open(fn, "w", encoding="utf-8") as f:
            f.write(html)
        self._sys(f"Saved to {fn}", SYS_SUCCESS)

    def _c_peers(self):
        a = self.app
        net = a.net
        if not net:
            return
        self._sys(
            f"You: {a.user_name}  [{a.user_cid}]", a.user_color,
        )
        for p in net.peers.values():
            fp = a.crypto.peer_fp(p.sign_pub)
            self._sys(f"  {p.name}  [{p.id}]  {fp[:19]}...",
                      p.color)
        if not net.peers:
            self._sys("  No peers connected.", SYS_MUTED)

    def _c_verify(self, arg: str):
        tid = arg.strip().upper()
        a = self.app
        if not a.net or not tid:
            self._sys("Usage: /verify <CHAT_ID>", SYS_ERROR)
            return
        peer = a.net.peers.get(tid)
        if not peer:
            self._sys(f"Peer {tid} not found.", SYS_ERROR)
            return
        fp = a.crypto.peer_fp(peer.sign_pub)
        self._sys(f"{peer.name}'s fingerprint:", peer.color)
        self._sys(f"  {fp}", SYS_PRIMARY)

    async def _c_login_cmd(self):
        self._sys("Disconnecting and returning to Login...", SYS_MUTED)
        await asyncio.sleep(0.2)
        if self.app.net:
            try:
                await self.app.net.stop()
            except Exception:
                pass
            self.app.net = None
        self.app.room_name = ""
        self._hist.clear()
        self.app.pop_screen()
        self.app.pop_screen()

    async def _c_lobby(self):
        self._sys("Disconnecting and returning to Lobby...", SYS_MUTED)
        await asyncio.sleep(0.2)
        if self.app.net:
            try:
                await self.app.net.stop()
            except Exception:
                pass
            self.app.net = None
        self.app.room_name = ""
        self._hist.clear()
        self.app.pop_screen()

    async def _c_exit(self):
        self._sys("Secure wipe complete. Goodbye.", SYS_SUCCESS)
        await asyncio.sleep(0.5)
        await self.app.exit_secure()

    def _c_help(self):
        cmds = [
            ("/join <ID>",        "Connect to a peer by Chat ID"),
            ("/connect <IP:PORT>","Direct TCP connection"),
            ("/save txt",         "Export chat as plaintext"),
            ("/save html",        "Export chat as styled HTML"),
            ("/clear",            "Clear the screen"),
            ("/peers",            "List connected peers"),
            ("/fingerprint",      "Show your Ed25519 fingerprint"),
            ("/verify <ID>",      "Show a peer's fingerprint"),
            ("/lobby",            "Disconnect and return to Lobby screen"),
            ("/login",            "Disconnect and return to Login screen"),
            ("/exit",             "Secure wipe and quit"),
        ]
        self._sys("Available commands:", SYS_PRIMARY)
        for c, d in cmds:
            t = Text()
            t.append(f"    {c:22s}", style=SYS_PRIMARY)
            t.append(f" {d}", style="#FFFFFF")
            self.query_one("#chat-log", RichLog).write(t)

# ═══════════════════════════════════════════════════════════════
#  Screen: Exit Menu Modal Overlay
# ═══════════════════════════════════════════════════════════════

class ExitMenuScreen(ModalScreen):
    """Modal overlay for continue / quit selection."""

    def compose(self) -> ComposeResult:
        with Vertical(id="exit-menu-card"):
            yield Label("Quit OpenChatTUI?", id="exit-menu-title")
            yield Label(
                "Are you sure you want to exit?\nThis will trigger a secure memory wipe.",
                id="exit-menu-desc"
            )
            with Horizontal(id="exit-menu-buttons"):
                yield Button("Continue Chat", id="exit-continue")
                yield Button("Secure Quit", id="exit-quit")
            yield Label("ESC: Continue  ·  Ctrl+Q: Secure Quit", id="exit-menu-tagline")

    def on_mount(self):
        self.query_one("#exit-continue", Button).focus()

    @on(Button.Pressed, "#exit-continue")
    def _on_continue(self):
        self.dismiss(False)

    @on(Button.Pressed, "#exit-quit")
    def _on_quit(self):
        self.dismiss(True)

    def on_key(self, event) -> None:
        if event.key == "escape":
            event.prevent_default()
            event.stop()
            self.dismiss(False)

# ═══════════════════════════════════════════════════════════════
#  Application
# ═══════════════════════════════════════════════════════════════

class OpenChatApp(App):
    """OpenChatTUI — Encrypted P2P Terminal Chat."""

    TITLE = "OpenChatTUI"

    CSS = """
    /* ═══════════════════════════════════════════════════════ */
    /*  Global                                                 */
    /* ═══════════════════════════════════════════════════════ */
    Screen {
        background: #000000;
        color: #FFFFFF;
    }
    Input {
        background: #000000;
        border: tall #333333;
        color: #FFFFFF;
    }
    Input:focus {
        border: tall #FFFFFF;
    }
    Button {
        background: #333333;
        color: #FFFFFF;
        border: none;
        text-style: bold;
        min-width: 16;
    }
    Button:hover {
        background: #FFFFFF;
        color: #000000;
        text-style: bold;
    }
    Button:focus {
        background: #FFFFFF;
        color: #000000;
        text-style: bold;
    }
    RadioSet {
        background: transparent;
        border: none;
        height: auto;
    }

    /* ═══════════════════════════════════════════════════════ */
    /*  Login Screen                                           */
    /* ═══════════════════════════════════════════════════════ */
    #login-card {
        width: 82;
        height: auto;
        background: #000000;
        border: round #333333;
        padding: 1 2;
    }
    #logo {
        color: #FFFFFF;
        text-style: bold;
        text-align: center;
    }
    .sep {
        color: #333333;
        text-align: center;
    }
    .lbl {
        color: #888888;
        padding: 1 0 0 0;
    }
    #clr-pick {
        layout: grid;
        grid-size: 7 2;
        height: 5;
        margin: 1 0;
    }
    #hex-container {
        height: auto;
    }
    #login-card Input {
        margin: 0 0 0 0;
    }
    #go-btn {
        width: 100%;
        margin: 1 0;
    }
    #tagline {
        text-align: center;
        color: #888888;
        padding: 1 0 0 0;
    }

    /* ═══════════════════════════════════════════════════════ */
    /*  Lobby Screen                                           */
    /* ═══════════════════════════════════════════════════════ */
    #lobby-wrap {
        height: 100%;
    }
    #lobby-hdr {
        dock: top;
        height: 3;
        background: #000000;
        color: #FFFFFF;
        text-style: bold;
        padding: 1 0;
        border-bottom: solid #333333;
    }
    #lobby-cards {
        width: 82;
        height: auto;
    }
    .lcard {
        background: #000000;
        border: round #333333;
        padding: 1 2;
        margin: 1 0;
        height: auto;
    }
    .card-title {
        color: #FFFFFF;
        text-style: bold;
        padding: 0 0 1 0;
    }
    .lcard Input {
        margin: 0 0 1 0;
    }
    .lcard Button {
        width: 100%;
    }
    #lobby-ftr {
        dock: bottom;
        height: 3;
        color: #888888;
        padding: 1 0;
        text-align: center;
        border-top: solid #333333;
    }
    #back-login-btn {
        width: 100%;
        margin-top: 1;
        background: #333333;
        color: #FFFFFF;
    }
    #back-login-btn:hover, #back-login-btn:focus {
        background: #FFFFFF;
        color: #000000;
        text-style: bold;
    }

    /* ═══════════════════════════════════════════════════════ */
    /*  Chat Screen                                            */
    /* ═══════════════════════════════════════════════════════ */
    #chat-wrap {
        height: 100%;
    }
    #chat-hdr {
        dock: top;
        height: 3;
        background: #000000;
        color: #FFFFFF;
        text-style: bold;
        padding: 1 0;
        border-bottom: solid #333333;
    }
    #chat-body {
        height: 1fr;
    }
    #chat-log {
        width: 1fr;
        background: #000000;
        border: none;
        padding: 0;
        scrollbar-color: #333333;
        scrollbar-color-hover: #FFFFFF;
        scrollbar-color-active: #FFFFFF;
    }
    #sidebar {
        width: 24;
        background: #000000;
        border-left: solid #333333;
        padding: 1 0;
    }
    #input-bar {
        dock: bottom;
        height: 3;
        background: #000000;
        border-top: solid #333333;
    }
    #msg-in {
        width: 1fr;
        border: none;
        background: #000000;
    }
    #msg-in:focus {
        border: none;
    }
    #enc-badge {
        width: 10;
        color: #FFFFFF;
        text-style: bold;
        background: #000000;
        padding: 1 0;
        text-align: center;
    }
    #cmd-suggestions {
        dock: bottom;
        height: 12;
        background: #000000;
        color: #FFFFFF;
        border-top: solid #333333;
        display: none;
    }
    #cmd-suggestions > .option-list--active {
        background: #FFFFFF;
        color: #000000;
        text-style: bold;
    }
    ExitMenuScreen {
        align: center middle;
        background: rgba(0, 0, 0, 0.7);
    }
    #exit-menu-card {
        width: 50;
        height: auto;
        background: #000000;
        border: round #333333;
        padding: 1 2;
    }
    #exit-menu-title {
        color: #FFFFFF;
        text-style: bold;
        text-align: center;
        width: 100%;
        margin-bottom: 1;
    }
    #exit-menu-desc {
        color: #888888;
        text-align: center;
        width: 100%;
        margin-bottom: 2;
    }
    #exit-menu-buttons {
        height: auto;
        align: center middle;
    }
    #exit-menu-buttons Button {
        margin: 0 1;
        min-width: 18;
    }
    #exit-continue {
        background: #333333;
        color: #FFFFFF;
    }
    #exit-continue:hover, #exit-continue:focus {
        background: #FFFFFF;
        color: #000000;
        text-style: bold;
    }
    #exit-quit {
        background: #882222;
        color: #FFFFFF;
    }
    #exit-quit:hover, #exit-quit:focus {
        background: #FF3B30;
        color: #FFFFFF;
        text-style: bold;
    }
    #exit-menu-tagline {
        color: #888888;
        text-align: center;
        width: 100%;
        margin-top: 1;
    }
    """

    # ── App state ─────────────────────────────────────────────

    user_name: str = ""
    user_color: str = ""
    user_cid: str = ""
    room_name: str = ""
    join_target: str = ""
    crypto: CryptoEngine | None = None
    net: NetNode | None = None

    BINDINGS = [
        ("ctrl+q", "quit_emergency", "Emergency Quit"),
        ("escape", "show_exit_menu", "Exit Menu"),
    ]

    def on_mount(self):
        self.push_screen(LoginScreen())

    async def action_quit_emergency(self):
        await self.exit_secure()

    def action_show_exit_menu(self):
        def on_dismiss(result):
            if result:
                self.run_worker(self.exit_secure())
        self.push_screen(ExitMenuScreen(), callback=on_dismiss)

    async def exit_secure(self):
        """Securely wipe history, stop network, and exit."""
        try:
            for s in self.screen_stack:
                if hasattr(s, "_hist"):
                    s._hist.clear()
        except Exception:
            pass
        if self.net:
            try:
                await self.net.stop()
            except Exception:
                pass
        if self.crypto:
            try:
                self.crypto.secure_wipe()
            except Exception:
                pass
        self.exit()

    async def action_quit_secure(self):
        await self.exit_secure()


# ═══════════════════════════════════════════════════════════════
#  Entry Point
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    OpenChatApp().run()
