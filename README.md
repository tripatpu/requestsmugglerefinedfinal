# smuggle_scan — HTTP/1.1 + HTTP/2 Request Smuggling Scanner & PoC Forge

An advanced, threaded, memory-conscious scanner that detects HTTP request
smuggling (desync) vulnerabilities across a list of URLs and, for every
**confirmed** finding, writes a pack of **raw HTTP requests** ready to paste
into **Burp Suite Repeater** — including weaponised proof-of-concepts for the
full range of smuggling-based attacks (front-end control bypass, capturing
other users' requests, reflected XSS, web cache poisoning, web cache deception,
and response-queue poisoning).

> ⚠️ **Authorised testing only.** This tool sends malformed requests that can
> disrupt a service and, if you run the weaponised PoCs, can affect other users
> of the target. Only use it against systems you own or have **explicit written
> permission** to test. You are responsible for staying in scope.

---

## Why this tool

Request smuggling happens when a front-end (CDN / load balancer / reverse proxy)
and a back-end server disagree about where one HTTP request ends and the next
begins. That disagreement lets an attacker prepend bytes to the *next* person's
request. Detection is subtle and noisy, so this scanner is built around three
goals you asked for:

* **Thorough coverage** — HTTP/1.1 `CL.TE` and `TE.CL` across 27 Transfer-Encoding
  obfuscations, **plus** HTTP/2→1.1 downgrade desync (`H2.CL`, `H2.TE`,
  `H2.CRLF`).
* **Low false positives** — a multi-stage timing gate (baseline → attack hang →
  self-consistent control must be fast → attack hang must reproduce), with an
  optional content-based **differential-response confirmation**.
* **Threaded & memory-optimised** — a bounded thread pool fans out across hosts
  (requests to a single host stay serialised for clean timing and politeness),
  responses are capped, and the URL list is streamed rather than slurped.

---

## Detection techniques

### HTTP/1.1 timing desync
For each Transfer-Encoding mutation the scanner sends a probe crafted so that a
**vulnerable** server stalls a socket (one component waits for bytes the other
never forwards) while a **safe** server answers immediately.

* **CL.TE** — front-end honours `Content-Length`, back-end honours
  `Transfer-Encoding`. The probe forwards a partial chunk; the back-end waits
  for a chunk terminator that never arrives → **hang**.
* **TE.CL** — front-end honours `Transfer-Encoding`, back-end honours
  `Content-Length`. The probe completes the chunked body but sets a larger
  `Content-Length`; the back-end waits for the missing byte → **hang**.

**False-positive controls.** A raw hang is not enough. Each candidate must:
1. hang on the attack probe, **and**
2. return **fast** on a self-consistent *control* (proves the host is
   responsive, so the hang is specific to the malformed framing), **and**
3. **reproduce** the hang on a second attempt (rejects one-off network jitter).

Add `--diff-confirm` to also run the PortSwigger differential technique: a benign
`GET` to a random non-existent path is smuggled, and a follow-up request is
checked for the resulting 404/400/405 signature. When it corroborates, the
finding is promoted to `high` confidence.

### HTTP/2 → HTTP/1.1 downgrade desync
Many edge servers accept HTTP/2 from clients but speak HTTP/1.1 to the origin.
If the rewrite is sloppy, HTTP/2's exact-length framing can be subverted. Using
the `h2` library **with outbound validation disabled**, the scanner injects
constructs a compliant server must reject:

* **H2.TE** — smuggle a `transfer-encoding: chunked` header (must be stripped).
* **H2.CL** — declare `content-length: 0` while sending a non-empty body whose
  bytes become a smuggled request after downgrade.
* **H2.CRLF** — embed `\r\n` in a header value to split out a new request line
  once the message is serialised to HTTP/1.1.

H2 findings are corroborated by a stall or an anomalous stream reset / 400-class
status versus an HTTP/2 baseline, and are labelled `low`/`medium` — always
verify them manually (see limitations).

---

## Installation

```bash
python3 -m pip install h2            # only needed for HTTP/2 tests
# (standard library covers everything else)
```

Python 3.8+. If `h2` is not installed the tool still runs; it just skips the
HTTP/2 tests and tells you.

---

## Usage

```bash
# Single target
python3 smuggle_scan.py -u https://target.example --authorize

# A list of URLs (one per line; scheme optional, defaults to https)
python3 smuggle_scan.py -l urls.txt --authorize -o poc.txt -j findings.json

# Thorough run with content-based confirmation, 20 workers
python3 smuggle_scan.py -l urls.txt --authorize --diff-confirm -w 20 -v
```

`--authorize` asserts you have permission (otherwise it prompts). Without it,
nothing is scanned.

### Key flags

| Flag | Default | Meaning |
|------|---------|---------|
| `-u, --url` / `-l, --list` | — | single URL / file of URLs |
| `-o, --poc` | `smuggle_poc.txt` | Burp-ready PoC pack |
| `-j, --json` | `smuggle_findings.json` | machine-readable results |
| `-w, --workers` | `10` | concurrent hosts |
| `--timeout` | `10` | connect / baseline socket timeout (s) |
| `--attack-timeout` | `8` | read timeout for attack probes; a hang ≈ this |
| `--min-hang` | `5` | minimum stall (s) treated as a hang |
| `--hang-factor` | `6` | hang if attack ≥ baseline × factor |
| `--baseline-samples` | `3` | baseline timing samples (min taken) |
| `--delay` | `0.15` | polite delay between requests to one host (s) |
| `--max-response-bytes` | `8192` | cap bytes read per response (memory bound) |
| `--diff-confirm` | off | add differential-response confirmation |
| `--min-confidence` | `medium` | only report at/above this level (`low`/`medium`/`high`); suppresses timing/heuristic noise |
| `--raw-dir DIR` | — | also write byte-exact `.raw` files (guaranteed CRLF) + `send_raw.py` + `INDEX.txt`/`PASTE_SAFETY.txt` |
| `--no-http2` | off | disable HTTP/2 downgrade tests |
| `--stop-on-first` | off | stop a host after its first finding |
| `--insecure` | on | ignore TLS cert errors (common when scanning) |

### Byte-exact `.raw` export and Burp

`--raw-dir out/` writes each detection PoC as a standalone `.raw` file with
**Windows CRLF** and no length rewriting, so the exact bytes survive to the wire
(clipboards, editors and MCP channels all tend to strip the `\r`). Each finding
gets a `_detect.raw` (the probe) and a `_queue.raw` (the safe response-queue
confirmation), plus:

- `send_raw.py` — sends a `.raw` byte-exact and reports timing.
  `--proxy HOST:PORT` tunnels through Burp (CONNECT) so you can
  **intercept → Send to Repeater → Drop** and get a byte-exact request into
  Repeater without the request ever reaching the target.
- `PASTE_SAFETY.txt` — lists which `_detect` files are safe to copy/paste from
  Notepad++ vs which contain an intentional lone-LF mutation byte and must be
  delivered byte-exact (`--proxy`/`send_raw.py`).
- `RAW_README.md` — step-by-step Notepad++ + Repeater instructions.

A `_detect` hang is **not** proof — confirm with the `_queue` request plus a
normal follow-up (look for the smuggled `/sg-…` 404).

---

## Output

### `smuggle_findings.json`
An array of findings, each with the target, `kind` (`CL.TE`/`TE.CL`/`H2.*`),
channel, mutation, confidence, timing evidence, and the base64 of the exact
detection request.

### `smuggle_poc.txt` — the evidence pack
Per confirmed finding it emits:

* **Detection request** — the exact probe, shown human-readably (with `\r\n`
  made visible) **and** as base64 for byte-perfect replay of unusual bytes.
* **ATTACK A — Front-end control bypass** — reach `/admin` (or any path the edge
  blocks) via the back-end.
* **ATTACK B — Capture another user's request** — oversized `Content-Length` so
  the next visitor's request (cookies, tokens) is appended into a sink you read.
* **ATTACK C — Reflected XSS via smuggling** — inject script into the next
  victim's response; each PoC carries a unique marker to grep for.
* **ATTACK D — Web cache poisoning** — targets a **unique canary path** so a real
  user URL is never poisoned during verification.
* **ATTACK E — Web cache deception** — trick the cache into storing a private
  page (verify only with your own second account).
* **ATTACK F — Response-queue poisoning** — the **safest live confirmation**: a
  harmless smuggled request to a non-existent path desynchronises the response
  queue, provable with a single follow-up.
* **ATTACK G — HTTP/2 downgrade weaponisation** — H2-specific notes and the
  smuggled inner request, for findings on the HTTP/2 channel.

### Using the pack in Burp Repeater
1. Paste a raw request into a Repeater tab.
2. **Uncheck “Update Content-Length”** (Repeater menu) — the lengths are
   deliberately malformed and Burp must not rewrite them.
3. Force **HTTP/1.1** for the H1 PoCs (Inspector → request attributes); use the
   HTTP/2 tab / Inspector for the H2 PoCs.
4. For bytes shown as `\r\n`, `\x0b`, `\x00`, decode the provided base64 and
   paste via Burp’s hex view to preserve them exactly.
5. Most attacks require sending the request **twice** (attacker prime + victim
   request). Turbo Intruder automates the race window.

---

## How false positives are minimised (summary)

* Baseline must succeed and be fast, or the host is skipped.
* Attack must hang, control must be fast, and the hang must reproduce.
* Optional differential-response check adds an independent, content-based signal.
* HTTP/2 findings require a reproduced stall or reset/400-class anomaly vs an
  HTTP/2 baseline.

No heuristic is perfect; treat every finding as a lead to confirm in Burp, not a
guaranteed exploit.

---

## Limitations & honest caveats

* **Timing is probabilistic.** On very slow or heavily load-balanced targets,
  tune `--attack-timeout`, `--min-hang`, and `--hang-factor`. A front-end that
  itself speaks chunked can occasionally hang on the CL.TE probe — the Burp step
  is where you nail down the exact variant.
* **HTTP/2 detection is best-effort.** Faithful downgrade-desync confirmation
  often needs the actual downgraded bytes, which the client can’t observe. H2
  findings are flagged `low`/`medium` and must be manually verified.
* **Connection-level desync only.** This build focuses on classic and downgrade
  desync; it does not implement client-side desync (browser-powered) or every
  exotic parser quirk. Extending the mutation matrix is straightforward.
* **Impact PoCs touch shared state.** ATTACKS B/D/E can affect other users; use
  canaries and your own accounts, and prefer ATTACK F for live confirmation.

---

## Remediation (share with the target’s owners)

* Make the front-end and back-end agree on one, unambiguous framing; **reject**
  any request containing both `Content-Length` and `Transfer-Encoding`, or a
  malformed/duplicated `Transfer-Encoding`.
* Prefer **HTTP/2 end-to-end**; if you must downgrade, validate and re-serialise
  strictly, stripping `transfer-encoding` and rejecting header CRLF.
* Normalise/close ambiguous connections; enable back-end connection isolation.
* Further reading: PortSwigger Web Security Academy — *HTTP request smuggling*
  and *HTTP/2* topics.

---

## Files

* `smuggle_scan.py` — the scanner + PoC forge (single file, stdlib + optional `h2`).
* `mock_server.py` — a local mock origin used to self-test the detection logic.
* `urls.txt` — example target list.

## Responsible disclosure

If you find a real vulnerability, report it privately to the operator or via
their bug-bounty program, include the minimal PoC, and give them reasonable time
to remediate before any public discussion.
