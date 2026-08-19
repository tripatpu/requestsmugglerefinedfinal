# Byte-exact raw request pack

These `.raw` files are HTTP request-smuggling PoCs written with **exact bytes and
Windows CRLF line endings**, so they open cleanly in Notepad++ and can be pasted
into Burp Repeater as a raw request.

> Authorised targets only. A hang on a `_detect` request is **not** proof of a
> vulnerability — it is very often front-end tarpitting. Real confirmation comes
> from the `_queue` request (see below).

## What's in here

- `NNN_<host>_<kind>_detect.raw` — the detection probe (expect a hang if the
  timing signal is real).
- `NNN_<host>_<kind>_queue.raw` — the **safe** response-queue confirmation
  request (smuggles a harmless `GET /sg-…-notfound`).
- `send_raw.py` — sends any `.raw` byte-exact and reports timing; supports
  `--proxy` to route through Burp.
- `INDEX.txt` — per-finding list with ready-to-run send commands.
- `PASTE_SAFETY.txt` — which `detect` files are safe to copy/paste vs which
  contain an intentional lone-LF mutation byte and must be sent byte-exact.

## Verify a file is well-formed (Notepad++)

1. Open the `.raw` in **Notepad++**.
2. **View → Show Symbol → Show All Characters.** Every line must end with a
   `CR LF` pair (Notepad++ shows it as a single `↵` glyph in Windows mode; with
   "Show All Characters" you'll see `CR` `LF`).
3. Bottom-right status bar should read **Windows (CR LF)**. If it says Unix (LF),
   the file was altered after generation — regenerate; don't hand-fix.
4. Each file's correct ending depends on its type (this is normal — do not
   "fix" it):

   | File type        | last visible chars        | last bytes (hex)              |
   |------------------|---------------------------|-------------------------------|
   | `TE.CL` _detect  | `0` then a blank line     | `... 30 0d 0a 0d 0a`          |
   | `CL.TE` _detect  | `A` then `X` (no newline) | `... 31 0d 0a 41 0d 0a 58`    |
   | `TE.CL` _queue   | `0` then a blank line     | `... 30 0d 0a 0d 0a`          |
   | `CL.TE` _queue   | `x=` (no trailing newline)| `... 78 3d`                   |

   Rule of thumb: **CL.TE** requests end with the smuggled payload's last bytes
   (no trailing CRLF); **TE.CL** requests end with the `0␍␊␍␊` terminating chunk.
   The only universal check is that every line ends in CR LF and the status bar
   reads "Windows (CR LF)".

## Get it into Burp Repeater — three ways

### A) Notepad++ copy/paste (Windows clipboard preserves CRLF)
Use this only for files listed as paste-safe in `PASTE_SAFETY.txt`.

1. In Notepad++: `Ctrl+A`, `Ctrl+C`.
2. New Repeater tab → **Raw** view → select all → paste.
3. **Repeater menu → untick "Update Content-Length."** (Mandatory — the length
   is intentionally wrong.)
4. **Inspector → HTTP version → HTTP/1.**
5. Switch the editor to **Hex** and confirm the tail is `… 30 0d 0a 0d 0a`.
6. Send.

### B) Intercept-and-drop through Burp (byte-exact, nothing reaches the target)
Works for **every** file, including the 17 that aren't paste-safe.

1. Burp → **Proxy → Intercept ON**.
2. `python3 send_raw.py <host> <port> <file.raw> --proxy 127.0.0.1:8080`
3. Burp pauses on the request → **right-click → Send to Repeater** (`Ctrl+R`).
4. Click **Drop** so the original never reaches the target.
5. In the new Repeater tab: untick "Update Content-Length", force HTTP/1.1, send.

### C) No Burp — just observe the hang
```
python3 send_raw.py <host> <port> <file.raw>
# through Burp instead:
python3 send_raw.py <host> <port> <file.raw> --proxy 127.0.0.1:8080
```

## Confirming a real vulnerability (this is the part that matters)

A `_detect` hang alone is inconclusive. To confirm:

1. Send the matching `_queue.raw` (note the `/sg-XXXXXX-notfound` path inside it).
2. Immediately send **one normal request** to the same host on a **new
   connection** (e.g. `GET /` in a separate Repeater tab).
3. If that follow-up comes back as a **404 for the smuggled `/sg-…` path** (not
   for `/`), the response queue is desynchronised — that's a real finding.
4. If the follow-up is a normal `200`/expected response, the `_detect` hang was
   a false positive (front-end tarpit). Expect this for most hosts.

## Common pitfalls

- **"Update Content-Length" left on** → Burp rewrites the malformed length and
  the test silently fails. Turn it off.
- **Sent over HTTP/2** → Burp re-frames the request; smuggling disappears. Force
  HTTP/1.1.
- **Edited in an editor that trims trailing newlines** → the terminating chunk
  breaks. Don't hand-edit; regenerate.
- **Pasting a non-paste-safe file** → the lone-LF mutation byte is altered by the
  clipboard. Use method B for those (see `PASTE_SAFETY.txt`).
