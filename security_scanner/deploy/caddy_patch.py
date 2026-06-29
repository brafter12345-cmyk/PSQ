#!/usr/bin/env python3
"""Wire the Phishield scanner sub-path mount into an existing Caddyfile site block.

Inserts a `/scanner/*` reverse-proxy (to localhost:8001, with X-Forwarded-Prefix) right
after the site's `encode` line. Idempotent (bails if already present) and safe (backs up
first; run `caddy validate` before reloading). Run with sudo on the VM:

    sudo python3 caddy_patch.py
    sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
    sudo systemctl reload caddy

See security_scanner/docs/DEPLOYMENT.md §1 for how the prefix mount works.
"""
import re
import shutil
import sys
import time

CADDYFILE = "/etc/caddy/Caddyfile"
MARKER = "Phishield CyberRisk Scanner"

BLOCK = """\
    # --- Phishield CyberRisk Scanner (interim sub-path mount) --------------------
    # Flask+React app on localhost:8001, mounted under /scanner. handle_path strips
    # the /scanner prefix; X-Forwarded-Prefix makes the app emit /scanner URLs.
    redir /scanner /scanner/ permanent
    handle_path /scanner/* {
        reverse_proxy localhost:8001 {
            header_up X-Forwarded-Prefix /scanner
        }
    }
    # ---------------------------------------------------------------------------
"""


def main() -> int:
    src = open(CADDYFILE).read()
    if MARKER in src:
        print("already patched; nothing to do")
        return 0

    # Insert after the first `encode ...` line (inside the target site block).
    anchor = re.search(r"^(\s*encode .*\n)", src, re.MULTILINE)
    if not anchor:
        print("ERROR: no `encode` anchor line found in Caddyfile", file=sys.stderr)
        return 2

    bak = f"{CADDYFILE}.bak-scanner-{int(time.time())}"
    shutil.copy2(CADDYFILE, bak)
    print("backup:", bak)

    idx = anchor.end()
    open(CADDYFILE, "w").write(src[:idx] + "\n" + BLOCK + src[idx:])
    print("inserted scanner block after:", anchor.group(1).strip())
    print("now run: sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile && sudo systemctl reload caddy")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
