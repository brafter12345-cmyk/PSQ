#!/usr/bin/env python3
"""Wire the SME Rating Engine sub-path mount into the existing Caddyfile.

Inserts a `/smerating/*` reverse-proxy (to localhost:8002) into the
`veilguard.phishield.com` site block, right after its `encode` line. Unlike the
scanner, NO `X-Forwarded-Prefix` is sent: `handle_path` strips `/smerating`, the
React bundle is built with base=/smerating/, and the frontend's one API call is
base-aware, so the app runs at the web root and needs no prefix awareness.

Idempotent (bails if already present), safe (backs up + you validate). Run with
sudo on the VM:

    sudo python3 caddy_patch_sme.py
    sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
    sudo systemctl reload caddy
"""
import re
import shutil
import sys
import time

CADDYFILE = "/etc/caddy/Caddyfile"
MARKER = "Phishield SME Rating Engine"

BLOCK = """\
    # --- Phishield SME Rating Engine (sub-path mount) ---------------------------
    # Flask+React app on localhost:8002, mounted under /smerating. handle_path
    # strips the /smerating prefix; the app runs at the web root (base-path build
    # + base-aware fetch mean no X-Forwarded-Prefix is needed).
    redir /smerating /smerating/ permanent
    handle_path /smerating/* {
        reverse_proxy localhost:8002
    }
    # ---------------------------------------------------------------------------
"""


def main() -> int:
    src = open(CADDYFILE).read()
    if MARKER in src:
        print("already patched; nothing to do")
        return 0

    anchor = re.search(r"^(\s*encode .*\n)", src, re.MULTILINE)
    if not anchor:
        print("ERROR: no `encode` anchor line found in Caddyfile", file=sys.stderr)
        return 2

    bak = f"{CADDYFILE}.bak-sme-{int(time.time())}"
    shutil.copy2(CADDYFILE, bak)
    print("backup:", bak)

    idx = anchor.end()
    open(CADDYFILE, "w").write(src[:idx] + "\n" + BLOCK + src[idx:])
    print("inserted SME block after:", anchor.group(1).strip())
    print("now run: sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile && sudo systemctl reload caddy")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
