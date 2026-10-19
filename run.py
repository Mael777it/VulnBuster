#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marcin Lewandowski <marcin.lewandowski.x@gmail.com>
"""VulnBuster — uruchomienie serwera.

  python run.py [--host 127.0.0.1] [--port 8443] [--data data/vulnbuster.json.enc]
                [--cert cert.pem --key key.pem] [--log logs/vulnbuster.log]
"""
import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

p = argparse.ArgumentParser(description="VulnBuster — zarządzanie podatnościami (on-prem)")
p.add_argument("--host", default=os.environ.get("VULNBUSTER_HOST", "127.0.0.1"))
p.add_argument("--port", type=int, default=int(os.environ.get("VULNBUSTER_PORT", "8443")))
p.add_argument("--data", default=os.environ.get("VULNBUSTER_DATA", os.path.join("data", "vulnbuster.json.enc")))
p.add_argument("--cert", default=os.environ.get("VULNBUSTER_CERT"))
p.add_argument("--key", default=os.environ.get("VULNBUSTER_KEY"))
p.add_argument("--log", default=os.environ.get("VULNBUSTER_LOG"),
               help="plik logu (przydatne przy uruchomieniu jako zadanie/usługa)")
p.add_argument("--quiet", action="store_true", help="nie loguj każdego żądania HTTP")
a = p.parse_args()

if a.log:
    os.makedirs(os.path.dirname(os.path.abspath(a.log)), exist_ok=True)
    f = open(a.log, "a", encoding="utf-8", buffering=1)
    sys.stdout = sys.stderr = f
if a.quiet:
    os.environ["VULNBUSTER_QUIET"] = "1"

from vulnbuster.server import serve  # noqa: E402

os.makedirs(os.path.dirname(os.path.abspath(a.data)), exist_ok=True)
if a.host not in ("127.0.0.1", "localhost", "::1") and not a.cert:
    print("UWAGA: nasłuch na interfejsie sieciowym bez TLS. Użyj --cert/--key albo reverse proxy z HTTPS.")
serve(a.data, a.host, a.port, a.cert, a.key)
