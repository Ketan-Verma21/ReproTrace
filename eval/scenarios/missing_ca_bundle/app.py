"""Fails when the system CA bundle is missing (no TLS connection needed)."""

import ssl

loaded = ssl.create_default_context().cert_store_stats()["x509_ca"]
if loaded == 0:
    raise SystemExit("no CA certificates loaded: HTTPS verification would fail")
print(f"{loaded} CA certificates loaded")
