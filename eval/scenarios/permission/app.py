"""Reads its configuration file."""

with open("/app/config.ini", encoding="utf-8") as handle:
    print(handle.read().strip())
