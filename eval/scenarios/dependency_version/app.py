"""Requires major version 2 of the installed 'mylib' distribution."""

from importlib.metadata import version

found = version("mylib")
if not found.startswith("2."):
    raise SystemExit(f"mylib {found} installed, 2.x required")
print("mylib", found)
