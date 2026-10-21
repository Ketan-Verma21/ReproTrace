"""Loads settings from a file next to the application."""

with open("/app/settings.toml", encoding="utf-8") as handle:
    print(handle.read().strip())
