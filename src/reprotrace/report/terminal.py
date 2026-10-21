"""Terminal styling per Design.md: semantic styles, width cap, plain output when needed.

Colors never carry meaning alone: every styled status is also spelled out
(``[CRITICAL]``). Output is plain when ``NO_COLOR`` is set, ``--no-color`` is passed, or
stdout is not a terminal (pipes, CI logs).
"""

import os
import re
from collections.abc import Iterable

from rich.console import Console
from rich.text import Text

MAX_WIDTH = 100
MAX_TOKEN = 60

STYLES = {
    "critical": "bold red",
    "warning": "yellow",
    "info": "cyan",
    "success": "green",
    "muted": "dim",
    "accent": "bold",
}
SEVERITY_STYLES = {"CRITICAL": "critical", "WARNING": "warning", "INFO": "info"}

_LONG_TOKEN = re.compile(r"\S*/\S*")


def make_console(no_color: bool = False, stderr: bool = False) -> Console:
    """A console that honors NO_COLOR, --no-color and non-TTY output, capped at 100 columns."""
    plain = no_color or bool(os.environ.get("NO_COLOR"))
    console = Console(stderr=stderr, color_system=None if plain else "auto", highlight=False)
    if console.is_terminal and console.width > MAX_WIDTH:
        console = Console(
            stderr=stderr,
            color_system=None if plain else "auto",
            highlight=False,
            width=MAX_WIDTH,
        )
    return console


def print_lines(console: Console, lines: Iterable[Text | str]) -> None:
    """Print lines; in pipes and logs, never insert line breaks of our own."""
    for line in lines:
        console.print(line, soft_wrap=not console.is_terminal, markup=False)


def styled(text: str, role: str) -> Text:
    """``text`` in a Design.md role (critical, warning, info, success, muted, accent)."""
    return Text(text, style=STYLES[role])


def severity_label(severity: str) -> Text:
    """``[CRITICAL]`` etc., styled by severity."""
    return styled(f"[{severity}]", SEVERITY_STYLES.get(severity, "info"))


def shorten_middle(value: str, limit: int = MAX_TOKEN) -> str:
    """Shorten ``value`` to ``limit`` characters by cutting out its middle."""
    if len(value) <= limit:
        return value
    keep = limit - 3
    head = keep // 2
    return f"{value[:head]}...{value[-(keep - head) :]}"


def shorten_paths(text: str, limit: int = MAX_TOKEN) -> str:
    """Shorten long path-like words in ``text``; full paths stay in the report."""
    return _LONG_TOKEN.sub(lambda m: shorten_middle(m.group(0), limit), text)
