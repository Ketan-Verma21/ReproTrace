"""Low-level helpers for strace's argument syntax: strings, brackets, fd annotations."""

import re

_CLOSERS = {"(": ")", "[": "]", "{": "}"}
_FD_ANNOTATION = re.compile(r"^(?:-?\d+|AT_FDCWD)<(?P<path>.*)>$", re.DOTALL)
_ESCAPE = re.compile(r"\\(x[0-9a-fA-F]{2}|[0-7]{1,3}|.)", re.DOTALL)
_SIMPLE_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "v": "\v", "f": "\f", "\\": "\\", '"': '"'}


_SPECIAL = re.compile(r'["()\[\]{}<>,]')
_STRING_REST = re.compile(r'(?:[^"\\]|\\.)*"', re.DOTALL)


def skip_string(text: str, start: int) -> int:
    """Return the index just after the string literal opening at ``start``.

    Returns ``len(text)`` if the string is never closed (a malformed line).
    """
    match = _STRING_REST.match(text, start + 1)
    return match.end() if match else len(text)


def _opens_fd_annotation(text: str, index: int) -> bool:
    # strace -y writes "3</etc/hosts>" and "AT_FDCWD</tmp>"; a '<' right after a word
    # character starts such an annotation, which may itself contain ',' or ')'.
    return index > 0 and (text[index - 1].isalnum() or text[index - 1] == "_")


def _scan(text: str, start: int, stop_at_close: bool) -> tuple[list[int], int | None]:
    """Find top-level commas and, if ``stop_at_close``, the closing ')' of a call.

    Jumps between bracket, quote, and comma characters with a regex because execve
    environments and struct arguments make per-character loops slow.
    """
    commas: list[int] = []
    stack: list[str] = []
    pos = start
    while (match := _SPECIAL.search(text, pos)) is not None:
        i = match.start()
        char = text[i]
        if char == '"':
            pos = skip_string(text, i)
            continue
        if char == "<":
            if _opens_fd_annotation(text, i):
                stack.append(">")
        elif char in _CLOSERS:
            stack.append(_CLOSERS[char])
        elif stack and char == stack[-1]:
            stack.pop()
        elif not stack:
            if char == ",":
                commas.append(i)
            elif char == ")" and stop_at_close:
                return commas, i
        pos = i + 1
    return commas, None


def _split_at(text: str, start: int, end: int, commas: list[int]) -> list[str]:
    bounds = [start - 1, *commas, end]
    args = [text[bounds[k] + 1 : bounds[k + 1]].strip() for k in range(len(bounds) - 1)]
    if args == [""]:
        return []
    return args


def scan_call_args(text: str, start: int) -> tuple[list[str], int] | None:
    """Split a call's arguments starting at ``start``; return them and the closing ')'."""
    commas, end = _scan(text, start, stop_at_close=True)
    if end is None:
        return None
    return _split_at(text, start, end, commas), end


def split_args(text: str) -> list[str]:
    """Split an argument list on top-level commas, respecting strings and brackets."""
    commas, _ = _scan(text, 0, stop_at_close=False)
    return _split_at(text, 0, len(text), commas)


def _decode_escape(match: re.Match[str]) -> str:
    code = match.group(1)
    if code in _SIMPLE_ESCAPES:
        return _SIMPLE_ESCAPES[code]
    if code.startswith("x") and len(code) == 3:
        return chr(int(code[1:], 16))
    if code.isdigit() and all(c in "01234567" for c in code):
        return chr(int(code, 8))
    return code


def unquote(arg: str) -> tuple[str, bool] | None:
    """Decode a strace string literal.

    Returns ``(value, truncated)`` where ``truncated`` is True when strace cut the string
    (it appends ``...`` after the closing quote), or None if ``arg`` is not a string.
    """
    if not arg.startswith('"'):
        return None
    end = skip_string(arg, 0)
    body = arg[1 : end - 1] if end <= len(arg) and arg[end - 1] == '"' else arg[1:end]
    truncated = arg[end:].startswith("...")
    return _ESCAPE.sub(_decode_escape, body), truncated


def fd_path(arg: str) -> str | None:
    """Return the path from an fd annotation such as ``3</etc/hosts>``, if present."""
    match = _FD_ANNOTATION.match(arg.strip())
    return match.group("path") if match else None
