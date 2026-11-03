"""A small document model for reports, written out as Markdown or as standalone HTML.

The report is built once as blocks (headings, paragraphs, lists, code, tables) of inline
segments (text, code, bold, severity), so both formats carry exactly the same content and
each writer does its own escaping (PRD FR-19).
"""

import html
from dataclasses import dataclass, field

# --- inline segments ------------------------------------------------------------------


@dataclass(frozen=True)
class Text:
    text: str


@dataclass(frozen=True)
class Code:
    text: str


@dataclass(frozen=True)
class Strong:
    text: str


@dataclass(frozen=True)
class Severity:
    """CRITICAL, WARNING or INFO: bold in Markdown, a colored label in HTML."""

    level: str


Inline = Text | Code | Strong | Severity
Inlines = list[Inline]


def t(text: str) -> Inlines:
    """Shorthand for a run of plain text."""
    return [Text(text)]


# --- blocks ---------------------------------------------------------------------------


@dataclass
class Heading:
    level: int
    content: Inlines


@dataclass
class Paragraph:
    content: Inlines
    muted: bool = False


@dataclass
class Quote:
    content: Inlines


@dataclass
class Item:
    content: Inlines
    children: list[Inlines] = field(default_factory=list)


@dataclass
class Bullets:
    items: list[Item]


@dataclass
class CodeBlock:
    lines: list[str]


@dataclass
class Table:
    header: list[Inlines]
    rows: list[list[Inlines]]


@dataclass
class Rule:
    pass


Block = Heading | Paragraph | Quote | Bullets | CodeBlock | Table | Rule


# --- Markdown -------------------------------------------------------------------------


def _md_escape(text: str) -> str:
    """Placeholders like <cwd> would otherwise render as HTML tags in Markdown viewers."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _md_inline(content: Inlines, in_table: bool = False) -> str:
    def cell(text: str) -> str:
        return text.replace("|", "\\|").replace("\n", " ") if in_table else text

    parts = []
    for seg in content:
        if isinstance(seg, Text):
            parts.append(cell(_md_escape(seg.text)))
        elif isinstance(seg, Code):
            parts.append(f"`{cell(_md_escape(seg.text) if in_table else seg.text)}`")
        elif isinstance(seg, Strong):
            parts.append(f"**{cell(_md_escape(seg.text))}**")
        else:
            parts.append(seg.level if in_table else f"**{seg.level}**")
    return "".join(parts)


def _md_block(block: Block) -> list[str]:
    if isinstance(block, Heading):
        return [f"{'#' * block.level} {_md_inline(block.content)}"]
    if isinstance(block, Paragraph):
        return [_md_inline(block.content)]
    if isinstance(block, Quote):
        return [f"> {_md_inline(block.content)}"]
    if isinstance(block, Bullets):
        lines = []
        for item in block.items:
            lines.append(f"- {_md_inline(item.content)}")
            lines += [f"  - {_md_inline(child)}" for child in item.children]
        return lines
    if isinstance(block, CodeBlock):
        return ["```text", *block.lines, "```"]
    if isinstance(block, Table):
        row = lambda cells: "| " + " | ".join(_md_inline(c, True) for c in cells) + " |"  # noqa: E731
        return [row(block.header), "|" + "---|" * len(block.header), *map(row, block.rows)]
    return ["---"]


def to_markdown(blocks: list[Block]) -> str:
    """Markdown: one blank line between blocks, newline at the end."""
    lines: list[str] = []
    for block in blocks:
        lines += _md_block(block)
        lines.append("")
    return "\n".join(lines[:-1]) + "\n"


# --- HTML -----------------------------------------------------------------------------

# Design.md 2 and 3: semantic colors (light/dark), system fonts, no downloads.
_CSS = """
:root {
  --bg: #FFFFFF; --surface: #F9FAFB; --border: #EAECF0; --text: #101828; --code-bg: #F2F4F7;
  --critical: #B42318; --warning: #B54708; --info: #175CD3; --success: #067647;
  --muted: #667085; --accent: #101828;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0F1419; --surface: #171C23; --border: #2A313B; --text: #F2F4F7; --code-bg: #1D242D;
    --critical: #F97066; --warning: #FDB022; --info: #53B1FD; --success: #47CD89;
    --muted: #98A2B3; --accent: #F2F4F7;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font-family: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  font-size: 16px; line-height: 1.6;
}
main { max-width: 960px; margin: 0 auto; padding: 32px 16px 48px; }
h1 { font-size: 28px; font-weight: 700; line-height: 1.25; margin: 0 0 16px; color: var(--accent); }
h2 { font-size: 20px; font-weight: 600; margin: 40px 0 12px; padding-top: 16px;
     border-top: 1px solid var(--border); color: var(--accent); }
h3 { font-size: 17px; font-weight: 600; margin: 28px 0 8px; color: var(--accent);
     overflow-wrap: anywhere; }
p, ul { margin: 0 0 12px; }
ul { padding-left: 22px; }
li { margin: 2px 0; overflow-wrap: anywhere; }
code, pre {
  font-family: ui-monospace, "JetBrains Mono", "Fira Code", Menlo, Consolas, monospace;
  font-size: 14px;
}
code { background: var(--code-bg); border-radius: 4px; padding: 1px 5px; overflow-wrap: anywhere; }
pre {
  background: var(--code-bg); border: 1px solid var(--border); border-radius: 8px;
  padding: 12px 14px; line-height: 1.5; overflow-x: auto; margin: 0 0 12px;
}
pre code { background: none; padding: 0; overflow-wrap: normal; }
blockquote {
  margin: 0 0 16px; padding: 12px 16px; background: var(--surface);
  border: 1px solid var(--border); border-left: 4px solid var(--warning); border-radius: 6px;
}
.table-wrap { overflow-x: auto; margin: 0 0 12px; border: 1px solid var(--border);
              border-radius: 8px; }
table { border-collapse: collapse; width: 100%; min-width: 640px; font-size: 14px; }
th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--border);
         vertical-align: top; }
th { background: var(--surface); font-weight: 600; white-space: nowrap; }
td { overflow-wrap: anywhere; }
td code { white-space: nowrap; overflow-wrap: normal; }
tr:last-child td { border-bottom: none; }
.sev { font-weight: 700; font-size: 13px; letter-spacing: 0.02em; white-space: nowrap; }
.sev-CRITICAL { color: var(--critical); }
.sev-WARNING { color: var(--warning); }
.sev-INFO { color: var(--info); }
.muted, hr + p { color: var(--muted); font-size: 13px; }
hr { border: none; border-top: 1px solid var(--border); margin: 40px 0 12px; }
"""


def _html_inline(content: Inlines) -> str:
    parts = []
    for seg in content:
        if isinstance(seg, Text):
            parts.append(html.escape(seg.text, quote=False))
        elif isinstance(seg, Code):
            parts.append(f"<code>{html.escape(seg.text, quote=False)}</code>")
        elif isinstance(seg, Strong):
            parts.append(f"<strong>{html.escape(seg.text, quote=False)}</strong>")
        else:
            level = html.escape(seg.level)
            parts.append(f'<span class="sev sev-{level}">{level}</span>')
    return "".join(parts)


def _html_block(block: Block) -> str:
    if isinstance(block, Heading):
        return f"<h{block.level}>{_html_inline(block.content)}</h{block.level}>"
    if isinstance(block, Paragraph):
        css = ' class="muted"' if block.muted else ""
        return f"<p{css}>{_html_inline(block.content)}</p>"
    if isinstance(block, Quote):
        return f"<blockquote>{_html_inline(block.content)}</blockquote>"
    if isinstance(block, Bullets):
        items = []
        for item in block.items:
            inner = _html_inline(item.content)
            if item.children:
                kids = "".join(f"<li>{_html_inline(c)}</li>" for c in item.children)
                inner += f"<ul>{kids}</ul>"
            items.append(f"<li>{inner}</li>")
        return f"<ul>{''.join(items)}</ul>"
    if isinstance(block, CodeBlock):
        return f"<pre><code>{html.escape(chr(10).join(block.lines), quote=False)}</code></pre>"
    if isinstance(block, Table):
        head = "".join(f"<th>{_html_inline(c)}</th>" for c in block.header)
        rows = "".join(
            "<tr>" + "".join(f"<td>{_html_inline(c)}</td>" for c in row) + "</tr>"
            for row in block.rows
        )
        return (
            f'<div class="table-wrap"><table><thead><tr>{head}</tr></thead>'
            f"<tbody>{rows}</tbody></table></div>"
        )
    return "<hr>"


def to_html(blocks: list[Block], title: str) -> str:
    """A complete, self-contained HTML page (inline CSS, no scripts, no external files)."""
    body = "\n".join(_html_block(block) for block in blocks)
    return (
        "<!doctype html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        '<meta name="color-scheme" content="light dark">\n'
        f"<title>{html.escape(title)}</title>\n<style>{_CSS}</style>\n</head>\n"
        f"<body>\n<main>\n{body}\n</main>\n</body>\n</html>\n"
    )
