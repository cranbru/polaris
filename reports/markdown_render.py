"""
Markdown rendering utility for POLARIS reports.
Converts structured LLM markdown analysis into clean, celestial-styled HTML.
"""

import html
import re


def render_ai_markdown_to_html(md_text: str) -> str:
    """Convert forensic LLM Markdown synthesis into structured, styled HTML."""
    if not md_text:
        return ""

    lines = md_text.splitlines()
    html_lines = []
    in_list = False
    in_sublist = False

    def close_lists():
        nonlocal in_list, in_sublist
        res = []
        if in_sublist:
            res.append("</ul></li>")
            in_sublist = False
        if in_list:
            res.append("</ul>")
            in_list = False
        return res

    for line in lines:
        stripped = line.strip()
        if not stripped:
            html_lines.extend(close_lists())
            continue

        # Check for headings
        if stripped.startswith("### "):
            html_lines.extend(close_lists())
            title = _format_inlines(html.escape(stripped[4:]))
            html_lines.append(f'<h3 class="ai-heading">{title}</h3>')
            continue
        elif stripped.startswith("#### "):
            html_lines.extend(close_lists())
            title = _format_inlines(html.escape(stripped[5:]))
            html_lines.append(f'<h4 class="ai-subheading">{title}</h4>')
            continue
        elif stripped.startswith("## "):
            html_lines.extend(close_lists())
            title = _format_inlines(html.escape(stripped[3:]))
            html_lines.append(f'<h2 class="ai-main-heading">{title}</h2>')
            continue

        # Check for bullet points
        indent = len(line) - len(line.lstrip())
        is_bullet = stripped.startswith("* ") or stripped.startswith("- ")

        if is_bullet:
            content = _format_inlines(html.escape(stripped[2:]))
            if indent >= 4:
                if not in_sublist:
                    html_lines.append('<ul class="ai-sublist">')
                    in_sublist = True
                html_lines.append(f'<li class="ai-subitem">{content}</li>')
            else:
                if in_sublist:
                    html_lines.append("</ul></li>")
                    in_sublist = False
                if not in_list:
                    html_lines.append('<ul class="ai-list">')
                    in_list = True
                html_lines.append(f'<li class="ai-item">{content}</li>')
            continue

        # Regular text / paragraph
        html_lines.extend(close_lists())
        formatted_line = _format_inlines(html.escape(stripped))
        html_lines.append(f'<p class="ai-paragraph">{formatted_line}</p>')

    html_lines.extend(close_lists())
    return "\n".join(html_lines)


def _format_inlines(escaped_text: str) -> str:
    # Forensic callout tags
    escaped_text = re.sub(
        r"\*\*OBSERVED:\*\*",
        '<span class="badge badge-info ai-badge">OBSERVED</span>',
        escaped_text,
    )
    escaped_text = re.sub(
        r"\*\*INFERRED:\*\*",
        '<span class="badge badge-medium ai-badge">INFERRED</span>',
        escaped_text,
    )
    escaped_text = re.sub(
        r"\*\*UNCONFIRMED:\*\*",
        '<span class="badge badge-low ai-badge">UNCONFIRMED</span>',
        escaped_text,
    )
    escaped_text = re.sub(
        r"\*\*HYPOTHESIS:\*\*",
        '<span class="badge badge-high ai-badge">HYPOTHESIS</span>',
        escaped_text,
    )
    escaped_text = re.sub(
        r"\*\*CONFIDENCE:\*\*\s*(Low|Medium|High|Confirmed)",
        r'<span class="badge badge-info ai-badge">CONFIDENCE: \1</span>',
        escaped_text,
        flags=re.IGNORECASE,
    )

    # Inline code: `code`
    escaped_text = re.sub(r"`([^`]+)`", r'<code class="ai-inline-code">\1</code>', escaped_text)

    # Bold: **text**
    escaped_text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", escaped_text)

    # Italic: *text*
    escaped_text = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"<em>\1</em>", escaped_text)

    return escaped_text
