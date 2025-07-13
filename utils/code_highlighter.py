import pygments
from pygments import highlight
from pygments.lexers import PythonLexer
from pygments.formatters import HtmlFormatter

def highlight_code(code, highlight_line=None):
    """
    Highlight Python code with a specific line (or lines) highlighted.
    highlight_line can be an int (single line) or list of ints (multiple lines).
    """
    if not highlight_line:
        highlight_line = []
    elif isinstance(highlight_line, int):
        highlight_line = [highlight_line]
    formatter = HtmlFormatter(linenos=True, hl_lines=highlight_line, full=False, cssclass="highlight")
    highlighted = highlight(code, PythonLexer(), formatter)
    style = f"<style>{formatter.get_style_defs('.highlight')}</style>"
    return style + highlighted
