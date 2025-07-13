import datetime

def generate_html_report(issues_dict, code_files):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    report = [f"<html><head><title>PyGuard Security Report</title></head><body>"]
    report.append(f"<h1>PyGuard Security Report</h1>")
    report.append(f"<p><b>Generated:</b> {now}</p>")

    for fname, issues in issues_dict.items():
        report.append(f"<hr><h2>File: {fname}</h2>")
        if not issues:
            report.append("<p style='color:green'><b>No vulnerabilities detected.</b></p>")
        else:
            report.append(f"<table border='1' cellpadding='4' cellspacing='0'>")
            report.append("<tr style='background:#f3f3f3'><th>Type</th><th>Line</th><th>Severity</th><th>Message</th><th>Remediation</th></tr>")
            for issue in issues:
                color = {"LOW":"#e2f7e2", "MEDIUM":"#fff3cd", "HIGH":"#f8d7da"}.get(issue['severity'], "#f0f0f0")
                report.append(
                    f"<tr style='background:{color}'>"
                    f"<td>{issue['type']}</td>"
                    f"<td>{issue['line']}</td>"
                    f"<td>{issue['severity']}</td>"
                    f"<td>{issue['message']}</td>"
                    f"<td>{issue['remediation']}</td>"
                    "</tr>"
                )
            report.append("</table>")
        # Show code with findings marked
        code_html = highlight_code_for_report(code_files[fname], [iss['line'] for iss in issues])
        report.append(f"<h3>Source Code</h3>{code_html}")

    report.append("</body></html>")
    return "\n".join(report)

def highlight_code_for_report(code, highlight_lines=None):
    """
    Returns HTML for code block with specified lines highlighted.
    """
    from pygments import highlight
    from pygments.lexers import PythonLexer
    from pygments.formatters import HtmlFormatter

    if not highlight_lines:
        highlight_lines = []
    formatter = HtmlFormatter(linenos=True, hl_lines=highlight_lines, full=False, cssclass="highlight")
    style = f"<style>{formatter.get_style_defs('.highlight')}</style>"
    highlighted = highlight(code, PythonLexer(), formatter)
    return style + highlighted
