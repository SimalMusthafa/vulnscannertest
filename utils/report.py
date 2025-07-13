import datetime
from utils.vuln_patterns import VULN_KNOWLEDGE

def generate_html_report(issues_dict, code_files):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    sev_emoji = {'HIGH': '🚨 HIGH', 'MEDIUM': '⚠️ MEDIUM', 'LOW': '🟢 LOW'}
    sev_color = {'HIGH': '#431010', 'MEDIUM': '#292813', 'LOW': '#102c13'}
    sev_text = {'HIGH': '#ff4444', 'MEDIUM': '#ffe156', 'LOW': '#50fa7b'}

    # Compute summary
    summary = {}
    for issues in issues_dict.values():
        for iss in issues:
            s = iss['severity'].upper()
            summary[s] = summary.get(s, 0) + 1
    total_files = len(code_files)
    total_issues = sum(summary.values())
    total_lines = sum(len(c.splitlines()) for c in code_files.values())
    num_high = summary.get("HIGH", 0)
    num_med = summary.get("MEDIUM", 0)
    num_low = summary.get("LOW", 0)
    # Risk Badge
    if num_high:
        risk_badge = '<span style="background:#ff4444;color:#fff;border-radius:7px;padding:3px 10px;margin-right:7px;">🚨 HIGH RISK</span>'
    elif num_med:
        risk_badge = '<span style="background:#ffe156;color:#333;border-radius:7px;padding:3px 10px;margin-right:7px;">⚠️ Moderate Risk</span>'
    elif num_low:
        risk_badge = '<span style="background:#50fa7b;color:#222;border-radius:7px;padding:3px 10px;margin-right:7px;">🟢 Low Risk</span>'
    else:
        risk_badge = '<span style="background:#16cc72;color:#fff;border-radius:7px;padding:3px 10px;margin-right:7px;">✅ No Issues</span>'

    # TOC for files
    toc_links = []
    for fname in code_files:
        anchor = fname.replace(".", "-")
        toc_links.append(f'<li><a href="#{anchor}" style="color:#ffe156;">{fname}</a></li>')

    # Chart data as HTML table (bar chart)
    max_count = max(summary.values()) if summary else 1
    chart_rows = []
    for sev in ['HIGH', 'MEDIUM', 'LOW']:
        count = summary.get(sev, 0)
        width = int(280 * (count / max_count)) if max_count else 0
        bar = f'<div style="display:inline-block;height:14px;width:{width}px;background:{sev_text[sev]};border-radius:4px;"></div>'
        chart_rows.append(f'<tr><td>{sev_emoji[sev]}</td><td>{count}</td><td>{bar}</td></tr>')

    report = [f"""
    <html>
    <head>
    <meta charset="utf-8">
    <title>PyGuard Security Report</title>
    <style>
        body {{
            background: #181a1b; color: #fafafa; font-family: 'Segoe UI', Arial, sans-serif; padding:0 16px 40px 16px;
        }}
        h1, h2, h3, h4, h5 {{ color: #fafafa; }}
        a:link, a:visited {{ color: #ffe156; }}
        .summary-table, .bar-table {{
            border-collapse: collapse; margin-bottom: 18px; min-width: 320px;
        }}
        .summary-table th, .summary-table td, .bar-table td {{
            padding: 8px 14px; border-bottom: 1px solid #282b31; font-size: 1.09em;
        }}
        .sev-high {{ color: #ff4444; font-weight: bold; }}
        .sev-medium {{ color: #ffe156; font-weight: bold; }}
        .sev-low {{ color: #50fa7b; font-weight: bold; }}
        .issue-card {{
            border-radius: 12px; padding: 16px 22px; margin-bottom: 22px;
        }}
        .issue-card-high {{ background: #431010; border-left: 6px solid #ff4444; }}
        .issue-card-medium {{ background: #292813; border-left: 6px solid #ffe156; }}
        .issue-card-low {{ background: #102c13; border-left: 6px solid #50fa7b; }}
        .issue-type {{ font-weight: bold; font-size: 1.13em; }}
        .code-block {{
            background: #181c22 !important;
            color: #fafafa !important;
            border-radius: 10px;
            font-size: 15px;
            font-family: 'Fira Mono', 'Consolas', 'Monaco', monospace;
            padding: 10px 10px;
            margin: 6px 0 12px 0;
            overflow-x: auto;
            max-height: 300px;
        }}
        .collapsible {{
            background: #23272e;
            color: #f7f7f7;
            cursor: pointer;
            padding: 8px 16px;
            width: 100%;
            border: none;
            text-align: left;
            outline: none;
            font-size: 1.06em;
            border-radius: 8px;
            margin-bottom: 4px;
        }}
        .active, .collapsible:hover {{
            background-color: #394150;
        }}
        .content {{
            padding: 0 10px;
            display: none;
            overflow: hidden;
        }}
        .toc-list li {{margin:7px 0;}}
        .risk-badge {{ font-size:1.09em; }}
        .knowledge-box {{
            background:#262b32; border-radius:11px; padding:16px; margin:18px 0;
        }}
    </style>
    </head>
    <body>
    <h1>🐍 PyGuard Security Report</h1>
    <p><b>Generated:</b> {now}</p>
    <div class='risk-badge'>{risk_badge}</div>
    <h2>Executive Summary</h2>
    <table class="summary-table">
      <tr>
        <th>Metric</th>
        <th>Value</th>
      </tr>
      <tr><td>Files Scanned</td><td>{total_files}</td></tr>
      <tr><td>Lines of Code</td><td>{total_lines}</td></tr>
      <tr><td>Total Issues</td><td>{total_issues}</td></tr>
      <tr><td>🚨 High Severity</td><td>{num_high}</td></tr>
      <tr><td>⚠️ Medium Severity</td><td>{num_med}</td></tr>
      <tr><td>🟢 Low Severity</td><td>{num_low}</td></tr>
    </table>
    <h3>Findings Breakdown</h3>
    <table class="bar-table">
      <tr>
        <th>Severity</th>
        <th>Count</th>
        <th>Chart</th>
      </tr>
      {''.join(chart_rows)}
    </table>
    <h3>Table of Contents</h3>
    <ul class='toc-list'>
      {''.join(toc_links)}
    </ul>
    """]
    # All files/issues
    for fname, issues in issues_dict.items():
        anchor = fname.replace(".", "-")
        report.append(f"<hr><h2 id='{anchor}'>File: {fname}</h2>")
        if not issues:
            report.append("<p style='color:#50fa7b'><b>No vulnerabilities detected.</b></p>")
        else:
            for idx, issue in enumerate(issues):
                sev = issue['severity'].upper()
                sev_class = f"issue-card-{sev.lower()}"
                sev_icon = sev_emoji.get(sev, '')
                report.append(
                    f"<div class='issue-card {sev_class}'>"
                    f"<span class='issue-type'>{sev_icon} {issue['type']}</span> "
                    f"<span class='sev-{sev.lower()}'>[Severity: {sev.capitalize()}]</span>"
                    f"<br><b>Line:</b> {issue['line']} — {issue['message']}"
                    f"<br><b>Remediation:</b> {issue['remediation']}"
                    f"</div>"
                )
                # Collapsible code block
                snippet = html_code_snippet_with_arrow(code_files[fname], issue['line'])
                report.append(f"""
                    <button class="collapsible">Show code context for line {issue['line']} ⬇️</button>
                    <div class="content">
                        <pre class="code-block">{snippet}</pre>
                    </div>
                """)
    # Knowledgebase section
    report.append("<hr><h2>Vulnerability Knowledgebase</h2>")
    for vtype, desc in VULN_KNOWLEDGE.items():
        report.append(f"""
        <div class="knowledge-box">
            <b>{vtype}</b>
            <div style="margin-top:5px;font-size:1.01em;line-height:1.5;">{desc}</div>
        </div>
        """)
    report.append("""
    <script>
    var coll = document.getElementsByClassName("collapsible");
    var i;
    for (i = 0; i < coll.length; i++) {
      coll[i].addEventListener("click", function() {
        this.classList.toggle("active");
        var content = this.nextElementSibling;
        if (content.style.display === "block") {
          content.style.display = "none";
        } else {
          content.style.display = "block";
        }
      });
    }
    </script>
    </body>
    </html>
    """)
    return "\n".join(report)

def html_code_snippet_with_arrow(code, vuln_line, context=2):
    """
    Returns HTML-formatted code snippet with arrow (👉) pointing at the vulnerable line.
    """
    lines = code.splitlines()
    start = max(0, vuln_line - 1 - context)
    end = min(len(lines), vuln_line + context)
    html = ""
    for idx in range(start, end):
        pointer = "👉" if idx == vuln_line - 1 else "&nbsp;&nbsp;"
        lineno = f"{idx+1:3}"
        # Color vulnerable line
        if idx == vuln_line - 1:
            html += f"<span style='background:#2d1717;color:#ff9999;'><b>{pointer} {lineno}: {lines[idx]}</b></span><br>"
        else:
            html += f"{pointer} {lineno}: {lines[idx]}<br>"
    return html
