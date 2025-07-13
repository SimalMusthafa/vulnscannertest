import streamlit as st
import pandas as pd
from scanner import scan_python_code
from utils.code_highlighter import show_code_snippet_with_arrow
from utils.report import generate_html_report

# --- Modern CSS for cards and summary ---
st.markdown("""
<style>
.stApp { background-color: #181a1b; }
h1, h2, h3, h4, h5 { color: #fafafa; }
.issue-card-high {
    background: #3b1212;
    border-left: 5px solid #ff5252;
}
.issue-card-medium {
    background: #292813;
    border-left: 5px solid #ffe156;
}
.issue-card-low {
    background: #163a22;
    border-left: 5px solid #50fa7b;
}
.issue-type { font-weight: bold; font-size: 1.1em; color: #f9f9f9; }
.severity-high { color: #ff5252; font-weight: bold; }
.severity-medium { color: #ffe156; font-weight: bold; }
.severity-low { color: #50fa7b; font-weight: bold; }
hr { border-color: #2a2e32; }
div.stDownloadButton > button { background: #22232b; color: #fafafa; }
</style>
""", unsafe_allow_html=True)

# --- Sidebar with navigation ---
with st.sidebar:
    st.title("🐍 PyGuard")
    st.markdown("**Secure Python Coding Scanner**")
    st.info("Upload Python file(s) to scan for OWASP Top 10 security bugs. Powered by Bandit and custom rules.")
    st.markdown("---")
    st.markdown("v1.3 | [GitHub](#)")
    st.markdown("---")
    if 'file_list' in st.session_state:
        st.markdown("#### Files in Scan:")
        for idx, fname in enumerate(st.session_state['file_list']):
            st.markdown(f"- [{fname}](#{fname.replace('.','-')})")

st.title("🔒 Python Secure Coding Vulnerability Scanner")

uploaded_file = st.file_uploader(
    "Upload a Python file (.py) or zip (.zip) of Python files", 
    type=["py", "zip"], 
    accept_multiple_files=False
)

if uploaded_file:
    code_files = scan_python_code.load_code_files(uploaded_file)
    st.session_state['file_list'] = list(code_files.keys())
    st.subheader("📄 Uploaded Files")
    for fname, code in code_files.items():
        with st.expander(fname):
            st.code(code, language="python")

    if st.button("Scan for Vulnerabilities"):
        with st.spinner("Analyzing your code for vulnerabilities..."):
            all_issues = scan_python_code.scan_multiple_files(code_files)

        st.success("Scan complete!")

        # --- Severity summary table with emojis ---
        all_flat_issues = [i for issues in all_issues.values() for i in issues]
        sev_emoji = {'HIGH': '🚨 HIGH', 'MEDIUM': '⚠️ MEDIUM', 'LOW': '🟢 LOW'}
        if all_flat_issues:
            summary = pd.Series([i['severity'].upper() for i in all_flat_issues]).value_counts()
            summary_display = summary.rename(lambda x: sev_emoji.get(x, x)).rename("Count").to_frame()
            st.markdown("### 🗂️ Severity Summary")
            st.dataframe(summary_display, use_container_width=True)
        else:
            st.info("No vulnerabilities detected!")

        # --- Toggle filters for severity levels ---
        st.markdown("### Filter Findings")
        show_high = st.checkbox("Show HIGH severity", True)
        show_med = st.checkbox("Show MEDIUM severity", True)
        show_low = st.checkbox("Show LOW severity", False)
        severity_filter = set()
        if show_high: severity_filter.add('HIGH')
        if show_med: severity_filter.add('MEDIUM')
        if show_low: severity_filter.add('LOW')

        st.subheader("🔎 Findings Summary")
        for fname, issues in all_issues.items():
            display_issues = [i for i in issues if i['severity'].upper() in severity_filter]
            if not display_issues:
                continue
            st.markdown(f"<div id='{fname.replace('.','-')}' style='margin-bottom:10px;'><span style='background:#222; color:#50fa7b; padding:4px 10px; border-radius:6px; font-size:1.0em;'>{fname}</span></div>", unsafe_allow_html=True)
            code = code_files[fname]
            for issue in display_issues:
                sev = issue['severity'].lower()
                sev_icon = {'high':'🚨', 'medium':'⚠️', 'low':'🟢'}.get(sev, '')
                st.markdown(f"""
                <div class="issue-card-{sev}" style="padding: 14px 18px; border-radius: 10px; margin-bottom: 16px;">
                    <span class="issue-type">{sev_icon} {issue['type']}</span>
                    <span class="severity-{sev}">(Severity: {issue['severity'].capitalize()})</span>
                    <br>
                    <span style="opacity:0.92;"><b>Line:</b> {issue['line']} — {issue['message']}</span>
                    <br>
                    <b>Remediation:</b> <span style="opacity:0.90;">{issue['remediation']}</span>
                </div>
                """, unsafe_allow_html=True)
                snippet = show_code_snippet_with_arrow(code, issue['line'])
                st.code(snippet, language="python")

        # --- Download HTML report button ---
        report_html = generate_html_report(all_issues, code_files)
        st.download_button(
            label="Download Beautiful HTML Report",
            data=report_html,
            file_name="pyguard_report.html",
            mime="text/html"
        )

    st.button("Scan Again", on_click=lambda: st.experimental_rerun())
else:
    st.markdown("⬆️ *Upload a `.py` file or a `.zip` of Python files to get started.*")
