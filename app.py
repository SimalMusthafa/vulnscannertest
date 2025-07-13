import streamlit as st
import pandas as pd
from scanner import scan_python_code
from utils.code_highlighter import highlight_code
from utils.report import generate_html_report

# -------- Custom CSS for modern look --------
st.markdown("""
<style>
.stApp { background-color: #17191c; }
h1, h2, h3, h4, h5 { color: #fafafa; }
.code-block {
    background: #181c22 !important;
    color: #fafafa !important;
    border-radius: 12px;
    font-size: 15px;
    font-family: 'Fira Mono', 'Consolas', 'Monaco', monospace;
    padding: 16px 8px !important;
    margin: 14px 0 30px 0;
    overflow-x: auto;
    max-height: 450px;
}
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
.issue-type {
    font-weight: bold;
    font-size: 1.1em;
    color: #f9f9f9;
}
.severity-high { color: #ff5252; font-weight: bold; }
.severity-medium { color: #ffe156; font-weight: bold; }
.severity-low { color: #50fa7b; font-weight: bold; }
hr { border-color: #2a2e32; }
div.stDownloadButton > button { background: #22232b; color: #fafafa; }
</style>
""", unsafe_allow_html=True)

# ---------- Sidebar ----------
with st.sidebar:
    st.title("🐍 PyGuard")
    st.markdown("**Secure Python Coding Scanner**")
    st.info("Upload Python file(s) to scan for OWASP Top 10 security bugs. Powered by Bandit and custom rules.")
    st.markdown("---")
    st.markdown("v1.1 | [GitHub](#)")

st.title("🔒 Python Secure Coding Vulnerability Scanner")

uploaded_file = st.file_uploader(
    "Upload a Python file (.py) or zip (.zip) of Python files", 
    type=["py", "zip"], 
    accept_multiple_files=False
)

if uploaded_file:
    code_files = scan_python_code.load_code_files(uploaded_file)
    st.subheader("📄 Uploaded Files")
    for fname, code in code_files.items():
        with st.expander(fname):
            st.code(code, language="python")

    if st.button("Scan for Vulnerabilities"):
        with st.spinner("Analyzing your code for vulnerabilities..."):
            all_issues = scan_python_code.scan_multiple_files(code_files)

        st.success("Scan complete!")

        # --- Severity summary table ---
        all_flat_issues = [i for issues in all_issues.values() for i in issues]
        if all_flat_issues:
            summary = pd.Series([i['severity'].capitalize() for i in all_flat_issues]).value_counts()
            st.markdown("### 🗂️ Severity Summary")
            st.dataframe(summary.rename("Count").to_frame(), use_container_width=True)
        else:
            st.info("No vulnerabilities detected!")

        # --- Detailed findings, with cards and code blocks ---
        st.subheader("🔎 Findings Summary")
        for fname, issues in all_issues.items():
            if not issues:
                continue
            st.markdown(f"<div style='margin-bottom:10px;'><span style='background:#222; color:#50fa7b; padding:4px 10px; border-radius:6px; font-size:1.0em;'>{fname}</span></div>", unsafe_allow_html=True)
            code = code_files[fname]
            for issue in issues:
                sev = issue['severity'].lower()
                st.markdown(f"""
                <div class="issue-card-{sev}" style="padding: 14px 18px; border-radius: 10px; margin-bottom: 16px;">
                    <span class="issue-type">{issue['type']}</span>
                    <span class="severity-{sev}">(Severity: {issue['severity'].capitalize()})</span>
                    <br>
                    <span style="opacity:0.92;"><b>Line:</b> {issue['line']} — {issue['message']}</span>
                    <br>
                    <b>Remediation:</b> <span style="opacity:0.90;">{issue['remediation']}</span>
                </div>
                """, unsafe_allow_html=True)
                code_html = highlight_code(code, highlight_line=issue['line'])
                st.markdown(f'<div class="code-block">{code_html}</div>', unsafe_allow_html=True)

        # --- Download report button ---
        report_html = generate_html_report(all_issues, code_files)
        st.download_button(
            label="Download HTML Report",
            data=report_html,
            file_name="pyguard_report.html",
            mime="text/html"
        )

    st.button("Scan Again", on_click=lambda: st.experimental_rerun())
else:
    st.markdown("⬆️ *Upload a `.py` file or a `.zip` of Python files to get started.*")
