import streamlit as st
import pandas as pd
from scanner import scan_python_code
from utils.code_highlighter import show_code_snippet_with_arrow
from utils.report import generate_html_report
from utils.vuln_patterns import VULN_KNOWLEDGE
import time
import io

SAMPLE_FILENAME = "vulnerable_test_script.py"

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
.code-context-pop { font-size:0.94em; color:#bbbbbb; }
</style>
""", unsafe_allow_html=True)

with st.sidebar:
    st.title("🐍 PyGuard")
    st.markdown("**Secure Python Coding Scanner**")
    st.info("Upload Python file(s) to scan for OWASP Top 10 security bugs. Powered by Bandit and custom rules.")
    st.markdown("---")
    st.markdown("v1.4 | [GitHub](#)")
    st.markdown("---")
    if 'file_list' in st.session_state:
        st.markdown("#### Files in Scan:")
        for idx, fname in enumerate(st.session_state['file_list']):
            st.markdown(f"- [{fname}](#{fname.replace('.','-')})")

st.title("🔒 Python Secure Coding Vulnerability Scanner")

# --- Load sample file button ---
if st.button("Load Sample File for Demo"):
    try:
        with open(SAMPLE_FILENAME, "rb") as f:
            file_bytes = io.BytesIO(f.read())
            file_bytes.name = SAMPLE_FILENAME
            st.session_state['demo_file'] = file_bytes
            st.success("Sample file loaded! Click 'Scan for Vulnerabilities' to analyze.")
    except Exception as e:
        st.error(f"Could not load sample file: {e}")

# --- Main file uploader (auto-uses sample file if loaded) ---
uploaded_file = st.file_uploader(
    "Upload a Python file (.py) or zip (.zip) of Python files", 
    type=["py", "zip"], 
    accept_multiple_files=False
)
if not uploaded_file and 'demo_file' in st.session_state:
    uploaded_file = st.session_state['demo_file']

if uploaded_file:
    code_files = scan_python_code.load_code_files(uploaded_file)
    st.session_state['file_list'] = list(code_files.keys())
    st.subheader("📄 Uploaded Files")
    for fname, code in code_files.items():
        with st.expander(fname):
            st.code(code, language="python")

    if st.button("Scan for Vulnerabilities"):
        start = time.time()
        with st.spinner("Analyzing your code for vulnerabilities..."):
            all_issues = scan_python_code.scan_multiple_files(code_files)
        elapsed = time.time() - start

        st.success("Scan complete!")

        all_flat_issues = [i | {'filename': fname} for fname, issues in all_issues.items() for i in issues]
        sev_emoji = {'HIGH': '🚨 HIGH', 'MEDIUM': '⚠️ MEDIUM', 'LOW': '🟢 LOW'}

        total_files = len(code_files)
        total_issues = len(all_flat_issues)
        total_lines = sum(len(c.splitlines()) for c in code_files.values())
        num_high = sum(1 for i in all_flat_issues if i['severity'].upper() == "HIGH")

        st.markdown("## 📊 Scan Overview")
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Files Scanned", total_files)
        col2.metric("Total Issues", total_issues)
        col3.metric("Lines of Code", total_lines)
        col4.metric("Time (sec)", f"{elapsed:.2f}")

        if num_high > 0:
            st.error(f"🚨 High risk! {num_high} HIGH severity issues found.")
        elif total_issues > 0:
            st.warning("⚠️ Medium/Low severity issues found.")
        else:
            st.success("✅ No vulnerabilities detected!")

        st.markdown("### 🗂️ Severity Bar Chart")
        if all_flat_issues:
            sev_df = pd.Series([i['severity'].capitalize() for i in all_flat_issues]).value_counts()
            st.bar_chart(sev_df)
        else:
            st.info("No findings to display.")

        # --- Tabs for results ---
        tabs = st.tabs(["📋 All Issues Table", "📝 By File", "🧑‍💻 Full Code"])
        with tabs[0]:
            st.markdown("#### Searchable Table of All Issues")
            if all_flat_issues:
                df_issues = pd.DataFrame(all_flat_issues)
                df_issues = df_issues[["filename", "line", "severity", "type", "message", "remediation"]]
                st.dataframe(df_issues, use_container_width=True)
            else:
                st.info("No issues found.")

        with tabs[1]:
            st.markdown("#### Grouped by File")
            for fname, issues in all_issues.items():
                if not issues:
                    continue
                st.markdown(f"<div id='{fname.replace('.','-')}' style='margin-bottom:10px;'><span style='background:#222; color:#50fa7b; padding:4px 10px; border-radius:6px; font-size:1.0em;'>{fname}</span></div>", unsafe_allow_html=True)
                code = code_files[fname]
                for issue in issues:
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
                        <span style="float:right">
                            <a href="#" title="{VULN_KNOWLEDGE.get(issue['type'], 'No details.')}" style="color:#ffe156;font-size:1.2em;text-decoration:none;">🛈</a>
                        </span>
                    </div>
                    """, unsafe_allow_html=True)
                    snippet = show_code_snippet_with_arrow(code, issue['line'])
                    st.code(snippet, language="python")

        with tabs[2]:
            st.markdown("#### Full Source Code (all files)")
            for fname, code in code_files.items():
                st.markdown(f"<b>{fname}</b>", unsafe_allow_html=True)
                st.code(code, language="python")

        # --- Download HTML report button ---
        report_html = generate_html_report(all_issues, code_files)
        st.download_button(
            label="Download HTML Report",
            data=report_html,
            file_name="pyguard_report.html",
            mime="text/html"
        )

    st.button("Scan Again", on_click=st.rerun)
else:
    st.markdown("⬆️ *Upload a `.py` file or a `.zip` of Python files to get started, or load a sample file for demonstration.*")
