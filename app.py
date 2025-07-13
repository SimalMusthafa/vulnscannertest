import streamlit as st
from scanner import scan_python_code
from utils.code_highlighter import highlight_code
from utils.report import generate_html_report

st.set_page_config(
    page_title="PyGuard: Python Security Scanner",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Sidebar branding and info
with st.sidebar:
    st.title("🐍 PyGuard")
    st.markdown("**Secure Python Coding Scanner**")
    st.markdown("---")
    st.info("Upload your Python file(s) below to scan for security issues. Powered by Bandit and custom rules.")
    st.markdown("v1.0 | [GitHub](#)")

# Main interface
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
        st.subheader("🔎 Findings Summary")
        if not all_issues:
            st.success("No vulnerabilities detected in your code!")
        else:
            for fname, issues in all_issues.items():
                st.markdown(f"#### `{fname}`")
                for issue in issues:
                    color = {"LOW":"#e2f7e2", "MEDIUM":"#fff3cd", "HIGH":"#f8d7da"}.get(issue['severity'], "#f0f0f0")
                    st.markdown(
                        f"""
                        <div style="background:{color};padding:8px;border-radius:10px;margin-bottom:6px;">
                        <b>{issue['type']}</b> (line {issue['line']})<br>
                        <span style="font-size:95%;">{issue['message']}</span>
                        <br><b>Remediation:</b> {issue['remediation']}
                        </div>
                        """, unsafe_allow_html=True)
                    st.markdown(highlight_code(code_files[fname], issue['line']), unsafe_allow_html=True)

        # Downloadable report
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

