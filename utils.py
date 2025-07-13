import streamlit as st

def display_vulnerabilities(vulnerabilities):
    if vulnerabilities:
        st.error("Vulnerabilities Found!")
        for vuln in vulnerabilities:
            st.warning(f"**{vuln['title']}** on line {vuln['line_number']}")
            st.code(vuln['code_snippet'], language='text')
            st.info(f"**Suggestion:** {vuln['suggestion']}")
    else:
        st.success("No vulnerabilities found!")

def highlight_vuln(code, line_number):
    lines = code.split('\n')
    lines[line_number - 1] = f"**{lines[line_number - 1]}**"
    return "\n".join(lines)
