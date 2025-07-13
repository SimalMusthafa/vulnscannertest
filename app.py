import streamlit as st
from utils import *

def main():
    st.title("Secure Coding Vulnerability Scanner")

    # Sidebar for navigation
    st.sidebar.title("Navigation")
    page = st.sidebar.radio("Go to", ["Home", "Scanner", "About"])

    if page == "Home":
        show_home_page()
    elif page == "Scanner":
        show_scanner_page()
    elif page == "About":
        show_about_page()

def show_home_page():
    st.header("Welcome to the Vulnerability Scanner")
    st.write("""
        This tool helps you analyze your source code for potential security vulnerabilities.
        Navigate to the 'Scanner' page to upload your code and see the analysis.
    """)

def show_scanner_page():
    st.header("Code Scanner")
    language = st.selectbox("Select Language", ["Python", "JavaScript"])
    uploaded_file = st.file_uploader("Upload a file")

    if uploaded_file is not None:
        code = uploaded_file.read().decode("utf-8")
        st.code(code, language=language.lower())

        if st.button("Analyze"):
            if language == "Python":
                from python_scanner import scan_python
                vulnerabilities = scan_python(code)
            elif language == "JavaScript":
                from javascript_scanner import scan_javascript
                vulnerabilities = scan_javascript(code)

            display_vulnerabilities(vulnerabilities)

def show_about_page():
    st.header("About This Tool")
    st.write("""
        This vulnerability scanner is designed to help developers write more secure code.
        It uses static analysis to find common security issues based on the OWASP Top 10.
    """)

if __name__ == "__main__":
    main()
