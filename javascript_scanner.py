import re

# OWASP Top 10 inspired checks for JavaScript

# 1. Cross-Site Scripting (XSS) Sinks
XSS_SINKS_PATTERN = re.compile(r"\.innerHTML\s*=|document\.write\s*\(", re.IGNORECASE)

# 2. Hardcoded Credentials/Secrets
HARDCODED_SECRET_PATTERN = re.compile(r"(const|let|var)\s+(password|secret|api_key)\s*=\s*['\"].+?['\"]", re.IGNORECASE)

# 3. Use of eval()
EVAL_PATTERN = re.compile(r"\beval\s*\(", re.IGNORECASE)

def scan_javascript(code):
    """
    Scans JavaScript code for a set of common vulnerabilities using regex.
    For a more robust solution, integrating a linter like ESLint with security plugins is recommended.
    """
    vulnerabilities = []
    lines = code.split('\n')

    for i, line in enumerate(lines, 1):
        # Check for potential XSS sinks
        if XSS_SINKS_PATTERN.search(line):
            vulnerabilities.append({
                "title": "Potential XSS Vulnerability",
                "line_number": i,
                "code_snippet": line.strip(),
                "suggestion": "Directly using .innerHTML or document.write with user-controllable input can lead to XSS. Use .textContent or proper sanitization instead."
            })

        # Check for hardcoded secrets
        if HARDCODED_SECRET_PATTERN.search(line):
            vulnerabilities.append({
                "title": "Hardcoded Secret Detected",
                "line_number": i,
                "code_snippet": line.strip(),
                "suggestion": "Avoid storing secrets in client-side code. Use a backend service to handle sensitive data and authentication."
            })
            
        # Check for use of eval()
        if EVAL_PATTERN.search(line):
            vulnerabilities.append({
                "title": "Use of eval()",
                "line_number": i,
                "code_snippet": line.strip(),
                "suggestion": "The use of eval() is dangerous as it can execute arbitrary code. Look for safer alternatives like JSON.parse for parsing JSON."
            })
            
    # Note on ESLint Integration:
    # A full integration of ESLint would be more complex than Bandit.
    # It would require setting up a JS environment, installing ESLint and plugins,
    # and running it as a subprocess, similar to the bandit implementation.
    # The regex approach here serves as a good starting point for basic checks.

    return vulnerabilities
