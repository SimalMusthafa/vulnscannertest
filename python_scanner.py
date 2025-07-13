import re
import subprocess
import json
import tempfile
import os

# OWASP Top 10 inspired checks for Python

# 1. SQL Injection (Simple Pattern)
SQL_INJECTION_PATTERN = re.compile(r"execute\s*\(\s*f?['\"].*?{.*}.*?['\"]\s*\)")

# 2. Hardcoded Credentials/Secrets
HARDCODED_SECRET_PATTERN = re.compile(r"(password|secret|api_key)\s*=\s*['\"].+?['\"]", re.IGNORECASE)

# 3. Use of dangerous functions
DANGEROUS_FUNCTIONS = {
    "eval": "Use of eval can lead to arbitrary code execution.",
    "exec": "Use of exec can lead to arbitrary code execution.",
    "pickle.loads": "Deserializing untrusted data with pickle can lead to remote code execution."
}
DANGEROUS_FUNCTIONS_PATTERN = re.compile(r"\b(" + "|".join(DANGEROUS_FUNCTIONS.keys()) + r")\s*\(")


def scan_python(code):
    """
    Scans Python code for a set of vulnerabilities.
    Combines custom regex checks with Bandit analysis.
    """
    vulnerabilities = []
    lines = code.split('\n')

    # Run custom regex-based checks
    for i, line in enumerate(lines, 1):
        # Check for SQL Injection
        if SQL_INJECTION_PATTERN.search(line):
            vulnerabilities.append({
                "title": "Potential SQL Injection",
                "line_number": i,
                "code_snippet": line.strip(),
                "suggestion": "Use parameterized queries or an ORM to prevent SQL injection."
            })

        # Check for hardcoded secrets
        if HARDCODED_SECRET_PATTERN.search(line):
            vulnerabilities.append({
                "title": "Hardcoded Secret Detected",
                "line_number": i,
                "code_snippet": line.strip(),
                "suggestion": "Store secrets in environment variables or a secure vault, not in source code."
            })
            
        # Check for dangerous functions
        match = DANGEROUS_FUNCTIONS_PATTERN.search(line)
        if match:
            func = match.group(1)
            vulnerabilities.append({
                "title": f"Use of Dangerous Function: {func}",
                "line_number": i,
                "code_snippet": line.strip(),
                "suggestion": DANGEROUS_FUNCTIONS[func]
            })

    # Integrate with Bandit for deeper analysis
    bandit_results = run_bandit(code)
    vulnerabilities.extend(bandit_results)

    return vulnerabilities


def run_bandit(code):
    """
    Runs the Bandit tool on the given code and parses the results.
    """
    vulnerabilities = []
    try:
        # Bandit needs a file to scan, so we create a temporary one
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.py') as temp_file:
            temp_file.write(code)
            temp_filepath = temp_file.name

        # Command to run bandit and get JSON output
        # Note: 'bandit' must be installed in the environment (pip install bandit)
        command = [
            "bandit",
            "-f", "json",
            temp_filepath
        ]
        
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        
        # Parse the JSON output
        report = json.loads(result.stdout)
        for issue in report.get("results", []):
            vulnerabilities.append({
                "title": f"Bandit: {issue['issue_text']}",
                "line_number": issue['line_number'],
                "code_snippet": issue['code'],
                "suggestion": f"{issue['issue_confidence'].capitalize()} confidence. {issue['issue_severity'].capitalize()} severity. More info: {issue['more_info']}"
            })

    except FileNotFoundError:
        # This error occurs if 'bandit' is not installed or not in the system's PATH
        vulnerabilities.append({
            "title": "Bandit Not Found",
            "line_number": 0,
            "code_snippet": "Could not execute the 'bandit' command.",
            "suggestion": "Please ensure 'bandit' is installed in your environment (`pip install bandit`) and accessible via the system's PATH."
        })
    except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
        # Handle other errors during bandit execution or parsing
        vulnerabilities.append({
            "title": "Error running Bandit",
            "line_number": 0,
            "code_snippet": str(e),
            "suggestion": "There was an issue running the Bandit analysis."
        })
    finally:
        # Clean up the temporary file
        if 'temp_filepath' in locals() and os.path.exists(temp_filepath):
            os.remove(temp_filepath)
            
    return vulnerabilities
