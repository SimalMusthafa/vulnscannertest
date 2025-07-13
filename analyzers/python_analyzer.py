import tempfile
import subprocess
import re
from utils.vuln_patterns import PYTHON_VULN_PATTERNS

def analyze_python_code(code):
    """
    Scans Python code for security issues using regex/static pattern rules.
    Returns a list of issue dicts.
    """
    issues = []
    lines = code.split('\n')
    for lineno, line in enumerate(lines, 1):
        for vuln in PYTHON_VULN_PATTERNS:
            if vuln['pattern'].search(line):
                issues.append({
                    'line': lineno,
                    'type': vuln['type'],
                    'severity': vuln.get('severity', 'MEDIUM'),
                    'message': vuln['message'],
                    'remediation': vuln.get('remediation', ''),
                })
    # (Optional: Could add AST checks for more depth in future)
    return issues

def run_bandit(code):
    """
    Runs Bandit on the given code and parses its JSON output.
    Returns a list of issue dicts.
    """
    issues = []
    try:
        with tempfile.NamedTemporaryFile('w', suffix='.py', delete=False) as tmp:
            tmp.write(code)
            tmp.flush()
            result = subprocess.run(
                ['bandit', '-f', 'json', tmp.name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=15
            )
        import json
        output = json.loads(result.stdout.decode())
        for res in output.get('results', []):
            issues.append({
                'line': res.get('line_number', 0),
                'type': f"Bandit: {res.get('test_name', 'Issue')}",
                'severity': res.get('issue_severity', 'LOW').upper(),
                'message': res.get('issue_text', ''),
                'remediation': res.get('issue_confidence', 'See Bandit docs.')
            })
    except Exception as e:
        issues.append({
            'line': 0,
            'type': 'Bandit Error',
            'severity': 'HIGH',
            'message': f"Bandit failed to run: {e}",
            'remediation': "Make sure Bandit is installed and working."
        })
    return issues
