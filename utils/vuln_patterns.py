import re

# Add, tune, and prioritize OWASP Top 10 relevant for Python
PYTHON_VULN_PATTERNS = [
    {
        'type': 'Hardcoded Credential',
        'pattern': re.compile(r'(password|passwd|pwd|secret)\s*=\s*["\'].*["\']', re.IGNORECASE),
        'message': 'Possible hardcoded credential found.',
        'remediation': 'Do not store credentials directly in code. Use environment variables or secret managers.',
        'severity': 'HIGH'
    },
    {
        'type': 'SQL Injection',
        'pattern': re.compile(r'(execute|executemany)\s*\(.*\+.*\)', re.IGNORECASE),
        'message': 'Possible SQL injection: Query string concatenation detected.',
        'remediation': 'Use parameterized queries instead of string concatenation.',
        'severity': 'HIGH'
    },
    {
        'type': 'Command Injection',
        'pattern': re.compile(r'os\.system\s*\(.*\+.*\)', re.IGNORECASE),
        'message': 'Potential command injection with os.system.',
        'remediation': 'Avoid using user input in os.system. Use subprocess with argument lists.',
        'severity': 'HIGH'
    },
    {
        'type': 'Insecure Deserialization',
        'pattern': re.compile(r'pickle\.load|pickle\.loads', re.IGNORECASE),
        'message': 'Unsafe use of pickle deserialization.',
        'remediation': 'Never unpickle untrusted data. Use json or safer alternatives.',
        'severity': 'HIGH'
    },
    {
        'type': 'Use of eval',
        'pattern': re.compile(r'\beval\s*\(', re.IGNORECASE),
        'message': 'Use of eval() detected.',
        'remediation': 'Avoid eval(). Use safer alternatives or parsers.',
        'severity': 'HIGH'
    },
    {
        'type': 'Weak Cryptography',
        'pattern': re.compile(r'(md5|sha1)\s*\(', re.IGNORECASE),
        'message': 'Weak cryptography detected (MD5/SHA1).',
        'remediation': 'Use strong algorithms like SHA256, SHA512, or bcrypt.',
        'severity': 'MEDIUM'
    },
    {
        'type': 'Insecure Random',
        'pattern': re.compile(r'random\.random|random\.randint|random\.choice', re.IGNORECASE),
        'message': 'Insecure random generator used for security purposes.',
        'remediation': 'Use secrets module for secure tokens, passwords, or IDs.',
        'severity': 'MEDIUM'
    },
    {
        'type': 'Wildcard Import',
        'pattern': re.compile(r'from\s+\S+\s+import\s+\*', re.IGNORECASE),
        'message': 'Wildcard import detected. Can lead to namespace pollution.',
        'remediation': 'Import only what you need explicitly.',
        'severity': 'LOW'
    },
    # Add more custom rules as desired!
]
