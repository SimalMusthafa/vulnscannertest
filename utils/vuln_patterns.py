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

VULN_KNOWLEDGE = {
    "Hardcoded Credential": 
        "Storing secrets or passwords in code is highly dangerous. If leaked or committed to version control, anyone can gain unauthorized access. Use environment variables or secret management services instead. [Learn More](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)",
    "SQL Injection":
        "SQL injection is a code injection technique that might destroy your database. Always use parameterized queries. [OWASP Guide](https://owasp.org/www-community/attacks/SQL_Injection)",
    "Command Injection":
        "Command injection allows attackers to run arbitrary commands on your server. Never pass user input to system shell commands. [OWASP Guide](https://owasp.org/www-community/attacks/Command_Injection)",
    "Insecure Deserialization":
        "Deserializing data from untrusted sources can result in arbitrary code execution. Use safe serialization like JSON, and never unpickle user input. [OWASP Guide](https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data)",
    "Use of eval":
        "Eval executes arbitrary code. User input passed to eval can lead to full code execution by attackers. Avoid at all costs. [Python Security Docs](https://realpython.com/python-eval-function/#security-risks)",
    "Weak Cryptography":
        "MD5 and SHA1 are broken and can be attacked. Use SHA256, SHA512, bcrypt, or Argon2 for security. [NIST Guidelines](https://csrc.nist.gov/projects/hash-functions)",
    "Insecure Random":
        "The random module is not cryptographically secure. Use the 'secrets' module for tokens or passwords. [Python docs](https://docs.python.org/3/library/secrets.html)",
    "Wildcard Import":
        "Wildcard imports make code unclear and can cause namespace conflicts. Import only what you need.",
    # Add more as you add patterns
}
