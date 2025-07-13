# PyGuard: Python Secure Coding Vulnerability Scanner

**PyGuard** is a modern, user-friendly vulnerability scanner for Python source code.
It combines fast static analysis, deep security checks, and a beautiful UI to help you find and fix OWASP Top 10 vulnerabilities and other common Python code risks.

---

## 🚀 What is PyGuard?

PyGuard is a web app you can run locally or deploy to the cloud.
Just upload your Python code (single file or ZIP of many files) and PyGuard will scan for:

* **Hardcoded credentials**
* **SQL injection**
* **Command injection**
* **Insecure deserialization**
* **Insecure random usage**
* **Weak cryptography**
* **Use of `eval()`**
* **Wildcard imports**
* ...and much more, including all major [OWASP Top 10](https://owasp.org/www-project-top-ten/) categories for Python.

It uses **Bandit** for advanced scanning, plus custom rules to catch what Bandit might miss.

---

## ✨ Key Features

* **Upload & Scan Instantly:** Works with `.py` or `.zip` files.
* **Sample Demo:** Click "Load Sample File" for instant demonstration—see the scanner in action!
* **Clear, Beautiful UI:** Severity badges, code context with arrows, grouped findings, charts, and tabs for exploring results.
* **Knowledgebase:** Every finding has a plain-English explanation with links to best practices and security guides.
* **Detailed Reports:** Download a gorgeous HTML report with executive summary, file-by-file breakdown, clickable table of contents, and security knowledgebase.
* **No code leaves your browser/server**—everything runs securely and privately.

---

## 🛠️ How to Run

1. **Clone the repository:**

   ```bash
   git clone https://github.com/YOUR_GITHUB_USER/YOUR_REPO.git
   cd YOUR_REPO
   ```

2. **Install requirements (ideally in a virtualenv):**

   ```bash
   pip install -r requirements.txt
   ```

3. **Run PyGuard locally:**

   ```bash
   streamlit run app.py
   ```

   The app will open in your browser at [http://localhost:8501](http://localhost:8501).

---

## 🧑‍💻 Usage

1. **Upload your Python file** (`.py`) or a ZIP of Python files.
2. *(Optional)* Click **"Load Sample File for Demo"** to try it instantly with a built-in vulnerable test script.
3. Click **"Scan for Vulnerabilities."**
4. Explore results in tabs:

   * **All Issues Table:** Search, sort, and filter findings.
   * **By File:** Grouped by filename, with severity and explanations.
   * **Full Code:** Browse your code.
5. **Download the HTML Report** for archiving, sharing, or compliance.

---

## 📄 Sample Output

The app displays:

* Risk summary and chart
* Severity badges (🚨 HIGH, ⚠️ MEDIUM, 🟢 LOW)
* Explanations and remediation for each finding
* Code context with arrow pointing to the exact vulnerable line
* Executive summary in report, knowledgebase for all vulnerability types

---

## 🛡️ Security & Privacy

* **No code is sent to the cloud** (unless you deploy it yourself).
* All analysis happens in your browser/server.
* Reports and scans are not stored after your session ends.

---

## 🙋 FAQ

**Q: What kinds of bugs does PyGuard find?**
A: PyGuard scans for hardcoded secrets, insecure code patterns, injection flaws, weak randomness, cryptographic misuse, dangerous deserialization, and more.

**Q: Is this for production?**
A: PyGuard is suitable for DevSecOps, CI/CD pipelines, and educational use. For mission-critical code reviews, always supplement with human expertise.

**Q: Can I add more rules?**
A: Yes! See `utils/vuln_patterns.py` to add or modify detection rules and their explanations.

---

## 📝 License

MIT License.
Feel free to fork, adapt, and use in your team/company!

---

## 👨‍🎓 Credits

* Built with [Streamlit](https://streamlit.io), [Bandit](https://bandit.readthedocs.io), and Python 3.
* Inspired by the OWASP Top 10 and secure coding best practices.

---

**Happy Secure Coding!**
