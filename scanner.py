import zipfile
import io
from analyzers.python_analyzer import analyze_python_code, run_bandit

class scan_python_code:
    @staticmethod
    def load_code_files(uploaded_file):
        code_files = {}
        if uploaded_file.name.endswith(".zip"):
            z = zipfile.ZipFile(uploaded_file)
            for fname in z.namelist():
                if fname.endswith(".py"):
                    code_files[fname] = z.read(fname).decode("utf-8")
        elif uploaded_file.name.endswith(".py"):
            code_files[uploaded_file.name] = uploaded_file.read().decode("utf-8")
        return code_files

    @staticmethod
    def scan_multiple_files(code_files):
        all_issues = {}
        for fname, code in code_files.items():
            issues = analyze_python_code(code)
            issues += run_bandit(code)
            # Remove duplicates
            seen = set()
            unique_issues = []
            for issue in issues:
                sig = (issue['line'], issue['type'], issue['message'])
                if sig not in seen:
                    unique_issues.append(issue)
                    seen.add(sig)
            all_issues[fname] = unique_issues
        return all_issues
