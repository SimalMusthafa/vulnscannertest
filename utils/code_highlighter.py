def show_code_snippet_with_arrow(code, vuln_line, context=2):
    """
    Returns a code snippet string with an arrow (👉) pointing at the vulnerable line.
    context: number of lines above/below to show.
    """
    lines = code.splitlines()
    start = max(0, vuln_line - 1 - context)
    end = min(len(lines), vuln_line + context)
    snippet = []
    for idx in range(start, end):
        pointer = "👉 " if idx == vuln_line - 1 else "   "
        # Add 1 to idx for 1-based line numbering
        snippet.append(f"{pointer}{idx+1:3}: {lines[idx]}")
    return "\n".join(snippet)
