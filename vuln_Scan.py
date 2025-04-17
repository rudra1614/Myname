import argparse
import re
from fpdf import FPDF

# === Vulnerability Patterns with Fix & Memory Insights ===
vulnerability_patterns = [
    {
        'name': 'strcpy usage',
        'regex': re.compile(r'\bstrcpy\s*\('),
        'description': 'strcpy is unsafe and can cause buffer overflows.',
        'suggestion': 'Use strncpy(buffer, input, sizeof(buffer) - 1);',
        'severity': 'High',
        'owasp': 'A1: Injection',
        'memory': [
            '- Writes beyond buffer size if unchecked.',
            '- May overwrite stack return address.'
        ]
    },
    {
        'name': 'gets usage',
        'regex': re.compile(r'\bgets\s*\('),
        'description': 'gets reads input with no bounds. Dangerous!',
        'suggestion': 'Use fgets(buffer, sizeof(buffer), stdin);',
        'severity': 'High',
        'owasp': 'A1: Injection',
        'memory': [
            '- Reads until newline with no limit.',
            '- Leads to stack buffer overflow.'
        ]
    },
    {
        'name': 'sprintf usage',
        'regex': re.compile(r'\bsprintf\s*\('),
        'description': 'sprintf can overflow buffer if not sized properly.',
        'suggestion': 'Use snprintf with size limit.',
        'severity': 'Medium',
        'owasp': 'A1: Injection',
        'memory': [
            '- Writes formatted data into buffer.',
            '- Without size limits, may overflow.'
        ]
    },
    {
        'name': 'scanf with %s without width',
        'regex': re.compile(r'\bscanf\s*\([^"]*".*(?<!\d)%s.*"'),
        'description': 'scanf with %s reads unlimited input.',
        'suggestion': 'Use scanf("%255s", var); to restrict length.',
        'severity': 'Medium',
        'owasp': 'A1: Injection',
        'memory': [
            '- May read more input than buffer can hold.',
            '- Results in stack overflow or corruption.'
        ]
    }
]

# === PDF Report ===
class PDF(FPDF):
    def header(self):
        self.set_font("Times", 'B', 14)
        self.cell(0, 10, "Vulnerability Memory Report", ln=1, align='C')

    def section_title(self, title):
        self.set_font("Times", 'B', 12)
        self.cell(0, 10, f"\n{title}", ln=1)

    def list_vulnerabilities(self, label, vulns):
        self.set_font("Times", 'B', 11)
        self.cell(0, 10, f"{label}:", ln=1)
        self.set_font("Times", '', 10)
        if not vulns:
            self.cell(0, 10, "  None found.", ln=1)
        for vuln in vulns:
            self.multi_cell(0, 8, f"[Line {vuln['line']}] {vuln['name']} ({vuln['severity']})")
            self.multi_cell(0, 8, f"  Description: {vuln['description']}")
            self.multi_cell(0, 8, f"  Suggestion : {vuln['suggestion']}")
            self.multi_cell(0, 8, f"  OWASP Tag  : {vuln['owasp']}")
            self.set_font("Times", 'I', 10)
            self.cell(0, 8, "  Memory Behavior:", ln=1)
            self.set_font("Times", '', 10)
            for point in vuln['memory']:
                self.multi_cell(0, 7, f"    - {point}")
            self.ln(2)

# === Scanner Function ===
def scan_file(filename):
    vulnerabilities = []
    with open(filename, 'r') as file:
        lines = file.readlines()
    for line_num, line in enumerate(lines, 1):
        for pattern in vulnerability_patterns:
            if pattern['regex'].search(line):
                vulnerabilities.append({
                    'line': line_num,
                    'name': pattern['name'],
                    'description': pattern['description'],
                    'suggestion': pattern['suggestion'],
                    'severity': pattern['severity'],
                    'owasp': pattern['owasp'],
                    'memory': pattern['memory']
                })
    return vulnerabilities

# === Comparator ===
def diff(before, after):
    removed = [v for v in before if v not in after]
    added = [v for v in after if v not in before]
    common = [v for v in before if v in after]
    return removed, added, common

# === Main ===
def main():
    parser = argparse.ArgumentParser(description="Compare memory-based vulnerabilities in two C files.")
    parser.add_argument("before", help="Original C file (before)")
    parser.add_argument("after", help="Updated C file (after)")
    args = parser.parse_args()

    before_vulns = scan_file(args.before)
    after_vulns = scan_file(args.after)

    removed, added, still_present = diff(before_vulns, after_vulns)

    pdf = PDF()
    pdf.add_page()

    pdf.section_title(f"Files Compared: {args.before} --> {args.after}")
    pdf.section_title(f"Total (Before): {len(before_vulns)}  |  Total (After): {len(after_vulns)}")

    pdf.section_title("Fixed Vulnerabilities")
    pdf.list_vulnerabilities("Resolved", removed)

    pdf.section_title("New Vulnerabilities Introduced")
    pdf.list_vulnerabilities("Introduced", added)

    pdf.section_title("Still Present Vulnerabilities")
    pdf.list_vulnerabilities("Unresolved", still_present)

    pdf.output("Vulnerability Report.pdf")
    print("Report saved as 'Vulnerability Report.pdf'")

if __name__ == "__main__":
    main()
