import re
import os

# Define patterns for common vulnerabilities (also implemented the use of regex!)
PATTERNS = {
    r'\beval\s*\(': "Use of eval() allows arbitrary code execution and is unsafe.",
    r'\bexec\s*\(': "Use of exec() can execute arbitrary code and poses a security risk.",
    r'\bos\.system\s*\(': "os.system() can lead to command injection vulnerabilities.",
    r'\bsubprocess\.\w+\s*\(': "Improper use of subprocess functions can lead to command injection.",
    r'pickle\s*\(': "Using pickle can execute arbitrary code if the data is untrusted.",
    r'input\s*\(': "Unvalidated input() can lead to security vulnerabilities.",
    r'try\s*:\s*.*?except\s*:': "Broad try-except blocks can mask critical errors.",
}

def detect_zero_division(lines):
    """
    Detect potential zero-division or NaN-related issues in code.
    """
    results = []
    for i, line in enumerate(lines):
        # Look for division, floor division, or modulo operations
        if '/' in line or '//' in line or '%' in line:
            # Check if the divisor might be zero or NaN (invalid)
            if re.search(r'(/|//|%)\s*(0|NaN)', line):
                results.append({
                    "line_number": i + 1,
                    "line": line.strip(),
                    "issue": "Potential zero-division or invalid operation detected."
                })
    return results
#regex
def detect_vulnerabilities(lines):
    """
    Scan code lines for vulnerabilities based on defined regex patterns.
    """
    results = []
    for i, line in enumerate(lines):
        for pattern, message in PATTERNS.items():
            if re.search(pattern, line):
                results.append({
                    "line_number": i + 1,
                    "line": line.strip(),
                    "issue": message
                })
    return results

def scan_code(lines):
    """
    Combine all vulnerability detection methods into a single scanning function.
    """
    results = []
    results.extend(detect_vulnerabilities(lines))  # Check for common vulnerabilities via regex
    results.extend(detect_zero_division(lines))  # Check for zero-division vulnerabilities
    return results

def load_file(file_path):
    """
    Safely load the contents of a code file.
    """
    try:
        with open(file_path, 'r') as file:
            return file.readlines()
    except Exception as e:
        print(f"Error loading file: {e}")
        return []

def generate_report(results, file_path=None):
    """
    Generate a detailed vulnerability report.
    """
    if not results:
        print("\nNo vulnerabilities found!")
        return
    
    print("\nPotential vulnerabilities detected:")
    report_lines = []
    for result in results:
        report = f"Line {result['line_number']}: {result['line']}\n  Issue: {result['issue']}\n"
        print(report)
        report_lines.append(report)
    
    if file_path:
        try:
            with open(file_path, 'w') as report_file:
                report_file.writelines(report_lines)
            print(f"\nReport saved to {file_path}")
        except Exception as e:
            print(f"Error saving report: {e}")

def single_file_scan():
    """
    Scan a single Python file for vulnerabilities.
    """
    file_path = input("Enter the path to the Python file: ").strip()
    if os.path.exists(file_path):
        lines = load_file(file_path)
        results = scan_code(lines)
        report_file = f"{os.path.splitext(file_path)[0]}_report.txt"
        generate_report(results, report_file)
    else:
        print("Invalid file path. Please try again.")

def main():
    """
    Main interactive menu for the scanner.
    """
    while True:
        print("\nSecurity Code Scanner")
        print("1. Scan a single file")
        print("2. Exit")
        
        choice = input("Enter your choice (1/2): ").strip()
        if choice == '1':
            single_file_scan()
        elif choice == '2':
            print("Exiting the scanner. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
