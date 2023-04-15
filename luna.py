import re
import os
import sys
import argparse
from typing import List, Tuple
import subprocess
import requests
from bs4 import BeautifulSoup
import json
from py_mini_racer import py_mini_racer
import hashlib
from termcolor import colored
import configparser
from severity import calculate_severity_score, get_severity_label

# Read configuration file
config = configparser.ConfigParser()
config.read("config.ini")

# Assign paths from the config file
codeql_executable = config.get("paths", "codeql_executable")
codeql_database = config.get("paths", "codeql_database")
target_directory = config.get("paths", "target_directory")
query_suites_folder = config.get("paths", "query_suites_folder")
javascript_code_scanning_qls = os.path.join(query_suites_folder, "javascript-code-scanning.qls")

def execute_js_function(code: str, function_name: str, *args) -> str:
    ctx = py_mini_racer.MiniRacer()
    ctx.eval(code)
    result = ctx.call(function_name, *args)
    return result

def check_sensitive_data_exposure(code: str) -> List[Tuple[str, int]]:
    sensitive_data_patterns = [
        r'password\b',
        r'secret\b',
        r'api[-_]?key\b',
        r'(?:\b|_)token(?:\b|_)',
    ]
    found_sensitive_data = []

    for pattern in sensitive_data_patterns:
        regex = re.compile(pattern, re.IGNORECASE)
        matches = regex.finditer(code)

        for match in matches:
            found_sensitive_data.append((match.group(), match.start()))

    return found_sensitive_data

def check_weak_hashing_algorithms(code: str) -> List[Tuple[str, int]]:
    weak_algorithms = [
        'md5',
        'sha1',
    ]
    found_weak_algorithms = []

    for algorithm in weak_algorithms:
        pattern = re.compile(r'\b' + re.escape(algorithm) + r'\b', re.IGNORECASE)
        matches = pattern.finditer(code)

        for match in matches:
            found_weak_algorithms.append((match.group(), match.start()))

    return found_weak_algorithms

def extractCodeSegment(file_path, position, lines_before, lines_after):
    with open(file_path, 'r') as file:
        file_content = file.read()
    lines = file_content.split('\n')
    line_number = file_content[:position].count('\n')

    start_line = max(0, line_number - lines_before)
    end_line = min(len(lines) - 1, line_number + lines_after)

    return '\n'.join(lines[start_line:end_line + 1])

def get_file_path():
    file_path = input("Enter the filepath of the JavaScript file: ")
    if not os.path.exists(file_path):
        print("File not found. Please check the file path and try again.")
        return None
    return file_path

def read_js_file(file_path):
    with open(file_path, 'r') as file:
        return file.read()

def find_insecure_functions(code):
    insecure_functions = [
        'eval',
        'setTimeout',
        'setInterval',
        'exec',
        'Function'
    ]
    found_functions = []

    for func in insecure_functions:
        pattern = re.compile(r'\b' + re.escape(func) + r'\b')
        matches = pattern.finditer(code)
        for match in matches:
            found_functions.append((func, match.start(), match.group()))

    return found_functions

def find_hardcoded_tokens(code):
    pattern = re.compile(r'(?<![\'\"])access_token|id_token|refresh_token(?![\'\"])')
    matches = pattern.finditer(code)
    found_tokens = []
    for match in matches:
        found_tokens.append((match.group(), match.start()))

    return found_tokens

def find_console_log_statements(code):
    pattern = re.compile(r'console\.log\([^)]*?\)')
    matches = pattern.finditer(code)
    found_statements = []
    for match in matches:
        found_statements.append((match.group(), match.start()))

    return found_statements

def find_dom_xss(code):
    pattern = re.compile(r'\.innerHTML\s*=\s*[^\n]+')
    matches = pattern.finditer(code)
    found_xss = []
    for match in matches:
        found_xss.append((match.group(), match.start()))

    return found_xss

def print_results(title, results, verbose, file_path):
    print(f"\n{title}:")
    for result in results:
        print(f"  {result[0]}, Position: {result[1]}")

        if verbose:
            print("\nCode segment:")
            print(extractCodeSegment(file_path, result[1], 5, 5))
            print("-" * 40)

def check_xss_vulnerabilities(code: str) -> List[Tuple[str, int]]:
    xss_patterns = [
        r'\.innerHTML\b',
        r'\.outerHTML\b',
    ]
    found_xss_vulnerabilities = []

    for pattern in xss_patterns:
        regex = re.compile(pattern, re.IGNORECASE)
        matches = regex.finditer(code)

        for match in matches:
            found_xss_vulnerabilities.append((match.group(), match.start()))

    return found_xss_vulnerabilities

# Helper function to execute a JavaScript function within the provided code using py_mini_racer
def execute_js_function(code: str, function_name: str, *args) -> str:
    ctx = py_mini_racer.MiniRacer()
    ctx.eval(code)
    result = ctx.call(function_name, *args)
    return result

# Function to check for the exposure of sensitive data in the code, such as passwords or API keys
def check_sensitive_data_exposure(code: str) -> List[Tuple[str, int]]:
    sensitive_data_patterns = [
        r'password\b',
        r'secret\b',
        r'api[-_]?key\b',
        r'(?:\b|_)token(?:\b|_)',
    ]
    found_sensitive_data = []

    for pattern in sensitive_data_patterns:
        regex = re.compile(pattern, re.IGNORECASE)
        matches = regex.finditer(code)

        for match in matches:
            found_sensitive_data.append((match.group(), match.start()))

    return found_sensitive_data

# Function to check for the use of weak hashing algorithms in the code, such as MD5 or SHA-1
def check_weak_hashing_algorithms(code: str) -> List[Tuple[str, int]]:
    weak_algorithms = [
        'md5',
        'sha1',
    ]
    found_weak_algorithms = []

    for algorithm in weak_algorithms:
        pattern = re.compile(r'\b' + re.escape(algorithm) + r'\b', re.IGNORECASE)
        matches = pattern.finditer(code)

        for match in matches:
            found_weak_algorithms.append((match.group(), match.start()))

    return found_weak_algorithms

# Function to check for potential XSS vulnerabilities in the code, such as the use of innerHTML or outerHTML
def check_xss_vulnerabilities(code: str) -> List[Tuple[str, int]]:
    xss_patterns = [
        r'\.innerHTML\b',
        r'\.outerHTML\b',
    ]
    found_xss_vulnerabilities = []

    for pattern in xss_patterns:
        regex = re.compile(pattern, re.IGNORECASE)
        matches = regex.finditer(code)

        for match in matches:
            found_xss_vulnerabilities.append((match.group(), match.start()))

    return found_xss_vulnerabilities

def analyze_code_for_vulnerabilities(code: str):
    # Check for insecure functions
    insecure_functions = find_insecure_functions(code)
    if insecure_functions:
        print("\nInsecure Functions Found:")
        for function, position in insecure_functions:
            print(f"  {function}, Position: {position}")

    # Check for sensitive data exposure
    sensitive_data_exposure = check_sensitive_data_exposure(code)
    if sensitive_data_exposure:
        print("\nSensitive Data Exposure:")
        for data, position in sensitive_data_exposure:
            print(f"  {data}, Position: {position}")

    # Check for weak hashing algorithms
    weak_hashing_algorithms = check_weak_hashing_algorithms(code)
    if weak_hashing_algorithms:
        print("\nWeak Hashing Algorithms Found:")
        for algorithm, position in weak_hashing_algorithms:
            print(f"  {algorithm}, Position: {position}")

    # Check for XSS vulnerabilities
    xss_vulnerabilities = check_xss_vulnerabilities(code)
    if xss_vulnerabilities:
        print("\nPotential XSS Vulnerabilities Found:")
        for vulnerability, position in xss_vulnerabilities:
            print(f"  {vulnerability}, Position: {position}")

def find_insecure_http(code):
    pattern = re.compile(r'http:\/\/')
    matches = pattern.finditer(code)
    found_http = []

    for match in matches:
        found_http.append(('http', match.start()))

    return found_http

def find_hardcoded_secrets(code):
    pattern = re.compile(r'(?:(?<=\W)|^)(?:password|secret|apikey)(?:(?=\W)|$)', re.IGNORECASE)
    matches = pattern.finditer(code)
    found_secrets = []

    for match in matches:
        found_secrets.append((match.group(), match.start()))

    return found_secrets

def find_xss_vulnerabilities(code):
    ctx = py_mini_racer.MiniRacer()
    ctx.eval("var window = {};")  # Mocking the window object
    ctx.eval("var document = {};")  # Mocking the document object

    soup = BeautifulSoup(code, 'html.parser')
    script_tags = soup.find_all('script')

    xss_vulnerabilities = []

    for script in script_tags:
        script_code = script.string
        if script_code:
            try:
                ctx.eval(script_code)
            except Exception as e:
                xss_vulnerabilities.append((script_code, str(e)))

    return xss_vulnerabilities

def categorize_finding_severity(category, finding):
    if category in ['insecure_functions', 'xss_vulnerabilities']:
        if finding in ['eval', 'document.write', 'document.writeln']:
            return "Critical Severity"
        elif finding in ['setTimeout', 'setInterval']:
            return "High Severity"
        else:
            return "Medium Severity"
    elif category in ['hardcoded_tokens', 'hardcoded_secrets']:
        return "High Severity"
    elif category in ['console_log_statements']:
        return "Low Severity"
    elif category in ['insecure_http']:
        return "Medium Severity"
    elif category in ['eslint_warnings_errors']:
        severity = finding['severity']
        if severity == 2:
            return "High Severity"
        else:
            return "Low Severity"
    else:
        return "Unknown Severity"


def run_eslint(file_path):
    try:
        import eslint_runner
        eslint_output = eslint_runner.run(file_path)
        return json.loads(eslint_output)
    except Exception as e:
        print(f"Error running ESLint: {e}")
        return {'messages': []}

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--verbose", help="increase output verbosity", action="store_true")
    args = parser.parse_args()
    return args


def run_codeql_analysis():
    # Initialize a CodeQL database
    subprocess.run(["codeql", "database", "init", "--language=javascript", "--source-root", ".", "codeql-database"])

    # Analyze the CodeQL database
    subprocess.run(["codeql", "database", "analyze", "codeql-database", "javascript-code-scanning.qls", "--format=sarif-latest", "--output=results.sarif"])

def run_codeql_analysis(codeql_executable, codeql_database, target_directory):
    # Create the CodeQL database
    subprocess.run([codeql_executable, "database", "create", codeql_database, "--language=javascript", "--source-root", target_directory, "--overwrite"], check=True)


    # Run the CodeQL analysis
    subprocess.run([codeql_executable, "database", "analyze", codeql_database, "--format=sarif-latest", "--output=codeql-results.sarif", "--no-sarif-add-snippets", "--search-path", query_suites_folder, javascript_code_scanning_qls], check=True)

def parse_codeql_results(sarif_file):
    with open(sarif_file, 'r') as f:
        sarif_data = json.load(f)

    results = []

    for run in sarif_data['runs']:
        tool = run['tool']['driver']['name']
        for result in run['results']:
            message = result['message']['text']
            rule_id = result['ruleId']
            severity = result['properties']['issue_severity']

def main():
    args = parse_args()
    file_path = input("Enter the filepath of the JavaScript file: ")

    if file_path:
        # Read the contents of the JavaScript file
        code = read_js_file(file_path)

        # Run CodeQL analysis
        run_codeql_analysis(codeql_executable, codeql_database, target_directory)
        codeql_results = parse_codeql_results("codeql-results.sarif")

        # Run ESLint analysis
        eslint_results = run_eslint(file_path)

        # Run custom analysis functions on the source code
        analysis_results = {
            'eslint_warnings_errors': eslint_results,
            'insecure_functions': find_insecure_functions(code),
            'hardcoded_tokens': find_hardcoded_tokens(code),
            'console_log_statements': find_console_log_statements(code),
            'insecure_http': find_insecure_http(code),
            'hardcoded_secrets': find_hardcoded_secrets(code),
            'xss_vulnerabilities': find_xss_vulnerabilities(code),
            'codeql_findings': codeql_results,
        }

        # Print the analysis results
        print("\n" + colored("Analysis Results:", "cyan", attrs=["bold"]))

        for category, findings in analysis_results.items():
            print("\n" + colored(f"{category.capitalize().replace('_', ' ')} Found:", "yellow", attrs=["bold"]))
            if findings:
                for finding in findings:
                    if category == 'eslint_warnings_errors':
                        for eslint_finding in finding['messages']:
                            severity = 'Error' if eslint_finding['severity'] == 2 else 'Warning'
                            print(colored(f"  {severity}: ", "red" if severity == "Error" else "yellow") + f"{eslint_finding['message']} (Line: {eslint_finding['line']}, Column: {eslint_finding['column']})")
                    elif category == 'codeql_findings':
                        severity = finding['severity']
                        print(colored(f"  {severity}: ", "red" if severity == "Critical Severity" else ("yellow" if severity == "High Severity" else "green")) + f"{finding['message']} (Rule ID: {finding['rule_id']})")
                    else:
                        severity_label = get_severity_label(category)
                        color = "red" if severity_label == "Critical Severity" else ("yellow" if severity_label == "High Severity" else "green")
                        vulnerability_info = finding[3] if len(finding) > 3 else "Not available"
                        line_of_code = finding[2] if len(finding) > 2 else "Not available"
                        print(colored(f"  {severity_label}: ", color) + f"{finding[0]} (Position: {finding[1]}, Line of Code: {line_of_code}, Vulnerability Info: {vulnerability_info})")

            else:
                print("  No findings")

if __name__ == "__main__":
    main()
