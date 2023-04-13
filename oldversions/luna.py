import re
import os

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
        if pattern.search(code):
            found_functions.append(func)

    return found_functions

def find_hardcoded_tokens(code):
    pattern = re.compile(r'\b(?:access_token|id_token|refresh_token)\b\s*[:=]\s*["\'][^"\']*["\']')
    return pattern.findall(code)

def find_token_leakage(code):
    leakage_patterns = [
        r'\bconsole.log\([^)]*?(?:access_token|id_token|refresh_token)[^)]*?\)',
        r'\b(?:access_token|id_token|refresh_token)\b.*?=.*?\b(?:localStorage|sessionStorage)\b',
        r'\b(?:localStorage|sessionStorage)\b.*?=.*?\b(?:access_token|id_token|refresh_token)\b',
    ]
    found_leakage = []

    for pattern in leakage_patterns:
        regex = re.compile(pattern)
        leakage = regex.findall(code)
        if leakage:
            found_leakage.extend(leakage)

    return found_leakage

def find_token_validation_issues(code):
    validation_patterns = [
        r'\b(?:access_token|id_token|refresh_token)\b\s*==',
        r'\b(?:access_token|id_token|refresh_token)\b\s*!=',
        r'\b==\s*(?:access_token|id_token|refresh_token)\b',
        r'\b!=\s*(?:access_token|id_token|refresh_token)\b',
    ]
    found_issues = []

    for pattern in validation_patterns:
        regex = re.compile(pattern)
        issues = regex.findall(code)
        if issues:
            found_issues.extend(issues)

    return found_issues

def find_token_endpoint_security(code):
    endpoint_patterns = [
        r'\btoken_endpoint\b\s*[:=]\s*["\'][^"\']*["\']',
        r'\btoken_endpoint\s*[:=]\s*[^{]*?\{(?:[^}]*?["\'][^"\']*["\'])?[^}]*?\}',
    ]
    found_endpoints = []

    for pattern in endpoint_patterns:
        regex = re.compile(pattern)
        endpoints = regex.findall(code)
        if endpoints:
            found_endpoints.extend(endpoints)

    return found_endpoints

def find_token_refresh_vulnerabilities(code):
    refresh_patterns = [
        r'\brefresh_token_expires_in\b\s*[:=]\s*\d+',
        r'\brefresh_token\b\s*[:=]\s*["\'][^"\']*["\']',
    ]
    found_refresh_vulns = []

    for pattern in refresh_patterns:
        regex = re.compile(pattern)
        refresh_vulns = regex.findall(code)
        if refresh_vulns:
            found_refresh_vulns.extend(refresh_vulns)

    return found_refresh_vulns

def find_error_handling_issues(code):
    error_handling_patterns = [
        r'\b(?:try\s*\{[^}]*\}\s*catch\s*\([^)]*\)\s*\{[^}]*\})',
    ]
    found_issues = []

    for pattern in error_handling_patterns:
        regex = re.compile(pattern)
        issues = regex.findall(code)
        if issues:
            found_issues.extend(issues)

    return found_issues

def main():
    file_path = get_file_path()
    if file_path:
        code = read_js_file(file_path)

        insecure_functions = find_insecure_functions(code)
        hardcoded_tokens = find_hardcoded_tokens(code)
        token_leakage = find_token_leakage(code)
        token_validation_issues = find_token_validation_issues(code)
        token_endpoint_security = find_token_endpoint_security(code)
        token_refresh_vulnerabilities = find_token_refresh_vulnerabilities(code)
        error_handling_issues = find_error_handling_issues(code)

        print("Insecure Functions Found: ", insecure_functions)
        print("Hardcoded Tokens Found: ", hardcoded_tokens)
        print("Token Leakage Found: ", token_leakage)
        print("Token Validation Issues Found: ", token_validation_issues)
        print("Token Endpoint Security Issues Found: ", token_endpoint_security)
        print("Token Refresh Vulnerabilities Found: ", token_refresh_vulnerabilities)
        print("Error Handling Issues Found: ", error_handling_issues)

if __name__ == "__main__":
    main()
