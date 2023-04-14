import re
import os
import sys
import argparse
from typing import List, Tuple

import requests
from bs4 import BeautifulSoup

import json
from py_mini_racer import py_mini_racer
import hashlib

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


# Update main function to call the new analyze_code_for_vulnerabilities function
def main():
    # ... previous code ...
    
    if args.verbose:
        print(f"Reading JavaScript file: {file_path}")
    
    with open(file_path, 'r', encoding='utf-8') as f:
        code = f.read()

    # Call the analyze_code_for_vulnerabilities function
    analyze_code_for_vulnerabilities(code)

def main():
    file_path = get_file_path()
    if file_path:
        code = read_js_file(file_path)

        insecure_functions = find_insecure_functions(code)
        hardcoded_tokens = find_hardcoded_tokens(code)
        console_log_statements = find_console_log_statements(code)
        dom_xss = find_dom_xss(code)

        verbose = args.verbose

        print_results("Insecure Functions Found", insecure_functions, verbose, file_path)

        print_results("Hardcoded Tokens Found", hardcoded_tokens, verbose, file_path)

        print_results("Console Log Statements Found", console_log_statements, verbose, file_path)

        print_results("Possible DOM XSS Found", dom_xss, verbose, file_path)

parser = argparse.ArgumentParser(description='Analyze JavaScript file for security issues.')
parser.add_argument('--verbose', action='store_true', help='Display code segments')

args = parser.parse_args()

if __name__ == "__main__":
    main()
