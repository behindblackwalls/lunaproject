import re
import os
import sys
import argparse

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
