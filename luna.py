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


def main():
    file_path = get_file_path()
    if file_path:
        code = read_js_file(file_path)

        insecure_functions = find_insecure_functions(code)
        hardcoded_tokens = find_hardcoded_tokens(code)
        console_log_statements = find_console_log_statements(code)

        print("Insecure Functions Found:")
        for func, position, matched in insecure_functions:
            print(f"  Function: {func}, Position: {position}, Matched: {matched}")

        print("Hardcoded Tokens Found:")
        for token, position in hardcoded_tokens:
            print(f"  Token: {token}, Position: {position}")

        print("Console Log Statements Found:")
        for statement, position in console_log_statements:
            print(f"  Statement: {statement}, Position: {position}")

        if args.verbose:
            # Display code segments for insecure functions
            for func, position, matched in insecure_functions:
                print(f'\nCode segment for function: {func}')
                print(extractCodeSegment(file_path, position, 5, 5))

            # Display code segments for hardcoded tokens
            for token, position in hardcoded_tokens:
                print(f'\nCode segment for token: {token}')
                print(extractCodeSegment(file_path, position, 5, 5))

            # Display code segments for console log statements
            for statement, position in console_log_statements:
                print(f'\nCode segment for console log statement: {statement}')
                print(extractCodeSegment(file_path, position, 5, 5))


parser = argparse.ArgumentParser(description='Analyze JavaScript file for security issues.')
parser.add_argument('--verbose', action='store_true', help='Display code segments')

args = parser.parse_args()

if __name__ == "__main__":
    main()
