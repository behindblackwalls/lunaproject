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
    pattern = re.compile(r'(?<![\'\"])access_token|id_token|refresh_token(?![\'\"])')
    return pattern.findall(code)

def find_console_log_statements(code):
    pattern = re.compile(r'console\.log\([^)]*?\)')
    return pattern.findall(code)

def main():
    file_path = get_file_path()
    if file_path:
        code = read_js_file(file_path)

        insecure_functions = find_insecure_functions(code)
        hardcoded_tokens = find_hardcoded_tokens(code)
        console_log_statements = find_console_log_statements(code)

        print("Insecure Functions Found: ", insecure_functions)
        print("Hardcoded Tokens Found: ", hardcoded_tokens)
        print("Console Log Statements Found: ", console_log_statements)

if __name__ == "__main__":
    main()
