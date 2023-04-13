import re
import os
import json


class VulnerabilityScanner:
    def __init__(self):
        self.insecure_functions = [
            'eval',
            'setTimeout',
            'setInterval',
            'exec',
            'Function'
        ]
        self.token_names = [
            'access_token',
            'id_token',
            'refresh_token'
        ]
        self.storage_names = [
            'localStorage',
            'sessionStorage'
        ]

    def get_file_path(self):
        file_path = input("Enter the filepath of the JavaScript file: ")
        if not os.path.exists(file_path):
            print("File not found. Please check the file path and try again.")
            return None
        return file_path

    def read_js_file(self, file_path):
        with open(file_path, 'r') as file:
            return file.read()

    def find_pattern(self, code, pattern):
        regex = re.compile(pattern)
        return regex.findall(code)

    def find_insecure_functions(self, code):
        found_functions = []

        for func in self.insecure_functions:
            pattern = r'\b' + re.escape(func) + r'\b'
            matches = self.find_pattern(code, pattern)
            if matches:
                found_functions.append(func)

        return found_functions

    # ... Add other vulnerability search functions here ...

    def analyze_code(self, code):
        results = {
            "insecure_functions": self.find_insecure_functions(code),
            # ... Add other vulnerability search results here ...
        }
        return results

    def print_results(self, results):
        print(json.dumps(results, indent=2))

    def run(self):
        file_path = self.get_file_path()
        if file_path:
            code = self.read_js_file(file_path)
            results = self.analyze_code(code)
            self.print_results(results)

if __name__ == "__main__":
    scanner = VulnerabilityScanner()
    scanner.run()

class VulnerabilityScanner:
    # ... Previous code ...

    def find_hardcoded_tokens(self, code):
        pattern = r'\b(?:' + '|'.join(self.token_names) + r')\b\s*[:=]\s*["\'][^"\']*["\']'
        return self.find_pattern(code, pattern)

    def find_token_leakage(self, code):
        leakage_patterns = [
            r'\bconsole.log\([^)]*?(' + '|'.join(self.token_names) + r')[^)]*?\)',
            r'\b(' + '|'.join(self.token_names) + r')\b.*?=.*?\b(' + '|'.join(self.storage_names) + r')\b',
            r'\b(' + '|'.join(self.storage_names) + r')\b.*?=.*?\b(' + '|'.join(self.token_names) + r')\b',
        ]
        found_leakage = []

        for pattern in leakage_patterns:
            leakage = self.find_pattern(code, pattern)
            if leakage:
                found_leakage.extend(leakage)

        return found_leakage

    def find_token_validation_issues(self, code):
        validation_patterns = [
            r'\b(?:' + '|'.join(self.token_names) + r')\b\s*==',
            r'\b(?:' + '|'.join(self.token_names) + r')\b\s*!=',
            r'\b==\s*(?:' + '|'.join(self.token_names) + r')\b',
            r'\b!=\s*(?:' + '|'.join(self.token_names) + r')\b',
        ]
        found_issues = []

        for pattern in validation_patterns:
            issues = self.find_pattern(code, pattern)
            if issues:
                found_issues.extend(issues)

        return found_issues

    # ... Add other vulnerability search functions here ...

    def analyze_code(self, code):
        results = {
            "insecure_functions": self.find_insecure_functions(code),
            "hardcoded_tokens": self.find_hardcoded_tokens(code),
            "token_leakage": self.find_token_leakage(code),
            "token_validation_issues": self.find_token_validation_issues(code),
            # ... Add other vulnerability search results here ...
        }
        return results

