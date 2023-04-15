def calculate_severity_score(finding, category, eslint_data, codeql_data):
    score = 0
    weightings = {
        'insecure_functions': 2,
        'hardcoded_tokens': 1,
        'console_log_statements': 1,
        'insecure_http': 2,
        'hardcoded_secrets': 3,
        'xss_vulnerabilities': 3,
    }

    if score < 250:
        return "Low Severity"
    elif score < 500:
        return "Medium Severity"
    elif score < 750:
        return "High Severity"
    else:
        return "Critical Severity"

def get_severity_label(finding):
    severity_mapping = {
        'insecure_functions': 'High Severity',
        'hardcoded_tokens': 'Low Severity',
        'console_log_statements': 'Low Severity',
        'insecure_http': 'Medium Severity',
        'hardcoded_secrets': 'Critical Severity',
        'xss_vulnerabilities': 'High Severity',
    }
    return severity_mapping[finding]

