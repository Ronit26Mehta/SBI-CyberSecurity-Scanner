# demo code just to see if the app works properly
def perform_static_analysis(code):
    issues = [
        {"line": 10, "type": "SQL Injection", "description": "Possible SQL injection vulnerability."},
        {"line": 25, "type": "XSS", "description": "Potential cross-site scripting vulnerability."}
    ]
    return issues