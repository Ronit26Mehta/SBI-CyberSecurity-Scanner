import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36"


def get_forms(url):
    # Make a GET request to the URL and parse the HTML content with BeautifulSoup
    soup = BeautifulSoup(s.get(url).content, "html.parser")
    # Find all form tags on the page and return them
    return soup.find_all("form")


def form_details(form):
    details_of_form = {}
    # Get the form action and method
    details_of_form["action"] = form.attrs.get("action", "").lower()
    details_of_form["method"] = form.attrs.get("method", "get").lower()

    # Get all input details
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})
    details_of_form["inputs"] = inputs

    return details_of_form


def vulnerable(response):
    errors = {
        "quoted string not properly terminated",
        "unclosed quotation mark after the character string",
        "you have an error in your sql syntax;",
    }
    for error in errors:
        if error in response.content.decode().lower():
            return True
    return False


def sql_injection_scan(url):
    forms = get_forms(url)
    results = []
    for form in forms:
        details = form_details(form)

        for c in "\"'":
            data = {}
            for input_tag in details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    data[input_tag["name"]] = input_tag["value"] + c
                elif input_tag["type"] != "submit":
                    data[input_tag["name"]] = f"test{c}"

            form_url = urljoin(url, details["action"])
            if details["method"] == "post":
                res = s.post(form_url, data=data)
            elif details["method"] == "get":
                res = s.get(form_url, params=data)

            if vulnerable(res):
                results.append(f"Vulnerable form detected at {form_url}")
                break  # Stop testing once a vulnerability is found

    if not results:
        results.append("No SQL Injection vulnerabilities detected.")

    return results


def detect_sql_injection(content):
    # Determine if the input is a URL or raw code
    if content.startswith("http://") or content.startswith("https://"):
        return sql_injection_scan(content)
    else:
        # For simplicity, this will act as a placeholder for detecting SQL vulnerabilities in raw code.
        # You can extend this logic to parse and analyze code for SQL-related vulnerabilities.
        if "SELECT * FROM" in content or "WHERE" in content:
            return ["Potential SQL Injection vulnerability detected in code."]
        return ["No SQL Injection vulnerabilities detected in code."]