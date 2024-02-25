import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"

# Function to get all forms
def get_forms(url):
    soup = BeautifulSoup(s.get(url).content, "html.parser")
    return soup.find_all("form")

# Function to get form details
def form_details(form):
    details_of_form = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get")
    inputs = []

    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({
            "type": input_type,
            "name": input_name,
            "value": input_value,
        })

    details_of_form['action'] = action
    details_of_form['method'] = method
    details_of_form['inputs'] = inputs
    return details_of_form

# Function to check for XSS vulnerabilities
def check_xss_vulnerability(url):
    try:
        # Send a GET request to the URL
        response = s.get(url)

        # Check if the response contains potential XSS indicators
        xss_patterns = ["<script>", "onerror", "javascript:"]

        if any(pattern in response.text.lower() for pattern in xss_patterns):
            print(f"The URL '{url}' has potential XSS vulnerability.")
        else:
            print(f"The URL '{url}' does not have XSS vulnerability.")

    except requests.RequestException as e:
        print(f"An error occurred while checking for XSS vulnerability: {e}")

# Function to check for CSRF vulnerabilities
def check_csrf_vulnerability(url):
    try:
        # Send a GET request to the URL
        response = s.get(url)

        # Check if the response contains potential CSRF indicators
        csrf_patterns = ["<input type=\"hidden\" name=\"csrf_token\" value=", "csrf_token="]

        if any(pattern in response.text for pattern in csrf_patterns):
            print(f"The URL '{url}' has potential CSRF vulnerability.")
        else:
            print(f"The URL '{url}' does not have CSRF vulnerability.")

    except requests.RequestException as e:
        print(f"An error occurred while checking for CSRF vulnerability: {e}")

# Function to check for SQL injection vulnerabilities
def vulnerable(response):
    errors = {"quoted string not properly terminated",
              "unclosed quotation mark after the character string",
              "you have an error in you SQL syntax"
              }
    for error in errors:
        if error in response.content.decode().lower():
            return True
    return False

def sql_injection_scan(url):
    forms = get_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")

    for form in forms:
        details = form_details(form)

        for i in "\"'":
            data = {}
            for input_tag in details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    data[input_tag['name']] = input_tag["value"] + i
                elif input_tag["type"] != "submit":
                    data[input_tag['name']] = f"test{i}"

            print(url)
            form_details(form)

            if details["method"] == "post":
                res = s.post(url, data=data)
            elif details["method"] == "get":
                res = s.get(url, params=data)
            if vulnerable(res):
                print("SQL injection attack vulnerability in link: ", url)
            else:
                print("No SQL injection attack vulnerability detected")
                break

if __name__ == "__main__":
    url_to_be_checked = input("Enter the URL to check for vulnerabilities: ")

    # Call the functions to check XSS, CSRF, and SQL injection vulnerabilities
    check_xss_vulnerability(url_to_be_checked)
    check_csrf_vulnerability(url_to_be_checked)
    sql_injection_scan(url_to_be_checked)
