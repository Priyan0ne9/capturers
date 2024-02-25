import requests
import re

def check_xss_vulnerability(url):
    try:
        # Send a GET request to the URL
        response = requests.get(url)

        # Check if the response contains potential XSS indicators
        xss_patterns = ["<script>", "onerror", "javascript:"]

        if any(pattern in response.text.lower() for pattern in xss_patterns):
            print(f"The URL '{url}' has potential XSS vulnerability.")
        else:
            print(f"The URL '{url}' does not have XSS vulnerability.")

    except requests.RequestException as e:
        print(f"An error occurred while checking for XSS vulnerability: {e}")

def check_csrf_vulnerability(url):
    try:
        # Send a GET request to the URL
        response = requests.get(url)

        # Check if the response contains potential CSRF indicators
        csrf_patterns = ["<input type=\"hidden\" name=\"csrf_token\" value=", "csrf_token="]

        if any(pattern in response.text for pattern in csrf_patterns):
            print(f"The URL '{url}' has potential CSRF vulnerability.")
        else:
            print(f"The URL '{url}' does not have CSRF vulnerability.")

    except requests.RequestException as e:
        print(f"An error occurred while checking for CSRF vulnerability: {e}")

if __name__ == "__main__":
    # Get URL input from the user
    url = input("Enter the URL to check for vulnerabilities: ")

    # Call the functions to check XSS and CSRF vulnerabilities
    check_xss_vulnerability(url)
    check_csrf_vulnerability(url)
