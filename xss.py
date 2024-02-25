import requests

def check_xss_vulnerability(url):
    try:
        # Send a GET request to the URL
        response = requests.get(url)

        # Check if the response contains potential XSS indicators
        if '<script>' in response.text:
            print(f"The URL '{url}' has potential XSS vulnerability.")
        else:
            print(f"The URL '{url}' does not have XSS vulnerability.")

    except requests.RequestException as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    # Get URL input from the user
    url = input("Enter the URL to check for XSS vulnerability: ")

    # Call the function to check XSS vulnerability
    check_xss_vulnerability(url)
