import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import requests
from bs4 import BeautifulSoup
import builtwith
import dns.resolver
import socket
import ssl
import re
import streamlit

class WebsiteScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Website Scanner Tool")

        # Set a custom theme for a more modern look
        self.style = ttk.Style()
        self.style.theme_use("clam")

        # Customize the theme with vibrant colors
        self.style.configure("TLabel",
                             foreground="#3498db",    # Blue
                             font=("Helvetica", 14, "bold"))
        self.style.configure("TEntry",
                             foreground="#2c3e50",    # Dark Gray
                             font=("Helvetica", 12))
        self.style.configure("TButton",
                             foreground="#ffffff",    # Text color
                             background="#e74c3c",    # Red
                             font=("Helvetica", 12),
                             padding=(12, 6),
                             relief='flat',
                             borderwidth=0)  # Remove border for a cleaner look

        self.create_widgets()

    def create_widgets(self):
        # Set a different background color for the entire window
        self.root.configure(bg="#323643")  # Orange background

        # Header label at the top
        header_label = ttk.Label(self.root, text="Website Scanner Tool", style="TLabel", font=("Helvetica", 18, "bold"))
        header_label.grid(row=0, column=0, pady=10, sticky="w")


        # Increase the size of the text in the label and center-align it
        self.url_label = ttk.Label(self.root, text="Enter the target URL:", style="TLabel")
        self.url_label.grid(row=1, column=0, padx=(0, 5), pady=10, sticky="w")

        self.url_entry = ttk.Entry(self.root, width=40, style="TEntry")
        self.url_entry.grid(row=1, column=1, padx=10, pady=10, sticky="w")


        # Dynamically center-align all the widgets
        for col in range(2):  # Iterate through columns 0 and 1
            self.root.columnconfigure(col, weight=1)

        # Customize the appearance of the scan button with curved edges
        self.scan_button = ttk.Button(self.root, text="Scan Website", command=self.scan_website, style="TButton", width=15)
        self.scan_button.grid(row=2, column=0, columnspan=2, pady=15)

        # Make the "Scan Results" label dynamically adjustable and a little smaller in size
        font_size = 12
        self.result_label = ttk.Label(self.root, text="Scan Results:", style="TLabel", font=("Helvetica", 12, "bold"))
        self.result_label.grid(row=3, column=0, columnspan=2, padx=(0, 0), pady=5, sticky="w")

        # ScrolledText for a scrollable and styled output (smaller size)
        self.result_text = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, background="#F7F7F7", font=("Helvetica", 12))
        self.result_text.grid(row=4, column=0, columnspan=2, padx=5, pady=5, sticky="nsew")

        # Configure row and column weights
        for row in range(5):  # Iterate through rows 0 to 4
            self.root.rowconfigure(row, weight=1)

        # Allow the ScrolledText widget to expand or contract vertically
        self.root.rowconfigure(4, weight=1)
    def scan_website(self):
        target_url = self.url_entry.get()

        if not self.is_valid_url(target_url):
            messagebox.showerror("Error", "Invalid URL. Please enter a valid URL.")
            return

        results = self.perform_scan(target_url)
        self.display_results(results)

    def is_valid_url(self, url):
        try:
            response = requests.head(url)
            return response.status_code == 200
        except requests.RequestException:
            return False

    def perform_scan(self, url):
        results = {}

        common_directories = [
            "/",
            "/admin",
            "/login",
            "/wp-admin",
            "/uploads",
            "/backup",
            "/config",
            "/js",
            "/css",
        ]

        directory_results = {}
        for directory in common_directories:
            response = self.check_directory(url, directory)
            directory_results[directory] = response.status_code if response else "Failed"

        results["Directories"] = directory_results
        subdomains = self.get_subdomains(url)
        results["Subdomains"] = subdomains
        server_headers = self.get_server_headers(url)
        results["Server Headers"] = server_headers
        tech_info = self.get_technologies(url)
        results["Web Technologies"] = tech_info
        ssl_info = self.get_ssl_certificate(url)
        results["SSL Certificate Information"] = ssl_info

        # Adding XSS and CSRF checks
        xss_result = self.check_xss_vulnerability(url)
        results["XSS Vulnerability"] = xss_result

        csrf_result = self.check_csrf_vulnerability(url)
        results["CSRF Vulnerability"] = csrf_result

        # Adding SQL injection check
        sql_result = self.sql_injection_scan(url)
        results["SQL Injection Vulnerability"] = sql_result

        return results

    def check_xss_vulnerability(self, url):
        try:
            response = requests.get(url)
            if '<script>' in response.text:
                return "Potential XSS Vulnerability"
            else:
                return "No XSS Vulnerability"
        except requests.RequestException:
            return "Error checking XSS vulnerability"

    def check_csrf_vulnerability(self, url):
        try:
            response = requests.get(url)
            csrf_patterns = ["<input type=\"hidden\" name=\"csrf_token\" value=", "csrf_token="]
            if any(pattern in response.text for pattern in csrf_patterns):
                return "Potential CSRF Vulnerability"
            else:
                return "No CSRF Vulnerability"
        except requests.RequestException:
            return "Error checking CSRF vulnerability"

    def sql_injection_scan(self, url):
        s = requests.Session()
        s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"

        forms = self.get_forms(url)
        result = f"[+] Detected {len(forms)} forms on {url}.\n"

        for form in forms:
            details = self.form_details(form)

            for i in "\"'":
                data = {}
                for input_tag in details["inputs"]:
                    if input_tag["type"] == "hidden" or input_tag["value"]:
                        data[input_tag['name']] = input_tag["value"] + i
                    elif input_tag["type"] != "submit":
                        data[input_tag['name']] = f"test{i}"

                result += f"{url}\n"
                result += f"Form Details: {details}\n"

                if details["method"] == "post":
                    res = s.post(url, data=data)
                elif details["method"] == "get":
                    res = s.get(url, params=data)
                if self.vulnerable(res):
                    result += "SQL injection attack vulnerability detected.\n"
                else:
                    result += "No SQL injection attack vulnerability detected.\n"
                    break

        return result

    def vulnerable(self, response):
        errors = {"quoted string not properly terminated",
                  "unclosed quotation mark after the character string",
                  "you have an error in your SQL syntax"
                  }
        for error in errors:
            if error in response.content.decode().lower():
                return True
        return False

    def get_forms(self, url):
        soup = BeautifulSoup(requests.get(url).content, "html.parser")
        return soup.find_all("form")

    def form_details(self, form):
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

    def check_directory(self, url, directory):
        try:
            response = requests.get(url + directory)
            return response
        except requests.ConnectionError:
            return None

    def get_subdomains(self, domain):
        try:
            answers = dns.resolver.resolve(domain, 'A')
            subdomains = [str(answer) for answer in answers]
            return subdomains
        except dns.resolver.NXDOMAIN:
            return []

    def get_server_headers(self, url):
        try:
            response = requests.head(url)
            return response.headers
        except requests.ConnectionError:
            return None

    def get_technologies(self, url):
        try:
            info = builtwith.builtwith(url)
            return info
        except builtwith.BuiltWithError:
            return None

    def get_ssl_certificate(self, url):
        try:
            hostname = url.split('//')[1].split('/')[0]
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_info = ssock.getpeercert()
                    return cert_info
        except (socket.error, ssl.SSLError):
            return None

    def display_results(self, results):
        self.result_text.config(state="normal")
        self.result_text.delete(1.0, tk.END)

        for category, data in results.items():
            self.result_text.insert(tk.END, f"{category}:\n", "bold")
            if isinstance(data, dict):
                for key, value in data.items():
                    self.result_text.insert(tk.END, f"  - {key}: {value}\n")
            elif isinstance(data, list):
                for item in data:
                    self.result_text.insert(tk.END, f"  - {item}\n")
            else:
                self.result_text.insert(tk.END, f"  - {data}\n")
            self.result_text.insert(tk.END, "\n")

        self.result_text.config(state="disabled")

if __name__ == "__main__":
    root = tk.Tk()
    app = WebsiteScannerApp(root)
    root.mainloop()