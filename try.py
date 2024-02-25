import tkinter as tk
from tkinter import ttk, messagebox
import requests
from bs4 import BeautifulSoup
import builtwith
import dns.resolver
import socket
import ssl

# Import the vulnerability scanning functions
from urllib.parse import urljoin

class WebsiteScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Website Scanner Tool")

        self.create_widgets()

    def create_widgets(self):
        # ... (existing code remains unchanged)

        # New button to initiate vulnerability scanning
        self.scan_vulnerabilities_button = ttk.Button(self.root, text="Scan Vulnerabilities", command=self.scan_vulnerabilities)
        self.scan_vulnerabilities_button.grid(row=1, column=1, pady=10)

    def scan_vulnerabilities(self):
        target_url = self.url_entry.get()

        if not self.is_valid_url(target_url):
            messagebox.showerror("Error", "Invalid URL. Please enter a valid URL.")
            return

        # Perform information gathering scan
        results_info = self.perform_scan(target_url)

        # Perform vulnerability scanning
        results_vulnerabilities = self.perform_vulnerability_scan(target_url)

        # Display both information gathering and vulnerability scanning results
        self.display_results(results_info)
        self.display_results(results_vulnerabilities)

    # ... (existing methods remain unchanged)

    def perform_vulnerability_scan(self, url):
        results = {}

        # XSS vulnerability scan
        results["XSS Vulnerability"] = self.check_xss_vulnerability(url)

        # CSRF vulnerability scan
        results["CSRF Vulnerability"] = self.check_csrf_vulnerability(url)

        # SQL injection vulnerability scan
        results["SQL Injection Vulnerability"] = self.check_sql_injection_vulnerability(url)

        return results

    def check_xss_vulnerability(self, url):
        try:
            # Send a GET request to the URL
            response = requests.get(url)

            # Check if the response contains potential XSS indicators
            xss_patterns = ["<script>", "onerror", "javascript:"]

            return any(pattern in response.text.lower() for pattern in xss_patterns)

        except requests.RequestException:
            return False

    def check_csrf_vulnerability(self, url):
        try:
            # Send a GET request to the URL
            response = requests.get(url)

            # Check if the response contains potential CSRF indicators
            csrf_patterns = ["<input type=\"hidden\" name=\"csrf_token\" value=", "csrf_token="]

            return any(pattern in response.text for pattern in csrf_patterns)

        except requests.RequestException:
            return False

    def check_sql_injection_vulnerability(self, url):
        # ... (use the existing SQL injection vulnerability check code)

 if __name__ == "__main__":
    root = tk.Tk()
    app = WebsiteScannerApp(root)
    root.mainloop()
