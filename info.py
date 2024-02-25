import tkinter as tk
from tkinter import ttk, messagebox
import requests
from bs4 import BeautifulSoup
import builtwith
import dns.resolver
import socket
import ssl

class WebsiteScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Website Scanner Tool")

        self.create_widgets()

    def create_widgets(self):
        self.url_label = ttk.Label(self.root, text="Enter the target URL:")
        self.url_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")

        self.url_entry = ttk.Entry(self.root, width=40)
        self.url_entry.grid(row=0, column=1, padx=10, pady=5, sticky="w")

        self.scan_button = ttk.Button(self.root, text="Scan Website", command=self.scan_website)
        self.scan_button.grid(row=1, column=0, columnspan=2, pady=10)

        # Result display
        self.result_label = ttk.Label(self.root, text="Scan Results:")
        self.result_label.grid(row=2, column=0, columnspan=2, padx=10, pady=5, sticky="w")

        self.result_text = tk.Text(self.root, height=10, width=60, wrap="word")
        self.result_text.grid(row=3, column=0, columnspan=2, padx=10, pady=5)

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

        # Check directories
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

        # Enumerate subdomains
        subdomains = self.get_subdomains(url)
        results["Subdomains"] = subdomains

        # Extract server headers
        server_headers = self.get_server_headers(url)
        results["Server Headers"] = server_headers

        # Extract web technologies
        tech_info = self.get_technologies(url)
        results["Web Technologies"] = tech_info

        # Extract SSL certificate details
        ssl_info = self.get_ssl_certificate(url)
        results["SSL Certificate Information"] = ssl_info

        return results

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
        self.result_text.config(state="normal")  # Enable text widget for editing

        # Clear previous results
        self.result_text.delete(1.0, tk.END)

        # Display new results
        for category, data in results.items():
            self.result_text.insert(tk.END, f"{category}:\n")
            if isinstance(data, dict):
                for key, value in data.items():
                    self.result_text.insert(tk.END, f"  - {key}: {value}\n")
            elif isinstance(data, list):
                for item in data:
                    self.result_text.insert(tk.END, f"  - {item}\n")
            else:
                self.result_text.insert(tk.END, f"  - {data}\n")
            self.result_text.insert(tk.END, "\n")

        self.result_text.config(state="disabled")  # Disable text widget for editing

if __name__ == "__main__":
    root = tk.Tk()
    app = WebsiteScannerApp(root)
    root.mainloop()