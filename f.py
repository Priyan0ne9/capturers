import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import requests
from bs4 import BeautifulSoup
import builtwith
import dns.resolver
import socket
import ssl
import webbrowser

class WebsiteScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Website Scanner Tool")

        # Set a custom theme for a more modern look
        self.style = ttk.Style()
        self.style.theme_use("clam")

        self.create_widgets()

    def create_widgets(self):
        # Set background color for the entire window
        self.root.configure(bg="#f0f0f0")

        self.url_label = ttk.Label(self.root, text="Enter the target URL:", background="#f0f0f0")
        self.url_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")

        self.url_entry = ttk.Entry(self.root, width=40)
        self.url_entry.grid(row=0, column=1, padx=10, pady=5, sticky="w")

        self.scan_button = ttk.Button(self.root, text="Scan Website", command=self.scan_website, style="TButton")
        self.scan_button.grid(row=1, column=0, columnspan=2, pady=10)

        self.result_label = ttk.Label(self.root, text="Scan Results:", background="#f0f0f0", font=("Helvetica", 12, "bold"))
        self.result_label.grid(row=2, column=0, padx=10, pady=5, sticky="w")

        # ScrolledText for a scrollable and styled output
        self.result_text = scrolledtext.ScrolledText(self.root, height=10, width=60, wrap=tk.WORD, background="#ffffff", font=("Helvetica", 10))
        self.result_text.grid(row=3, column=0, padx=10, pady=5, sticky="w")

        # Apply a custom style for the scan button
        self.style.configure("TButton", foreground="#ffffff", background="#007acc", padding=(5, 5))

    def scan_website(self):
        target_url = self.url_entry.get()

        if not self.is_valid_url(target_url):
            messagebox.showerror("Error", "Invalid URL. Please enter a valid URL.")
            return

        results_info = self.perform_scan(target_url)
        results_vulnerabilities = self.perform_vulnerability_scan(target_url)

        # Display results in separate tables
        self.display_table("Information Gathering Results", results_info)
        self.display_table("Vulnerability Scanning Results", results_vulnerabilities)

    # ... (existing methods remain unchanged)

    def display_table(self, table_title, results):
        self.result_text.config(state="normal")
        self.result_text.insert(tk.END, f"\n{table_title}:\n", "bold")

        for category, data in results.items():
            self.result_text.insert(tk.END, f"\n{category}:\n", "bold")
            if isinstance(data, dict):
                for key, value in data.items():
                    self.result_text.insert(tk.END, f"  - {key}: {value}\n")
            elif isinstance(data, list):
                for item in data:
                    self.result_text.insert(tk.END, f"  - {item}\n")
            else:
                self.result_text.insert(tk.END, f"  - {data}\n")

        self.result_text.tag_configure("bold", font=("Helvetica", 12, "bold"))
        self.result_text.config(state="disabled")

if __name__ == "__main__":
    root = tk.Tk()
    app = WebsiteScannerApp(root)
    root.mainloop()
