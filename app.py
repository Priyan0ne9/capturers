import streamlit as st
import requests
from bs4 import BeautifulSoup
import builtwith
import dns.resolver
import socket
import ssl
import re
from fpdf import FPDF
import time
from social_media_footprint import check_social_media_footprint
import json
import tempfile
import shutil

def main():
    st.sidebar.image("./logo.jpg", width=200)
    st.sidebar.header("Options")
    page = st.sidebar.selectbox("Select a page", ["Home", "Scan Website"])

    scan_button = None  # Declare scan_button outside the block
    url = ""  # Initialize url variable

    if page == "Home":
        st.markdown(
            """
            # Welcome to Capturers Web Scanning Tool!

            ## Overview

            The Web Scanning Tool is a powerful utility designed to help you analyze and assess various aspects of a website. Whether you're a developer, security professional, or just curious about a website's details, this tool provides valuable insights at your fingertips.

            ## Features

            - **Website Scanning:** Scan a target URL to gather information about common directories, subdomains, server headers, technologies used, SSL certificate details, and potential vulnerabilities.
            - **Security Checks:** Detect potential security vulnerabilities, including XSS (Cross-Site Scripting) and CSRF (Cross-Site Request Forgery), as well as perform SQL injection vulnerability scans.
            - **Performance Metrics:** Assess the performance of the target website, including response time, number of requests, and server status code.
            - **Downloadable Reports:** Generate detailed PDF reports summarizing the scan results for further analysis or documentation.

            ## How to Use

            1. Navigate to the "Scan Website" page from the sidebar.
            2. Enter the target URL in the provided input field.
            3. Click the "Scan Website" button to initiate the scan.
            4. Review the scan results and explore potential vulnerabilities and performance metrics.
            5. Download a PDF report for comprehensive documentation.

            Explore the various features and enhance your web analysis capabilities with the Web Scanning Tool!
            """
        )

    elif page == "Scan Website":
        url = st.text_input("Enter the target URL:")
        scan_button = st.button("Scan Website")

        if scan_button:  # This ensures the button is clicked
            if not is_valid_url(url):  # Validate URL here
                st.error("Invalid URL! Please enter a valid URL.")
            else:
                results, performance_metrics = perform_scan(url)  # Perform the scan and get performance metrics
                display_results(results, performance_metrics)  # Display the results
                generate_pdf_report(results, performance_metrics)  # Generate PDF report


def is_valid_url(url):
    try:
        response = requests.head(url)
        return response.status_code == 200
    except requests.RequestException:
        return False


def perform_scan(url):
    results = {}
    performance_metrics = {}

    # Performance metrics: response time, number of requests, server status code
    start_time = time.time()
    
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
        response = check_directory(url, directory)
        directory_results[directory] = response.status_code if response else "Failed"

    results["Directories"] = directory_results
    subdomains = get_subdomains(url)
    results["Subdomains"] = subdomains
    server_headers = get_server_headers(url)
    results["Server Headers"] = server_headers
    tech_info = get_technologies(url)
    results["Web Technologies"] = tech_info
    ssl_info = get_ssl_certificate(url)
    results["SSL Certificate Information"] = ssl_info

    # Adding XSS and CSRF checks
    xss_result = check_xss_vulnerability(url)
    results["XSS Vulnerability"] = xss_result

    csrf_result = check_csrf_vulnerability(url)
    results["CSRF Vulnerability"] = csrf_result

    # Adding SQL injection check
    sql_result = sql_injection_scan(url)
    results["SQL Injection Vulnerability"] = sql_result

    # Adding Social Media Footprint check
    social_media_result = check_social_media_footprint(url)
    results["Social Media Footprint"] = social_media_result

    # Performance Metrics
    end_time = time.time()
    response_time = end_time - start_time
    performance_metrics["Response Time"] = f"{response_time:.2f} seconds"
    performance_metrics["Total Requests"] = len(common_directories)
    performance_metrics["Status Code"] = get_server_status_code(url)

    return results, performance_metrics


def get_server_status_code(url):
    try:
        response = requests.head(url)
        return response.status_code
    except requests.RequestException:
        return "Error"


def check_xss_vulnerability(url):
    try:
        response = requests.get(url)
        if '<script>' in response.text:
            return "Potential XSS Vulnerability"
        else:
            return "No XSS Vulnerability"
    except requests.RequestException:
        return "Error checking XSS vulnerability"


def check_csrf_vulnerability(url):
    try:
        response = requests.get(url)
        csrf_patterns = ["<input type=\"hidden\" name=\"csrf_token\" value=", "csrf_token="]
        if any(pattern in response.text for pattern in csrf_patterns):
            return "Potential CSRF Vulnerability"
        else:
            return "No CSRF Vulnerability"
    except requests.RequestException:
        return "Error checking CSRF vulnerability"


def sql_injection_scan(url):
    s = requests.Session()
    s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"

    forms = get_forms(url)
    result = f"[+] Detected {len(forms)} forms on {url}.\n"

    for form in forms:
        details = form_details(form)

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
            if vulnerable(res):
                result += "SQL injection attack vulnerability detected.\n"
            else:
                result += "No SQL injection attack vulnerability detected.\n"
                break

    return result


def vulnerable(response):
    errors = {"quoted string not properly terminated",
              "unclosed quotation mark after the character string",
              "you have an error in your SQL syntax"
              }
    for error in errors:
        if error in response.content.decode().lower():
            return True
    return False


def get_forms(url):
    soup = BeautifulSoup(requests.get(url).content, "html.parser")
    return soup.find_all("form")


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


def check_directory(url, directory):
    try:
        response = requests.get(url + directory)
        return response
    except requests.ConnectionError:
        return None


def get_subdomains(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        subdomains = [str(answer) for answer in answers]
        return subdomains
    except dns.resolver.NXDOMAIN:
        return []


def get_server_headers(url):
    try:
        response = requests.head(url)
        return response.headers
    except requests.ConnectionError:
        return None


def get_technologies(url):
    try:
        info = builtwith.builtwith(url)
        return info
    except builtwith.BuiltWithError:
        return None


def get_ssl_certificate(url):
    try:
        hostname = url.split('//')[1].split('/')[0]
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_info = ssock.getpeercert()
                return cert_info
    except (socket.error, ssl.SSLError):
        return None


def display_results(results, performance_metrics):
    for category, data in results.items():
        st.subheader(category)
        if isinstance(data, dict):
            for key, value in data.items():
                st.write(f"**{key}:** {value}")
        else:
            st.write(data)

    st.subheader("Performance Metrics")
    for metric, value in performance_metrics.items():
        st.write(f"**{metric}:** {value}")


import os

def generate_pdf_report(results, performance_metrics):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    
    # Title
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt="Website Scan Report", ln=True, align="C")
    pdf.ln(10)

    # Directories
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, txt="Directories:", ln=True)
    pdf.set_font("Arial", '', 12)
    for directory, status in results["Directories"].items():
        pdf.cell(200, 10, txt=f"{directory}: {status}", ln=True)

    # Subdomains
    pdf.ln(5)
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, txt="Subdomains:", ln=True)
    pdf.set_font("Arial", '', 12)
    for subdomain in results["Subdomains"]:
        pdf.cell(200, 10, txt=f"{subdomain}", ln=True)

    # Server Headers
    pdf.ln(5)
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, txt="Server Headers:", ln=True)
    pdf.set_font("Arial", '', 12)
    for key, value in results["Server Headers"].items():
        pdf.cell(200, 10, txt=f"{key}: {value}", ln=True)

    # Web Technologies
    pdf.ln(5)
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, txt="Web Technologies:", ln=True)
    pdf.set_font("Arial", '', 12)
    for tech, tech_list in results["Web Technologies"].items():
        pdf.cell(200, 10, txt=f"{tech}: {', '.join(tech_list)}", ln=True)

    # SSL Certificate Information
    pdf.ln(5)
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, txt="SSL Certificate Information:", ln=True)
    pdf.set_font("Arial", '', 12)
    for cert_key, cert_value in results["SSL Certificate Information"].items():
        pdf.cell(200, 10, txt=f"{cert_key}: {cert_value}", ln=True)

    # Performance Metrics
    pdf.ln(5)
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, txt="Performance Metrics:", ln=True)
    pdf.set_font("Arial", '', 12)
    for metric, value in performance_metrics.items():
        pdf.cell(200, 10, txt=f"{metric}: {value}", ln=True)

    # Save PDF to temporary file
    tmp_pdf = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
    tmp_pdf_path = tmp_pdf.name
    pdf.output(tmp_pdf_path)

    # Close the file
    tmp_pdf.close()

    # Streamlit download button
    st.download_button(
        label="Download PDF Report",
        data=open(tmp_pdf_path, "rb").read(),
        file_name="website_scan_report.pdf",
        mime="application/pdf"
    )

    # Clean up the temporary file after download
    try:
        os.remove(tmp_pdf_path)
    except PermissionError:
        st.write("Error: Could not delete temporary file. Please try again later.")


if __name__ == "__main__":
    main()
