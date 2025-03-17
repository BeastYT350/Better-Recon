import os
import socket
import requests
import subprocess
import json
import re
from datetime import datetime
import shutil
import httpx
import ipaddress
from urllib.parse import urlparse
from httpx import Client
import logging

import whois
import sys


def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_url(url):
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)


def validate_domain(domain):
    pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$"
    return all(re.match(pattern, part) for part in domain.split("."))


def ssl_certificate_check(domain):
    try:
        import ssl

        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return cert
    except Exception as e:
        return str(e)


def advanced_http_checks(url):
    try:
        response = httpx.get(url, follow_redirects=True)
        return {
            "status_code": response.status_code,
            "final_url": str(response.url),
            "headers": dict(response.headers),
            "cookies": response.cookies.jar,
        }
    except Exception as e:
        return str(e)


def osint_domain(domain):
    try:
        whois_data = (
            whois_lookup(domain)
            if "whois_lookup" in globals()
            else "WHOIS lookup function not defined"
        )
        dns_data = (
            dns_lookup(domain)
            if "dns_lookup" in globals()
            else "DNS lookup function not defined"
        )
        reverse_dns = (
            reverse_dns_lookup(dns_data)
            if "reverse_dns_lookup" in globals() and validate_ip(dns_data)
            else "Reverse DNS lookup function not defined or Invalid IP"
        )
        return {
            "WHOIS": whois_data,
            "DNS": dns_data,
            "Reverse DNS": reverse_dns,
        }
    except Exception as e:
        return str(e)


def vulnerability_scan(target):
    try:
        result = subprocess.run(
            ["nmap", "-sV", "--script", "vuln", target],
            capture_output=True,
            text=True,
            shell=True,
        )
        return result.stdout
    except Exception as e:
        return str(e)


def directory_brute_force(url, wordlist):
    found_directories = []
    try:
        with open(wordlist, "r") as file:
            for line in file:
                directory = line.strip()
                full_url = f"{url}/{directory}"
                response = httpx.get(full_url)
                if response.status_code == 200:
                    found_directories.append(full_url)
    except Exception as e:
        return str(e)
    return found_directories


def wordpress_plugin_scan(url):
    try:
        plugins = {}

        # Check the plugin endpoint
        response = requests.get(f"{url}/wp-json/wp/v2/plugins")
        if response.status_code == 200:
            for plugin in response.json():
                plugins[plugin.get("name", "Unknown")] = plugin.get(
                    "version", "Unknown"
                )

        # Examine the main page source code
        main_page_response = requests.get(url)
        if main_page_response.status_code == 200:
            # Look for plugins in the source code or HTTP responses
            matches = re.findall(
                r"/wp-content/plugins/([a-zA-Z0-9_-]+)/.*?ver=([0-9.]+)",
                main_page_response.text,
            )
            for match in matches:
                plugin_name, plugin_version = match
                plugins[plugin_name] = plugin_version

        if plugins:
            return plugins
        else:
            return "No plugins found or endpoint not accessible"
    except Exception as e:
        return str(e)


def get_public_ip():
    try:
        response = requests.get("https://api.ipify.org?format=json")
        return response.json().get("ip")
    except Exception as e:
        return str(e)


def whois_lookup(domain):
    try:
        result = whois.whois(domain)
        return result
    except Exception as e:
        return str(e)


def dns_lookup(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception as e:
        return str(e)


def reverse_dns_lookup(ip):
    try:
        return socket.gethostbyaddr(ip)
    except Exception as e:
        return str(e)


def check_http_headers(url):
    try:
        response = requests.head(url)
        return dict(response.headers)
    except Exception as e:
        return str(e)


def extract_links(url):
    try:
        response = requests.get(url)
        links = re.findall(r'href=["\"](http[s]?://.*?)["\"]', response.text)
        return links
    except Exception as e:
        return str(e)


def traceroute(target):
    try:
        result = subprocess.run(
            ["tracert", target], capture_output=True, text=True, shell=True
        )
        return result.stdout
    except Exception as e:
        return str(e)


def ping(target):
    try:
        result = subprocess.run(
            ["ping", "-n", "4", target], capture_output=True, text=True, shell=True
        )
        return result.stdout
    except Exception as e:
        return str(e)


DEFAULT_ADMIN_WORDLIST = [
    "admin",
    "login",
    "dashboard",
    "controlpanel",
    "administrator",
]


def scan_admin_endpoints(url, wordlist=None):
    admin_endpoints = []
    wordlist = wordlist or DEFAULT_ADMIN_WORDLIST
    try:
        for endpoint in wordlist:
            full_url = f"{url}/{endpoint}"
            response = httpx.get(full_url)
            if response.status_code == 200:
                admin_endpoints.append(full_url)
    except Exception as e:
        return str(e)
    return admin_endpoints


def save_results(filename, data):
    with open(filename, "w") as file:
        file.write(json.dumps(data, indent=4))


def detect_cms(url):
    try:
        response = requests.get(url)
        headers = response.headers
        if "x-powered-by" in headers:
            return headers["x-powered-by"]
        elif "wp-content" in response.text:
            return "WordPress"
        elif "Joomla" in response.text:
            return "Joomla"
        elif "Drupal" in response.text:
            return "Drupal"
        else:
            return "Unknown CMS"
    except Exception as e:
        return f"Error detecting CMS: {e}"


def scrape_webpage(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        content = response.text
        emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", content)
        potential_phone_numbers = re.findall(r"\b\d{10}\b", content)
        api_keys = re.findall(
            r'(?i)(?:api[_-]?key|token)["\']?[:=]["\']?([a-zA-Z0-9]{16,})', content
        )
        sensitive_data = {
            "emails": emails,
            "potential_phone_numbers": potential_phone_numbers,
            "api_keys": api_keys,
        }
        return sensitive_data
    except Exception as e:
        return f"Error scraping webpage: {e}"


def main(input_func=None):
    if "ipykernel" in sys.modules:
        print(
            "Interactive input is not supported in this environment. Using default values for testing."
        )
        input_func = (
            lambda prompt: "test"
        )  # Replace "test" with appropriate default values for testing.
    while True:
        print("\nSelect a task to perform:")
        print("1. Perform WordPress Plugin Scan")
        print("2. Perform WHOIS Lookup")
        print("3. Perform DNS Lookup")
        print("4. Perform Reverse DNS Lookup")
        print("5. Check HTTP Headers")
        print("6. Extract Links from a Webpage")
        print("7. Perform Traceroute")
        print("8. Perform Ping")
        print("9. Check CMS of a Website")
        print("10. Scrape Webpage for Sensitive Data")
        print("11. Scan for Admin Endpoints")
        print("12. About the Developer")
        print("13. Help")
        print("14. Exit")

        choice = (
            input_func("Enter your choice: ")
            if input_func
            else input("Enter your choice: ")
        )

        if choice == "14":
            print("Exiting...")
            break

        try:
            if choice == "1":
                url = (
                    input_func("Enter the URL: ")
                    if input_func
                    else input("Enter the URL: ")
                )
                if detect_cms(url) == "WordPress":
                    print("WordPress Plugins:", wordpress_plugin_scan(url))
                else:
                    print("The site is not running WordPress.")
            elif choice == "2":
                domain = (
                    input_func("Enter the domain: ")
                    if input_func
                    else input("Enter the domain: ")
                )
                print("WHOIS Lookup:", whois_lookup(domain))
            elif choice == "3":
                domain = (
                    input_func("Enter the domain: ")
                    if input_func
                    else input("Enter the domain: ")
                )
                print("DNS Lookup:", dns_lookup(domain))
            elif choice == "4":
                ip = (
                    input_func("Enter the IP address: ")
                    if input_func
                    else input("Enter the IP address: ")
                )
                print("Reverse DNS Lookup:", reverse_dns_lookup(ip))
            elif choice == "5":
                url = (
                    input_func("Enter the URL: ")
                    if input_func
                    else input("Enter the URL: ")
                )
                print("HTTP Headers:", json.dumps(check_http_headers(url), indent=4))
            elif choice == "6":
                url = (
                    input_func("Enter the URL: ")
                    if input_func
                    else input("Enter the URL: ")
                )
                print("Extracted Links:", extract_links(url))
            elif choice == "7":
                target = (
                    input_func("Enter the target: ")
                    if input_func
                    else input("Enter the target: ")
                )
                print("Traceroute:", traceroute(target))
            elif choice == "8":
                target = (
                    input_func("Enter the target: ")
                    if input_func
                    else input("Enter the target: ")
                )
                print("Ping Result:", ping(target))
            elif choice == "9":
                url = (
                    input_func("Enter the URL: ")
                    if input_func
                    else input("Enter the URL: ")
                )
                print("CMS Detected:", detect_cms(url))
            elif choice == "10":
                url = (
                    input_func("Enter the URL: ")
                    if input_func
                    else input("Enter the URL: ")
                )
                sensitive_data = scrape_webpage(url)
                print("Sensitive Data Found:", json.dumps(sensitive_data, indent=4))
            elif choice == "11":
                url = (
                    input_func("Enter the URL: ")
                    if input_func
                    else input("Enter the URL: ")
                )
                wordlist = (
                    input_func(
                        "Enter the path to the wordlist (or press Enter to use the default): "
                    )
                    if input_func
                    else input(
                        "Enter the path to the wordlist (or press Enter to use the default): "
                    )
                )
                wordlist = wordlist if wordlist else None
                print("Admin Endpoints:", scan_admin_endpoints(url, wordlist))
            elif choice == "12":
                print(
                    "Hi Im a 14 year old who in his free time likes to go on hackerone and do bug bountys and honestly i hate the recon part of so thats why i made this tool to help ease that problem obviously it isnt perfect but it mostly works byeeee"
                )
            elif choice == "13":
                print("Help Menu:")
                print(
                    "1: Perform WordPress Plugin Scan - Scans a WordPress site for installed plugins."
                )
                print(
                    "2: Perform WHOIS Lookup - Retrieves WHOIS information for a domain."
                )
                print("3: Perform DNS Lookup - Resolves a domain to its IP address.")
                print(
                    "4: Perform Reverse DNS Lookup - Resolves an IP address to its domain name."
                )
                print("5: Check HTTP Headers - Displays HTTP headers of a URL.")
                print(
                    "6: Extract Links from a Webpage - Extracts all links from a webpage."
                )
                print(
                    "7: Perform Traceroute - Traces the route packets take to a target."
                )
                print(
                    "8: Perform Ping - Sends ICMP packets to a target to check connectivity."
                )
                print(
                    "9: Check CMS of a Website - Identifies the CMS used by a website."
                )
                print(
                    "10: Scrape Webpage for Sensitive Data - Extracts emails, potential phone numbers, and API keys from a webpage."
                )
                print(
                    "11: Scan for Admin Endpoints - Scans a website for potential admin login pages."
                )
                print(
                    "12: About the Developer - Displays information about the developer."
                )
                print("13: Help - Displays this help menu.")
                print("14: Exit - Exits the program.")
            else:
                print("Invalid choice. Please try again.")
        except Exception as e:
            print(f"Error: {e}")


if __name__ == "__main__":
    main()