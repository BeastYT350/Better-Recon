#Better-Recon

Better Recon is an advanced Python-based reconnaissance script designed to perform various security checks and information gathering tasks. It integrates multiple tools and techniques, such as WHOIS lookups, DNS lookups, HTTP header checks, link extraction, CMS detection, and much more. This script is designed for ethical hacking, vulnerability assessment, and penetration testing.

Features
Better Recon offers the following tasks:

WordPress Plugin Scan: Scan a website for WordPress plugins and their versions.
WHOIS Lookup: Retrieve WHOIS information of a domain.
DNS Lookup: Perform a DNS lookup to gather domain-related information.
Reverse DNS Lookup: Find the reverse DNS associated with an IP.
HTTP Header Check: Extract and analyze HTTP headers.
Link Extraction: Scrape links from a webpage.
Traceroute: Perform a traceroute to determine the route packets take to a network host.
Ping: Perform a ping test to check the availability of a server.
CMS Detection: Identify the content management system (CMS) used by a website.
Sensitive Data Scraping: Look for emails, API keys, tokens, or other sensitive data on a webpage.
Admin Endpoint Scan: Identify potential admin login endpoints.
Developer Information: Information about the developer of the tool.
Help: A detailed help section explaining the features and usage of the script.
Installation
To get started with Better Recon, you need to install the dependencies from requirements.txt. Follow the instructions below to install the necessary packages:

Clone or download the repository.

Install the required dependencies by running the following command in your terminal:

bash
Copy
Edit
pip install -r requirements.txt
Usage
Run the script and choose an option from the menu to perform a reconnaissance task. Here's an example of how to use the script:

bash
Copy
Edit
python better_recon.py
You will be presented with the following menu:

markdown
Copy
Edit
Select a task to perform:
1. Perform WordPress Plugin Scan
2. Perform WHOIS Lookup
3. Perform DNS Lookup
4. Perform Reverse DNS Lookup
5. Check HTTP Headers
6. Extract Links from a Webpage
7. Perform Traceroute
8. Perform Ping
9. Check CMS of a Website
10. Scrape Webpage for Sensitive Data
11. Scan for Admin Endpoints
12. About the Developer
13. Help
14. Exit
Enter your choice:

Enter the corresponding number to perform a task. For details on what each oen does just choose number 13 :) happy hacking!
