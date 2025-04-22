import os
import socket
import whois
import requests
import json
import ssl
import OpenSSL
import subprocess
from bs4 import BeautifulSoup
from tqdm import tqdm
from urllib.parse import urlparse


OUTPUT_DIR = "recon_results"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return "IP not found"

def get_whois(domain):
    try:
        return whois.whois(domain)
    except Exception as e:
        return f"No Whois data available ({e})"

def get_ipinfo(ip, token=None):
    try:
        headers = {}
        if token:
            headers['Authorization'] = f"Bearer {token}"
        res = requests.get(f"https://ipinfo.io/{ip}/json", headers=headers)
        return res.json()
    except:
        return {"error": "IP info fetch failed"}

def find_subdomains(domain):
    sub_list = ["www", "mail", "ftp", "admin", "webmail", "test"]
    found = {}
    for sub in sub_list:
        subdomain = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(subdomain)
            found[subdomain] = ip
        except:
            continue
    return found

def get_ssl_info(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5.0)
            s.connect((domain, 443))
            cert = s.getpeercert(binary_form=True)
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
        subject = x509.to_cryptography().subject
        issuer = x509.to_cryptography().issuer
        serial_number = x509.get_serial_number()
        not_before = x509.get_notBefore()
        not_after = x509.get_notAfter()
        

        ssl_protocols = ctx.get_cipher_list()
        return subject, issuer, serial_number, not_before, not_after, ssl_protocols
    except:
        return "SSL info not available"

def get_headers(domain):
    try:
        res = requests.get(f"https://{domain}", timeout=5)
    except:
        try:
            res = requests.get(f"http://{domain}", timeout=5)
        except:
            return {"error": "Failed to get headers"}
    return res.headers

def check_defensive_headers(headers):
    missing = []
    if 'X-Frame-Options' not in headers:
        missing.append("Missing X-Frame-Options")
    if 'Content-Security-Policy' not in headers:
        missing.append("Missing Content-Security-Policy")
    if 'X-XSS-Protection' not in headers:
        missing.append("Missing X-XSS-Protection")
    if 'Strict-Transport-Security' not in headers:
        missing.append("Missing Strict-Transport-Security")
    return missing

def extract_sensitive_keywords(domain):
    try:
        html = requests.get(f"https://{domain}").text
    except:
        try:
            html = requests.get(f"http://{domain}").text
        except:
            return []
    keywords = [
    "admin", "password", "token", "secret", "key", "credentials", "login", "passwd", 
    "username", "api_key", "apikey", "session", "cookie", "auth", "login_page", 
    "auth_token", "access", "private_key", "db_password", "mysql", "mongodb", "sql", 
    "db_user", "config", "backup", "admin_panel", "dashboard", "token", "oauth", 
    "login_credentials", "server", "path", "database", "secure", "ssh_key", "private", 
    "public_key", "login_form", "authentication", "user_password", "change_password", 
    "reset_password", "forgot_password", "user_data"
]
    found = []
    for word in keywords:
        if word in html:
            found.append(word)
    return found

def run_nmap(ip):
    try:
        output = subprocess.check_output(["nmap", "-sV", "-T4", ip, "--open", "--min-rate", "500", "-Pn", "-oX", "-"], text=True)
        grep_output = subprocess.check_output(["nmap", "-sV", ip, "--open", "--min-rate", "500", "-Pn", "--script", "default"], text=True)
        return grep_output
    except Exception as e:
        return str(e)

def calculate_risk(headers, ports, leaks):
    score = 0
    if len(headers) < 3:
        score += 2
    if leaks:
        score += 3
    if "80" in ports or "21" in ports:
        score += 2
    if "443" not in ports:
        score += 1
    return "High" if score >= 5 else "Medium" if score >= 3 else "Low"

def save_report(domain, report):
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
    with open(f"{OUTPUT_DIR}/{domain}.txt", "w") as f:
        f.write(report)

def shodan_lookup(ip, api_key):
    try:
        import shodan
        api = shodan.Shodan(api_key)
        result = api.host(ip)
        return json.dumps(result, indent=2)
    except Exception as e:
        return f"Shodan lookup failed: {e}"


def check_xss_protection(headers):
    if 'X-XSS-Protection' not in headers or headers['X-XSS-Protection'] != '1; mode=block':
        return "-  Missing or improperly configured XSS Protection"
    return "[+]  XSS Protection Enabled"

def check_sqli_protection(headers):
    if 'X-Content-Type-Options' not in headers or headers['X-Content-Type-Options'] != 'nosniff':
        return "-  Missing SQL Injection Protection (X-Content-Type-Options)"
    return "[+]  SQL Injection Protection (X-Content-Type-Options) Enabled"

def check_csrf_protection(headers, html):
    if 'Strict-Transport-Security' not in headers:
        return "-  Missing Strict-Transport-Security Header (May increase CSRF vulnerability)"
    
    csrf_token = None
    if 'csrf' in html or 'token' in html:
        csrf_token = True

    if csrf_token:
        return "[+]  CSRF Protection (Anti-CSRF Token) Found"
    else:
        return "-  Missing CSRF Token (Possible CSRF vulnerability)"

def recon(domain):
    print("\nStart advanced examination for", domain)
    ip = get_ip(domain)
    print(f"[+]  IP address: {ip}")

    whois_data = get_whois(domain)
    print("[+]  WHOIS information obtained.")

    ipinfo = get_ipinfo(ip)
    print("[+]  IP/ASN information obtained.")

    subdomains = find_subdomains(domain)
    print(f"[+]  {len(subdomains)} subdomains found.")

    ssl_info = get_ssl_info(domain)
    print("[+]  SSL information obtained.")

    headers = get_headers(domain)
    print("[+]  HTTP headers obtained.")

    missing_headers = check_defensive_headers(headers if isinstance(headers, dict) else {})
    print(f"[!]  Missing defensive heads: {len(missing_headers)}")

    leaks = extract_sensitive_keywords(domain)
    print(f"[!]  Sensitive words detected: {len(leaks)}")

    html = requests.get(f"http://{domain}").text
    xss_protection = check_xss_protection(headers)
    sqli_protection = check_sqli_protection(headers)
    csrf_protection = check_csrf_protection(headers, html)

    print(f"[!] {xss_protection}")
    print(f"[!] {sqli_protection}")
    print(f"[!] {csrf_protection}")

    ports_raw = run_nmap(ip)
    print("[+]  Ports checked.")

    risk_level = calculate_risk(missing_headers, ports_raw, leaks)
    print(f"[!]  Risk level: {risk_level}")

    shodan_data = ""
    use_shodan = input("Would you like to use Shodan for scanning? (y/n): ").strip().lower()
    if use_shodan == 'y':
        api_key = input("Enter your Shodan API key: ")
        shodan_data = shodan_lookup(ip, api_key)
        print("[+]  Shodan results obtained.")
    

    final_report = f"""
=== Scan report for {domain} ===

🔹 IP: {ip}
🔹 WHOIS: {whois_data}
🔹 IPINFO: {ipinfo}
🔹 Subdomains: {subdomains}
🔹 SSL Info: {ssl_info}
🔹 HTTP Headers: {headers}
🔹 Missing Headers: {missing_headers}
🔹 Sensitive Keywords: {leaks}
🔹 XSS Protection: {xss_protection}
🔹 SQL Injection Protection: {sqli_protection}
🔹 CSRF Protection: {csrf_protection}
🔹 Nmap Scan:\n{ports_raw}
🔹 Shodan Info: {shodan_data}
[*]  Risk Level: {risk_level}
===============================
"""
    save_report(domain, final_report)
    print(f"[+]  The report was saved in: {OUTPUT_DIR}/{domain}.txt")



if __name__ == "__main__":
    os.system("clear")
    print('''
        \033[91m
         █████╗ ███╗   ██╗ █████╗ ███████╗    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
        ██╔══██╗████╗  ██║██╔══██╗██╔════╝    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
        ███████║██╔██╗ ██║███████║███████╗    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
        ██╔══██║██║╚██╗██║██╔══██║╚════██║    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
        ██║  ██║██║ ╚████║██║  ██║███████║    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
        ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
                                                                                 \033[0m
        ''')
    target = input("[*]  Enter the domain name to check: ").strip()
    if target:
        recon(target)
    else:
        print("[-]  No valid domain entered.")
