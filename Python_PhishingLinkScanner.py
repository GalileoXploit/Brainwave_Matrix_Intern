import re
from urllib.parse import urlparse
import requests

# List of known suspicious keywords often found in phishing URLs
suspicious_keywords = ["signin", "update", "confirm", "verification", "payment","free","win","lottery"]

# List of common phishing-related Top Level Domains i.e. urls ending with the below mentioned Strings.
suspicious_tlds = [".xyz", ".top", ".club", ".win", ".loan", ".click", ".online", ".bid", ".link"]

# Function to check if a URL contains suspicious keywords
def has_suspicious_keywords(url):
    url = url.lower()
    for keyword in suspicious_keywords:
        if keyword in url:
            print(f"Suspicious keyword found in URL: {keyword}")
            return True
    return False    

# Function to check the domain for numbers or unusual patterns
def is_suspicious_domain(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()

# Check for excessive subdomain (More than 3 subdomain is considered Suspicious)
    subdomain_count = domain.count('.')
    if subdomain_count > 3:
        print(f"Suspicious: Excessive subdomains in {url}")
        return True

    # Check for IP address domains
    if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
        print(f"Suspicious: IP address domain in {url}")
        return True
    
    # Check if the domain contains numbers (commonly seen in phishing sites)
    if re.search(r"\d", domain):
        print(f"Suspicious domain: contains numbers - {domain}")
        return True
    
    # Check if the domain is too long or contains unusual characters
    if len(domain) > 30:
        print(f"Suspicious domain: too long - {domain}")
        return True

    return False

# Function to check for suspicious Top-Level Domain (TLD)
def has_suspicious_tld(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()
    
    # Check if the TLD is in the suspicious list
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            print(f"Suspicious TLD found: {tld}")
            return True
    return False

# Function to check if the URL is too long
def is_url_too_long(url):
    if len(url) > 80:
        print(f"Suspicious URL: too long ({len(url)} characters)")
        return True
    return False

def is_url_reachable(url):
    try:
        # Adding a common browser user-agent to the headers to mimic a real user request
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        response = requests.get(url, headers=headers, timeout=10)
        
        # Check if the status code is 200 (OK)
        if response.status_code == 200:
            print(f"URL is reachable. Status code: {response.status_code}")
            print("Response Headers:", response.headers)
            return True
        elif response.status_code == 403:
            print(f"Error: 403 Forbidden - Access to the URL is blocked.")
            return False
        else:
            print(f"URL returned status code: {response.status_code}")
            return False
    except requests.RequestException as e:
        print(f"Error reaching the URL: {e}")
        return False


# Function to analyze a URL and check for phishing indicators
def check_phishing(url):
    print(f"Checking URL: {url}")
    
    # Check if the URL contains suspicious keywords
    if has_suspicious_keywords(url):
        return True
    
    # Check if the domain contains numbers or unusual patterns
    if is_suspicious_domain(url):
        return True
    
    # Check if the URL is too long
    if is_url_too_long(url):
        return True
    
    # Check if the TLD is suspicious
    if has_suspicious_tld(url):
        return True

    # Check if the URL is reachable and fetch headers
    if not is_url_reachable(url):
        return True
    
    print(f"URL {url} appears to be safe.")
    return False

# Main program loop
if __name__ == "__main__":
    while True:
        url = input("Enter a URL to check (or 'exit/Exit/EXIT' to quit): ")
        if url.lower() == 'exit':
            break
        if check_phishing(url):
            print("Scan Result :-  Phishing detected!\n")
        else:
            print("Scan Result :- URL is safe.\n")
