import requests

def fetch_headers(url):
    try:
        response = requests.get(url)
        headers = response.headers
        return headers
    except requests.RequestException as e:
        print(f"Error fetching headers: {e}")
        return {}

def analyze_headers(headers):
    results = {}

    # Check Strict-Transport-Security (HSTS)
    hsts = headers.get("Strict-Transport-Security")
    if hsts:
        results["Strict-Transport-Security"] = "Present" if "max-age=" in hsts else "Improperly configured"
    else:
        results["Strict-Transport-Security"] = "Missing"

    # Check Content-Security-Policy (CSP)
    csp = headers.get("Content-Security-Policy")
    if csp:
        results["Content-Security-Policy"] = "Present"
    else:
        results["Content-Security-Policy"] = "Missing"

    # Check X-Content-Type-Options
    x_content_type = headers.get("X-Content-Type-Options")
    results["X-Content-Type-Options"] = "Present" if x_content_type == "nosniff" else "Missing or misconfigured"

    # Check X-Frame-Options
    x_frame_options = headers.get("X-Frame-Options")
    if x_frame_options in ["SAMEORIGIN", "DENY"]:
        results["X-Frame-Options"] = "Present"
    else:
        results["X-Frame-Options"] = "Missing or misconfigured"

    # Check Referrer-Policy
    referrer_policy = headers.get("Referrer-Policy")
    if referrer_policy:
        results["Referrer-Policy"] = "Present"
    else:
        results["Referrer-Policy"] = "Missing"

    # Check Permissions-Policy
    permissions_policy = headers.get("Permissions-Policy")
    results["Permissions-Policy"] = "Present" if permissions_policy else "Missing"

    return results

def check_security_headers(url):
    headers = fetch_headers(url)
    if not headers:
        print("Failed to retrieve headers.")
        return
    
    analysis = analyze_headers(headers)
    print("Security Headers Analysis:")
    for header, status in analysis.items():
        print(f"{header}: {status}")

def analyze_cookie_security(cookies):
    results = []

    for cookie in cookies:
        same_site = cookie._rest.get("samesite", "Missing")

        cookie_analysis = {
            "name": cookie.name,
            "Secure": "Present" if cookie.secure else "Missing",
            "HttpOnly": "Present" if cookie.has_nonstandard_attr("HttpOnly") else "Missing",
            "SameSite": same_site.capitalize() if same_site.lower() in ["strict", "lax"] else "Missing or misconfigured"
        }

        results.append(cookie_analysis)

    return results

def fetch_cookies(url):
    try:
        response = requests.get(url)
        cookies = response.cookies
        return cookies
    except requests.RequestException as e:
        print(f"Error fetching cookies: {e}")
        return None
    
def check_cookie_security(url):
    cookies = fetch_cookies(url)
    if not cookies:
        print("Failed to retrieve cookies.")
        return
    
    analysis = analyze_cookie_security(cookies)
    print("Cookie Security Analysis:")
    for cookie in analysis:
        print(f"Cookie Name: {cookie['name']}")
        print(f"  Secure: {cookie['Secure']}")
        print(f"  HttpOnly: {cookie['HttpOnly']}")
        print(f"  SameSite: {cookie['SameSite']}")
        print("")

def sql_injection_test(url):
    # Integration with SQLMap
    pass

def scan_website(url):
    check_security_headers(url)
    check_cookie_security(url)
    sql_injection_test(url)

target_url = "https://en.wikipedia.org/wiki/HTTP_cookie"
scan_website(target_url)
