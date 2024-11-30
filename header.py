import os
import requests
import subprocess

def fetch_headers(url):
    """
    Fetch HTTP headers from a URL.
    """
    try:
        response = requests.get(url)
        return response.headers
    except requests.RequestException as e:
        print(f"Error fetching headers: {e}")
        return {}

def analyze_headers(headers):
    """
    Analyze HTTP headers for common security policies.
    """
    def check_header(header_name, expected_value=None, present_message="Present", missing_message="Missing"):
        value = headers.get(header_name)
        if expected_value:
            return present_message if value == expected_value else missing_message
        return present_message if value else missing_message

    return {
        "Strict-Transport-Security": check_header("Strict-Transport-Security", expected_value="max-age="),
        "Content-Security-Policy": check_header("Content-Security-Policy"),
        "X-Content-Type-Options": check_header("X-Content-Type-Options", expected_value="nosniff"),
        "X-Frame-Options": check_header("X-Frame-Options", present_message="Valid", missing_message="Missing or misconfigured"),
        "Referrer-Policy": check_header("Referrer-Policy"),
        "Permissions-Policy": check_header("Permissions-Policy"),
    }

def fetch_cookies(url):
    """
    Fetch cookies from a URL.
    """
    try:
        response = requests.get(url)
        return response.cookies
    except requests.RequestException as e:
        print(f"Error fetching cookies: {e}")
        return None

def analyze_cookies(cookies):
    """
    Analyze cookies for security attributes.
    """
    results = []
    for cookie in cookies:
        same_site = cookie._rest.get("samesite", "Missing").lower()
        results.append({
            "name": cookie.name,
            "Secure": "Present" if cookie.secure else "Missing",
            "HttpOnly": "Present" if cookie.has_nonstandard_attr("HttpOnly") else "Missing",
            "SameSite": same_site.capitalize() if same_site in ["strict", "lax"] else "Missing or misconfigured"
        })
    return results

def sql_injection_test_cli(url, params=None, cookies=None, level=3, risk=2, tamper=None):
    """
    Perform an SQL injection test using SQLMap.
    """
    output_dir = "./sqlmap_results"
    os.makedirs(output_dir, exist_ok=True)

    command = [
        "sqlmap",
        "-u", url,
        "--batch",
        "--random-agent",
        f"--level={level}",
        f"--risk={risk}",
        f"--output-dir={output_dir}"
    ]
    if params:
        command.extend(["--data", params])
    if cookies:
        command.extend(["--cookie", cookies])
    if tamper:
        command.extend(["--tamper", tamper])

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"SQLMap error: {e.stderr}")

def check_security_headers(url):
    """
    Check and print the security headers analysis.
    """
    headers = fetch_headers(url)
    if not headers:
        print("Failed to retrieve headers.")
        return

    analysis = analyze_headers(headers)
    print("Security Headers Analysis:")
    for header, status in analysis.items():
        print(f"{header}: {status}")

def check_cookie_security(url):
    """
    Check and print the cookie security analysis.
    """
    cookies = fetch_cookies(url)
    if not cookies:
        print("Failed to retrieve cookies.")
        return

    analysis = analyze_cookies(cookies)
    print("Cookie Security Analysis:")
    for cookie in analysis:
        print(f"Cookie Name: {cookie['name']}")
        print(f"  Secure: {cookie['Secure']}")
        print(f"  HttpOnly: {cookie['HttpOnly']}")
        print(f"  SameSite: {cookie['SameSite']}")
        print("")

def scan_website(url, sql_params=None, sql_cookies=None, sql_level=3, sql_risk=2, sql_tamper=None):
    """
    Perform a full security scan on a website.
    """
    check_security_headers(url)
    check_cookie_security(url)
    sql_injection_test_cli(url, params=sql_params, cookies=sql_cookies, level=sql_level, risk=sql_risk, tamper=sql_tamper)

def headers_analysis_runner(config: dict) -> str:
    """
    Runner for header analysis
    """
    url = config["general"]["target_url"]
    header_conf = config["header_analysis"]
    
    if header_conf["enable"] is False:
        return "No md report"
    else:    
        check_security_headers(url)
        check_cookie_security(url)

        sql_map_conf = header_conf["sql_map"]
        if sql_map_conf["enable"] is False:
            return "No md report"
        else:
            sql_injection_test_cli(url)
    

if __name__ == "__main__":
    target_url = "https://en.wikipedia.org/wiki/HTTP_cookie"
    scan_website(target_url)
