import os
import logging
import subprocess
from typing import Optional, Union, Any

import requests
from requests.cookies import RequestsCookieJar
from requests.structures import CaseInsensitiveDict
from markdownmaker.markdownmaker import Paragraph, Bold

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def fetch_headers(url: str) -> Union[CaseInsensitiveDict[str], dict[str, Any]]:
    """
    Fetch HTTP headers from a given URL.
    Args:
        url (str): The target URL.
    Returns:
        Union[CaseInsensitiveDict[str], dict[str, Any]]: The headers dictionary or an empty dict if an error occurs.
    """
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.headers
    except requests.RequestException as e:
        logging.error(f"Error fetching headers from {url}: {e}")
        return {}

def analyze_headers(headers: Union[CaseInsensitiveDict[str], dict[str, Any]]) -> list[Paragraph]:
    """
    Analyze HTTP headers for security policies.
    Args:
        headers (dict[str, str]): The headers dictionary.
    Returns:
        list[Paragraph]: A list of analyzed header results in markdown format.
    """
    def check_header(header_name: str, expected_value: Optional[str] = None, 
                     present_message: str = "Present", missing_message: str = "Missing") -> str:
        value = headers.get(header_name)
        if expected_value:
            return present_message if value == expected_value else missing_message
        return present_message if value else missing_message

    return [
        Paragraph(f"{Bold('Strict-Transport-Security')}: {check_header('Strict-Transport-Security', 'max-age=')}"),
        Paragraph(f"{Bold('Content-Security-Policy')}: {check_header('Content-Security-Policy')}"),
        Paragraph(f"{Bold('X-Content-Type-Options')}: {check_header('X-Content-Type-Options', 'nosniff')}"),
        Paragraph(f"{Bold('X-Frame-Options')}: {check_header('X-Frame-Options', present_message='Valid', missing_message='Missing or misconfigured')}"),
        Paragraph(f"{Bold('Referrer-Policy')}: {check_header('Referrer-Policy')}"),
        Paragraph(f"{Bold('Permissions-Policy')}: {check_header('Permissions-Policy')}")
    ]

def fetch_cookies(url: str) -> Optional[RequestsCookieJar]:
    """
    Fetch cookies from a given URL.
    Args:
        url (str): The target URL.
    Returns:
        Optional[RequestsCookieJar]: A jar containing cookies or None if an error occurs.
    """
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.cookies
    except requests.RequestException as e:
        logging.error(f"Error fetching cookies from {url}: {e}")
        return None

def analyze_cookies(cookies: RequestsCookieJar) -> list[Paragraph]:
    """
    Analyze cookies for security attributes.
    Args:
        cookies (RequestsCookieJar): A jar of cookies.
    Returns:
        list[Paragraph]: A list of cookie analysis results in markdown format.
    """
    results = []
    for cookie in cookies:
        same_site = cookie._rest.get("samesite", "Missing").lower() # type: ignore
        results.append(Paragraph(
            f"Name: {Bold(cookie.name)}\n"
            f"- Secure: {'Present' if cookie.secure else 'Missing'}\n"
            f"- HttpOnly: {'Present' if cookie.has_nonstandard_attr('HttpOnly') else 'Missing'}\n"
            f"- SameSite: {same_site.capitalize() if same_site in ['strict', 'lax'] else 'Missing or misconfigured'}\n"
        ))
    return results

def sql_injection_test_cli(url: str, params: Optional[str] = None, cookies: Optional[str] = None,
                           level: int = 3, risk: int = 2, tamper: Optional[str] = None) -> None:
    """
    Perform an SQL injection test using SQLMap.
    Args:
        url (str): The target URL.
        params (Optional[str]): POST data parameters for testing.
        cookies (Optional[str]): Cookies for the request.
        level (int): SQLMap testing level.
        risk (int): SQLMap risk level.
        tamper (Optional[str]): SQLMap tamper script.
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
        logging.info(f"SQLMap Results:\n{result.stdout}")
    except subprocess.CalledProcessError as e:
        logging.error(f"SQLMap error: {e.stderr}")

def detect_scheme(domain: str) -> Union[str, None]:
    """
    Detect whether the domain supports HTTP or HTTPS.
    Attempts HTTPS first, then falls back to HTTP if HTTPS fails.
    """
    if not domain:
        raise ValueError("Domain is not specified.")
    
    for scheme in ["https", "http"]:
        url = f"{scheme}://{domain}"
        try:
            response = requests.head(url, timeout=1)
            if response.status_code < 400:
                return scheme
        except requests.RequestException:
            continue
    else:
        logging.error(f"Unable to connect to the domain {domain} using HTTP or HTTPS.")

def headers_analysis_runner(config: dict) -> dict:
    """
    Runner for header analysis.
    Args:
        config (dict): Configuration dictionary.
    Returns:
        dict: Analysis results for headers, cookies, and SQLMap.
    """
    domain = config.get("general", {}).get("target_url")
    scheme = detect_scheme(domain) 
    header_conf = config.get("header_analysis", {})

    if not scheme or not domain or not header_conf.get("enable", False):
        logging.info("Header analysis disabled in configuration.")
        return {"headers": [], "cookies": [], "sqlmap": []}

    url = scheme + "://" + domain
    headers = fetch_headers(url)
    if not headers:
        logging.warning(f"No headers retrieved from {url}.")
        return {"headers": [], "cookies": [], "sqlmap": []}

    cookies = fetch_cookies(url) or RequestsCookieJar()
    sqlmap_results = sql_injection_test_cli(url) if header_conf.get("sql_map", {}).get("enable") else []

    return {
        "headers": analyze_headers(headers),
        "cookies": analyze_cookies(cookies),
        "sqlmap": sqlmap_results
    }
