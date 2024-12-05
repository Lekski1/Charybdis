import socket
import logging
import telnetlib
from typing import List, Dict, Optional, Union

from markdownmaker.markdownmaker import Document, Paragraph, Bold, OrderedList

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def parse_ports(ports: str) -> List[int]:
    """
    Parses a port range string into a list of integers.

    Args:
        ports (str): A comma-separated string of ports and port ranges (e.g., "22,80,1000-2000").

    Returns:
        List[int]: A list of all individual ports in the specified ranges.
    """
    port_list = []
    for part in ports.split(','):
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                port_list.extend(range(start, end + 1))
            except ValueError:
                logging.error(f"Invalid port range: {part}")
        else:
            try:
                port_list.append(int(part))
            except ValueError:
                logging.error(f"Invalid port value: {part}")
    return port_list

def telnet_scan(ip: str, ports: str) -> List[str]:
    """
    Scans a range of ports on a specified IP address using Telnet.

    Args:
        ip (str): The IP address to scan.
        ports (str): A comma-separated string of ports and port ranges.

    Returns:
        List[str]: A list of results for each scanned port.
    """
    results = []
    port_list = parse_ports(ports)
    logging.info(f"Starting Telnet scan on {ip} for ports: {port_list}")

    for idx, port in enumerate(port_list):
        try:
            with telnetlib.Telnet(ip, port, timeout=5) as tn:
                try:
                    banner = tn.read_eager().decode("utf-8", "ignore")
                    threat = get_port_threats(port)
                    results.append(
                        f"{idx + 1}. Port {port}\n- Status: Open\n- Banner: {banner or 'No banner received'}\n- Threat: {threat}\n"
                    )
                except EOFError:
                    results.append(f"{idx + 1}. Port {port}\n- Status: Open\n- Banner: No banner (EOF)\n")
        except (socket.timeout, ConnectionRefusedError, OSError, socket.gaierror) as e:
            results.append(f"{idx + 1}. Port {port}\n- Status: Closed\n- Error: {e}\n")

    return results

def get_port_threats(port: int) -> str:
    """
    Provides a description of known threats for a specific port.

    Args:
        port (int): The port number.

    Returns:
        str: Description of threats for the port.
    """
    threats = {
        21: "FTP - possible brute-force attacks or data theft.",
        22: "SSH - risk of brute-force attacks or vulnerabilities.",
        23: "Telnet - unencrypted access, risk of data interception.",
        80: "HTTP - potential web application attacks.",
        443: "HTTPS - MITM attacks if SSL is misconfigured.",
        3306: "MySQL - risk of unauthorized database access.",
        3389: "RDP - possibility of brute-force attacks or exploitation.",
    }
    return threats.get(port, "No known threats for this port in our database.")

def resolve_domain(domain: str) -> List[str]:
    """
    Resolves a domain name to its IP addresses.

    Args:
        domain (str): The domain name to resolve.

    Returns:
        List[str]: A list of IP addresses for the domain.
    """
    try:
        ips = [addr[4][0] for addr in socket.getaddrinfo(domain, None)]
        logging.info(f"Resolved domain {domain} to IPs: {ips}")
        return ips
    except socket.gaierror as e:
        logging.error(f"Error resolving domain {domain}: {e}")
        return []

def telnet_scan_configure(domain: str, ports: str) -> Union[Paragraph, Dict[str, str]]:
    """
    Configures and runs a Telnet scan for a given domain.

    Args:
        domain (str): The domain to scan.
        ports (str): A comma-separated string of ports and port ranges.

    Returns:
        Union[Paragraph, Dict[str, str]]: A Paragraph with the scan results or an error message.
    """
    ips = resolve_domain(domain)
    if not ips:
        return {"error": f"Could not resolve domain {domain}"}

    results = telnet_scan(ips[0], ports)
    return Paragraph(f"Domain: {Bold(domain)}\n\n" + "".join(results))

def generate_markdown_report(scan_results: Dict[str, Union[str, Paragraph]]) -> List[Paragraph]:
    """
    Generates a Markdown report from scan results.

    Args:
        scan_results (Dict): Telnet scan results.

    Returns:
        str: A Markdown-formatted string containing the scan report.
    """
    if not scan_results:
        return [Paragraph("No scan results available.")]

    doc = []
    for domain, result in scan_results.items():
        if isinstance(result, Paragraph):
            doc.append(result)
        else:
            doc.append(Paragraph(f"Error: {result.get('error')}"))

    return doc

def telnet_runner(config: Dict) -> Dict[str, Optional[Union[Paragraph, Dict[str, str]]]]:
    """
    Runner function for Telnet scan.

    Args:
        config (Dict): Configuration dictionary.

    Returns:
        Dict[str, Optional[Union[Paragraph, Dict[str, str]]]]: Scan results.
    """
    domain = config.get("general", {}).get("target_url", "")
    telnet_conf = config.get("telnet", {})

    results = {"telnet": None}

    if not domain or not telnet_conf.get("enable", False):
        logging.info("Telnet scan is disabled or the target domain is not specified.")
        return results

    results["telnet"] = telnet_scan_configure(domain, telnet_conf["ports"])
    return results

def main() -> None:
    """
    Main function to execute Telnet scans and generate Markdown reports.
    """
    domain = "lezgivi.com"
    ports = "78-80,99"

    try:
        scan_results = {domain: telnet_scan_configure(domain, ports)}
        markdown_report = generate_markdown_report(scan_results)

        output_file = "telnet_report.md"
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(markdown_report)

        logging.info(f"Markdown report saved to {output_file}")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()
