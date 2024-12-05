import logging
from typing import List, Dict, Optional, Union

import nmap3
from markdownmaker.markdownmaker import Document, Paragraph, OrderedList, Bold

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

def configure_nmap_scan(domain: str, ports: List[int], scan_type: str) -> Optional[Dict[str, Union[str, Dict]]]:
    """
    Configures and runs an Nmap scan on the specified domain and ports.

    Args:
        domain (str): Target domain or IP address.
        ports (List[int]): List of ports to scan.
        scan_type (str): Type of scan to perform ("syn", "fin", "tcp", or "udp").

    Returns:
        Optional[Dict]: Nmap scan results if successful, or None otherwise.
    """
    nmap = nmap3.NmapScanTechniques()
    stealth_scans = {
        "syn": nmap.scan_top_ports,
        "fin": nmap.nmap_fin_scan,
        "tcp": nmap.nmap_tcp_scan,
        "udp": nmap.nmap_udp_scan,
    }

    if scan_type not in stealth_scans:
        logging.error(f"Unsupported scan type: {scan_type}. Allowed types: {', '.join(stealth_scans.keys())}.")
        return None

    logging.info(f"Scanning {domain} on ports {ports} using {scan_type.upper()} scan.")

    try:
        scan_function = stealth_scans[scan_type]
        scan_result = scan_function(target=domain, args=f"-p{','.join(map(str, ports))}")
        logging.info("Scan completed successfully.")
        return scan_result
    except Exception as e:
        logging.error(f"Error during scan: {e}")
        return None

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

def generate_markdown_report(scan_results: Dict[str, Union[str, Dict]]) -> List[Paragraph]:
    """
    Generates a Markdown report from scan results.

    Args:
        scan_results (Dict): Nmap scan results.

    Returns:
        str: A Markdown-formatted string containing the scan report.
    """
    if not scan_results:
        return [Paragraph("No scan results available.")]

    doc = []
    open_ports = scan_results.get("ports", [])
    if open_ports:
        doc.append(Paragraph(f"{len(open_ports)} open ports detected:"))
        port_details = [
            f"Port {port['portid']} ({port.get('protocol', 'unknown')}): {port.get('state', 'unknown state')} - {get_port_threats(int(port['portid']))}"
            for port in open_ports
        ]
        doc.append(OrderedList(port_details))
    else:
        doc.append(Paragraph("No open ports were detected."))

    return doc

def nmap_runner(config: Dict) -> Dict[str, Optional[List]]:
    """
    Runner function for Nmap scan.

    Args:
        config (Dict): Configuration dictionary.

    Returns:
        Dict[str, Optional[Dict]]: Scan results.
    """
    domain = config.get("general", {}).get("target_url", "")
    nmap_conf = config.get("nmap", {})

    results = {
        "nmap": []
        }

    if not domain or not nmap_conf.get("enable", False):
        logging.info("Nmap scan is disabled or the target domain is not specified.")
        return results

    ports = parse_ports(nmap_conf.get("ports", ""))
    scan_type = nmap_conf.get("scan_type", "tcp")

    nmap_results = configure_nmap_scan(domain, ports, scan_type)
    results["nmap"] = generate_markdown_report(nmap_results)
    return results

def main() -> None:
    """
    Main function to execute Nmap scans and generate Markdown reports.
    """
    domain = "lezgivi.com"
    scan_type = "tcp"
    ports = "80,443"

    try:
        ports_list = parse_ports(ports)
        scan_result = configure_nmap_scan(domain, ports_list, scan_type)

        if scan_result:
            markdown_report = generate_markdown_report(scan_result)
            output_file = "scan_report.md"

            with open(output_file, "w") as f:
                f.write(markdown_report)

            logging.info(f"Markdown report saved to {output_file}")
        else:
            logging.error("Scan result is empty. Report generation skipped.")
    except ValueError as ve:
        logging.error(f"Invalid configuration: {ve}")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()
