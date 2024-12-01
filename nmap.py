import nmap3
from markdownmaker.markdownmaker import Document, Paragraph, Bold, Node, OrderedList

def parse_ports(ports):
    port_list = []
    for part in ports.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            port_list.extend(range(start, end + 1))
        else:
            port_list.append(int(part))
    return port_list

def configure_nmap_scan(domain, ports, scan_type):
    nmap = nmap3.NmapScanTechniques()
    stealth_scans = {
        "syn": nmap.scan_top_ports,
        "fin": nmap.nmap_fin_scan,
        "tcp": nmap.nmap_tcp_scan,
        "udp": nmap.nmap_udp_scan
    }

    if scan_type not in stealth_scans:
        raise ValueError(f"Unsupported scan type: {scan_type}. Use one of {', '.join(stealth_scans.keys())}.")

    print(f"Scanning {domain} on ports {ports} with scan type {scan_type}.")

    scan_function = stealth_scans[scan_type]
    scan_result = scan_function(target=domain, args=f"-p{','.join(map(str, ports))}")
    print(scan_result)
    return scan_result

def get_port_threats(port):
    threats = {
        21: "FTP - possible brute-force attacks or data theft.",
        22: "SSH - risk of brute-force attacks or vulnerabilities.",
        23: "Telnet - unencrypted access, risk of data interception.",
        80: "HTTP - potential web application attacks.",
        443: "HTTPS - MITM attacks if SSL is misconfigured.",
        3306: "MySQL - risk of unauthorized database access.",
        3389: "RDP - possibility of brute-force attacks or exploitation."
    }
    return threats.get(port, "No known threats for this port in our database.")

def generate_markdown_report(scan_results):
    if not scan_results:
        return "No scan results available."

    doc = Document()
    doc.add(Paragraph("This report contains the results of an Nmap scan."))

    return doc

def nmap():
    domain = "lezgivi.com"  
    scan_type = "tcp"
    ports = "80"

    try:
        scan_result = configure_nmap_scan(domain, parse_ports(ports), scan_type)
        print("Scan Results:")

        markdown_report = generate_markdown_report(scan_result)
        output_file = "scan_report.md"  # Specify output filename
        with open(output_file, "w") as f:
            f.write(markdown_report.write())
        print(f"Markdown report saved to {output_file}")
    except ValueError as e:
        print(e)
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    nmap()
