import telnetlib
import socket

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

def telnet_scan(ip, ports):
    results = []
    ports = parse_ports(ports)
    for idx, port in enumerate(ports):
        try:
            with telnetlib.Telnet(ip, port, timeout=5) as tn:
                try:
                    banner = tn.read_eager().decode("utf-8", "ignore")
                    threat = get_port_threats(port)
                    results.append(f"{idx}. Port {port}\n- status : open\n- banner: {banner if banner else "No banner received"}\n- {threat}\n")
                except EOFError:
                    results.append(f"{idx}. Port {port}\n- status: open\n- banner: No banner (EOF)\n")
        except (socket.timeout, ConnectionRefusedError, OSError, socket.gaierror) as e:
            results.append(f"{idx}. Port {port}\n- status: closed\n- error: {str(e)}\n")
    return results

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

def resolve_domain(domain):
    try:
        ips = [str(i[4][0]) for i in socket.getaddrinfo(domain, None)]
        return ips
    except socket.gaierror as e:
        print(f"Error {domain}: {e}")
        return []

def telnet_scan_configure(domain, ports):
    ips = resolve_domain(domain)
    if not ips:
        return {"error": f"Could not resolve domain {domain}"}

    result = telnet_scan(ips[0], ports)
    return Paragraph(
            f"Domain: {Bold(domain)}\n\n" +
            f"{"".join(result)}"
        )

def generate_markdown_report(scan_results):
    if not scan_results:
        return "No scan results available."

    doc = Document()
    doc.add(Paragraph("This report contains the results of a Telnet scan."))

    return doc

def telnet_runner(config: dict) -> dict:
    """
    Runner fot telnet scanning
    """
    domain = config["general"]["target_url"]
    telnet_conf = config["telnet"]

    results = {
        "telnet": None
    }

    if telnet_conf["enable"] is False:
        return results

    results["telnet"] = telnet_scan_configure(domain, telnet_conf["ports"])
    
    return results

def telnet():
    results = {}

    domain = 'lezgivi.com'
    ports = '78-80, 99'

    scan_result = telnet_scan_configure(domain, ports)
    results[domain] = scan_result
    print(results)

    markdown_report = generate_markdown_report(results)
    with open('telnet_report.md', "w", encoding="utf-8") as f:
        f.write(markdown_report.write())

    # print(f"Маркдавн сохранил telnet_report.md")

if __name__ == "__main__":
    telnet()