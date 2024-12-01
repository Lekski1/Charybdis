import argparse
import nmap
import random
import os
from itertools import chain

def parse_ports(ports):
    port_list = []
    for part in ports.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            port_list.extend(range(start, end + 1))
        else:
            port_list.append(int(part))
    return port_list

def load_proxies(proxy_file):
    proxies = []
    if os.path.exists(proxy_file):
        with open(proxy_file, 'r') as file:
            for line in file:
                line = line.strip()
                if line and not line.startswith('#'):
                    proxies.append(line)
    return proxies

def configure_nmap_scan(domain, ports, scan_type, proxy=None):
    nm = nmap.PortScanner()
    
    # Сбор аргументов для Nmap
    nmap_args = "-sS" 
    if scan_type == "udp":
        nmap_args = "-sU"
    
    if proxy:
        nmap_args += f" --proxies {proxy}"
    
    ports_str = ','.join(map(str, ports))

    print(f"Сканирование {domain} на портах {ports_str} с типом {scan_type}.")
    if proxy:
        print(f"Используется прокси: {proxy}")
    
    scan_result = nm.scan(domain, ports=ports_str, arguments=nmap_args)
    return scan_result

def main():
    parser = argparse.ArgumentParser(description="Nmap сканирование через прокси.")
    parser.add_argument("domain", help="Целевой домен или IP-адрес для сканирования.")
    parser.add_argument("scan_type", choices=["tcp", "udp"], help="Тип сканирования: tcp или udp.")
    parser.add_argument("ports", help="Список портов для сканирования, например: '1-400,546'.")
    parser.add_argument("--proxy_file", help="Файл с HTTP-прокси.", default=None)
    args = parser.parse_args()

    domain = args.domain
    scan_type = args.scan_type
    ports = parse_ports(args.ports)
    
    proxies = []
    if args.proxy_file:
        proxies = load_proxies(args.proxy_file)

    proxy = random.choice(proxies) if proxies else None

    scan_result = configure_nmap_scan(domain, ports, scan_type, proxy)

    print("Результаты сканирования:")
    for host, result in scan_result['scan'].items():
        print(f"Host: {host}")
        print(f"State: {result.get('status', {}).get('state', 'unknown')}")
        for proto in result.get('ports', {}):
            for port, details in result['ports'][proto].items():
                print(f"Port {port}/{proto}: {details.get('state')} ({details.get('name')})")

if __name__ == "__main__":
    main()
