#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════╗
║  01 · ASYNC PORT SCANNER             ║
║  Ultra-fast asyncio TCP scanner      ║
╚══════════════════════════════════════╝
Usage: python3 01_async_port_scanner.py -t 192.168.1.1 -p 1-1024
"""

import asyncio, argparse, socket, json, sys
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)

BANNER = f"""
{Fore.CYAN}╔══════════════════════════════════════╗
║  ⚡ ASYNC PORT SCANNER  v1.0         ║
║  asyncio — ultra-fast TCP scan       ║
╚══════════════════════════════════════╝{Style.RESET_ALL}
"""

SERVICE_MAP = {
    20:"FTP-data",21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",
    53:"DNS",67:"DHCP",68:"DHCP",69:"TFTP",80:"HTTP",
    110:"POP3",111:"RPC",119:"NNTP",123:"NTP",135:"MSRPC",
    137:"NetBIOS",138:"NetBIOS",139:"NetBIOS",143:"IMAP",
    161:"SNMP",162:"SNMP-trap",179:"BGP",194:"IRC",
    389:"LDAP",443:"HTTPS",445:"SMB",465:"SMTPS",
    514:"Syslog",515:"LPD",587:"SMTP-sub",631:"IPP",
    636:"LDAPS",873:"rsync",993:"IMAPS",995:"POP3S",
    1080:"SOCKS",1194:"OpenVPN",1433:"MSSQL",1521:"Oracle",
    1723:"PPTP",2049:"NFS",2181:"Zookeeper",2375:"Docker",
    2376:"Docker-TLS",3000:"Node/Grafana",3306:"MySQL",
    3389:"RDP",3690:"SVN",4444:"Metasploit",5000:"Flask",
    5432:"PostgreSQL",5672:"RabbitMQ",5900:"VNC",5985:"WinRM",
    6379:"Redis",6443:"K8s-API",7001:"WebLogic",8080:"HTTP-alt",
    8443:"HTTPS-alt",8888:"Jupyter",9000:"PHP-FPM",9090:"Prometheus",
    9200:"Elasticsearch",9300:"Elasticsearch-cluster",
    11211:"Memcached",27017:"MongoDB",27018:"MongoDB",
    50000:"SAP",50070:"Hadoop",61616:"ActiveMQ",
}

RISKY = {23,21,69,135,137,138,139,445,1433,3306,3389,
         5900,6379,9200,11211,27017,2375,4444,8888}

open_ports = []

async def scan_port(ip: str, port: int, timeout: float) -> tuple:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.close()
        try: await writer.wait_closed()
        except: pass
        return port, True
    except: return port, False

async def scan_range(ip: str, ports: list, timeout: float, semaphore: asyncio.Semaphore):
    async def bounded(port):
        async with semaphore:
            return await scan_port(ip, port, timeout)
    tasks = [bounded(p) for p in ports]
    return await asyncio.gather(*tasks)

def print_port(port: int, service: str, risky: bool):
    risk_tag = f" {Fore.RED}[RISKY]{Style.RESET_ALL}" if risky else ""
    print(f"  {Fore.GREEN}[OPEN]{Style.RESET_ALL} "
          f"{Fore.YELLOW}{port:6}{Style.RESET_ALL}  "
          f"{Fore.CYAN}{service:<20}{Style.RESET_ALL}{risk_tag}")

def parse_ports(port_str: str) -> list:
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            s, e = part.split("-", 1)
            ports.extend(range(int(s), int(e)+1))
        else:
            ports.append(int(part))
    return sorted(set(ports))

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Async Port Scanner")
    parser.add_argument("-t","--target",  required=True)
    parser.add_argument("-p","--ports",   default="1-1024")
    parser.add_argument("-c","--concurrency", type=int, default=500)
    parser.add_argument("--timeout",      type=float, default=0.8)
    parser.add_argument("-o","--output",  default=None)
    args = parser.parse_args()

    try: ip = socket.gethostbyname(args.target)
    except: print(f"{Fore.RED}[✗] No se pudo resolver: {args.target}"); sys.exit(1)

    if args.ports == "common":
        ports = list(SERVICE_MAP.keys())
    elif args.ports == "all":
        ports = list(range(1,65536))
    else:
        ports = parse_ports(args.ports)

    print(f"{Fore.CYAN}[*] Target      : {ip} ({args.target})")
    print(f"{Fore.CYAN}[*] Puertos     : {len(ports)}")
    print(f"{Fore.CYAN}[*] Concurrencia: {args.concurrency}")
    print(f"{Fore.CYAN}[*] Timeout     : {args.timeout}s")
    print(f"{Fore.GRAY}{'─'*44}\n")

    start = datetime.now()
    sem   = asyncio.Semaphore(args.concurrency)

    results = asyncio.run(scan_range(ip, ports, args.timeout, sem))
    elapsed = (datetime.now() - start).total_seconds()

    found = [(p, r) for p, r in results if r]
    for port, _ in sorted(found):
        service = SERVICE_MAP.get(port, "Unknown")
        risky   = port in RISKY
        print_port(port, service, risky)
        open_ports.append({"port":port,"service":service,"risky":risky})

    print(f"\n{Fore.GRAY}{'─'*44}")
    print(f"{Fore.GREEN}[✓] Abiertos : {len(found)}/{len(ports)}")
    print(f"{Fore.CYAN}[*] Tiempo   : {elapsed:.2f}s  ({len(ports)/elapsed:.0f} ports/s)")
    print(f"{Fore.RED}[!] Riesgosos: {sum(1 for p,_ in found if p in RISKY)}")

    if args.output:
        with open(args.output,"w") as f:
            json.dump({"target":ip,"ports":open_ports,"elapsed":elapsed}, f, indent=2)
        print(f"{Fore.CYAN}[*] Guardado: {args.output}")

if __name__ == "__main__":
    main()
