#!/usr/bin/env python3
"""11 · NETWORK MAPPER — Discover live hosts in subnet"""

import socket, argparse, json, ipaddress, concurrent.futures, subprocess, platform, re
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)

BANNER = f"{Fore.CYAN}╔══════════════════════════════════════╗\n║  🗺️  NETWORK MAPPER  v1.0            ║\n║  Live host discovery + OS fingerprint║\n╚══════════════════════════════════════╝{Style.RESET_ALL}"

def ping(ip: str, timeout: float = 1.0) -> bool:
    flag = "-n" if platform.system() == "Windows" else "-c"
    try:
        result = subprocess.run(
            ["ping", flag, "1", "-W" if platform.system()!="Windows" else "-w",
             "1000" if platform.system()=="Windows" else "1", str(ip)],
            capture_output=True, timeout=timeout+1
        )
        return result.returncode == 0
    except: return False

def tcp_ping(ip: str, ports: list = [80,22,443,8080,445], timeout: float = 0.5) -> bool:
    for port in ports:
        try:
            with socket.create_connection((str(ip), port), timeout=timeout):
                return True
        except: pass
    return False

def resolve_hostname(ip: str) -> str:
    try: return socket.gethostbyaddr(str(ip))[0]
    except: return ""

def grab_banner_host(ip: str, port: int = 22) -> str:
    try:
        with socket.create_connection((str(ip), port), timeout=2) as s:
            return s.recv(256).decode(errors="replace").strip()[:60]
    except: return ""

def get_mac_from_arp(ip: str) -> str:
    try:
        out = subprocess.check_output(["arp", "-n", str(ip)], text=True, timeout=3)
        m   = re.search(r"([0-9a-fA-F:]{17})", out)
        return m.group(1).lower() if m else ""
    except: return ""

def scan_host(ip) -> dict | None:
    ip_str = str(ip)
    alive  = ping(ip_str) or tcp_ping(ip_str)
    if not alive: return None
    hostname = resolve_hostname(ip_str)
    mac      = get_mac_from_arp(ip_str)
    banner   = grab_banner_host(ip_str)
    return {"ip": ip_str, "hostname": hostname, "mac": mac, "banner": banner, "alive": True}

def scan_network(network: str, workers: int = 50) -> list:
    try:
        net   = ipaddress.ip_network(network, strict=False)
        hosts = list(net.hosts())
    except ValueError as e:
        print(f"{Fore.RED}[✗] Red inválida: {e}"); return []

    print(f"{Fore.CYAN}[*] Red      : {network}")
    print(f"{Fore.CYAN}[*] Hosts    : {len(hosts)}")
    print(f"{Fore.CYAN}[*] Workers  : {workers}")
    print(f"{Fore.GRAY}{'─'*44}\n")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(scan_host, ip): ip for ip in hosts}
        done = 0
        for future in concurrent.futures.as_completed(futures):
            done += 1
            r = future.result()
            if r:
                results.append(r)
                print(f"  {Fore.GREEN}[UP]{Style.RESET_ALL} "
                      f"{Fore.YELLOW}{r['ip']:<18}{Style.RESET_ALL}"
                      f"{Fore.CYAN}{r.get('hostname',''):<30}{Style.RESET_ALL}"
                      f"{Fore.GRAY}{r.get('mac','')}{Style.RESET_ALL}")
            else:
                import sys
                sys.stdout.write(f"\r  {Fore.GRAY}[{done}/{len(hosts)}] Escaneando...{Style.RESET_ALL}   ")
                sys.stdout.flush()
    print()
    return results

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Network Mapper")
    parser.add_argument("-n","--network",  help="Red CIDR (ej: 192.168.1.0/24)")
    parser.add_argument("-w","--workers",  type=int, default=50)
    parser.add_argument("-o","--output",   default=None)
    args = parser.parse_args()

    network = args.network or input(f"{Fore.CYAN}Red CIDR: {Style.RESET_ALL}").strip()
    start   = datetime.now()
    results = scan_network(network, args.workers)
    elapsed = (datetime.now()-start).total_seconds()

    print(f"\n{Fore.GRAY}{'─'*44}")
    print(f"{Fore.GREEN}[✓] Hosts activos: {len(results)}")
    print(f"{Fore.CYAN}[*] Tiempo: {elapsed:.1f}s")

    if args.output:
        with open(args.output,"w") as f: json.dump(results, f, indent=2)
        print(f"{Fore.CYAN}[*] Guardado: {args.output}")

if __name__ == "__main__":
    main()
