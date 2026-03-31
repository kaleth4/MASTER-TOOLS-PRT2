#!/usr/bin/env python3
"""08 · ARP SPOOF DETECTOR — Detect ARP poisoning on local network"""

import socket, subprocess, re, time, argparse, json, platform
from colorama import Fore, Style, init
init(autoreset=True)

BANNER = f"{Fore.RED}╔══════════════════════════════════════╗\n║  🔺 ARP SPOOF DETECTOR  v1.0         ║\n║  Detect ARP poisoning / MITM attacks ║\n╚══════════════════════════════════════╝{Style.RESET_ALL}"

def get_arp_table_linux() -> list:
    entries = []
    try:
        out = subprocess.check_output(["arp","-n"], text=True)
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 3 and parts[2] != "(incomplete)":
                entries.append({"ip": parts[0], "mac": parts[2].lower(), "iface": parts[-1]})
    except Exception:
        try:
            with open("/proc/net/arp") as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                        entries.append({"ip": parts[0], "mac": parts[3].lower(), "iface": parts[-1]})
        except: pass
    return entries

def get_arp_table_windows() -> list:
    entries = []
    try:
        out = subprocess.check_output(["arp","-a"], text=True, encoding="cp1252", errors="replace")
        for line in out.splitlines():
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\-]{17})", line)
            if m:
                entries.append({"ip": m.group(1), "mac": m.group(2).replace("-",":").lower(), "iface": ""})
    except: pass
    return entries

def get_arp_table() -> list:
    if platform.system() == "Linux":
        return get_arp_table_linux()
    elif platform.system() == "Windows":
        return get_arp_table_windows()
    return []

def detect_duplicates(entries: list) -> list:
    """Detect: same MAC → multiple IPs (or same IP → multiple MACs)."""
    issues = []
    mac_to_ips = {}
    ip_to_macs = {}
    for e in entries:
        mac_to_ips.setdefault(e["mac"], []).append(e["ip"])
        ip_to_macs.setdefault(e["ip"],  []).append(e["mac"])

    for mac, ips in mac_to_ips.items():
        if len(ips) > 1:
            issues.append({
                "type":    "MAC_DUPLICATE",
                "level":   "ALTO",
                "message": f"Mismo MAC {mac} tiene múltiples IPs: {ips}",
                "detail":  "Posible ARP spoofing — un host haciéndose pasar por varios",
            })

    for ip, macs in ip_to_macs.items():
        if len(macs) > 1:
            issues.append({
                "type":    "IP_DUPLICATE",
                "level":   "CRÍTICO",
                "message": f"Misma IP {ip} tiene múltiples MACs: {macs}",
                "detail":  "ARP spoofing confirmado — IP disputada",
            })

    return issues

def check_gateway_mac(entries: list) -> list:
    """Verify gateway MAC hasn't changed."""
    issues = []
    gateway = None
    try:
        if platform.system() == "Linux":
            out = subprocess.check_output(["ip","route","show","default"], text=True)
            m   = re.search(r"via (\d+\.\d+\.\d+\.\d+)", out)
            if m: gateway = m.group(1)
        elif platform.system() == "Windows":
            out = subprocess.check_output(["route","print","0.0.0.0"], text=True)
            m   = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", out)
            if m: gateway = m.group(1)
    except: pass

    if gateway:
        gw_entries = [e for e in entries if e["ip"] == gateway]
        if len(gw_entries) > 1:
            macs = [e["mac"] for e in gw_entries]
            issues.append({
                "type":    "GATEWAY_SPOOFED",
                "level":   "CRÍTICO",
                "message": f"Gateway {gateway} tiene múltiples MACs: {macs}",
                "detail":  "¡ARP poisoning del gateway! Posible MITM total",
            })
    return issues, gateway

def monitor_arp(interval: int, log_file: str):
    baseline = {}
    alerts   = []
    print(f"{Fore.CYAN}[*] Estableciendo baseline ARP...\n")

    entries = get_arp_table()
    for e in entries:
        baseline[e["ip"]] = e["mac"]
        print(f"  {Fore.GRAY}{e['ip']:<18} {e['mac']}{Style.RESET_ALL}")

    print(f"\n{Fore.GREEN}[✓] Baseline: {len(baseline)} entradas")
    print(f"{Fore.CYAN}[*] Monitoreando cada {interval}s (Ctrl+C para detener)...\n")

    try:
        while True:
            time.sleep(interval)
            current = get_arp_table()
            for e in current:
                ip  = e["ip"]
                mac = e["mac"]
                if ip in baseline and baseline[ip] != mac:
                    ts  = time.strftime("%H:%M:%S")
                    alert = {
                        "ts": ts, "ip": ip,
                        "old_mac": baseline[ip], "new_mac": mac,
                    }
                    alerts.append(alert)
                    print(f"\n  {Fore.RED}[{ts}] ⚠ ARP CHANGE DETECTED!")
                    print(f"  IP      : {ip}")
                    print(f"  Old MAC : {baseline[ip]}")
                    print(f"  New MAC : {mac}")
                    print(f"  {Fore.RED}→ Posible ARP spoofing / MITM{Style.RESET_ALL}\n")
                    baseline[ip] = mac
                elif ip not in baseline:
                    baseline[ip] = mac
                    print(f"  {Fore.YELLOW}[NUEVO] {ip} → {mac}{Style.RESET_ALL}")
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Monitoreo detenido. Alertas: {len(alerts)}")
        if log_file and alerts:
            with open(log_file,"w") as f:
                json.dump(alerts, f, indent=2)
            print(f"{Fore.CYAN}[*] Log: {log_file}")

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="ARP Spoof Detector")
    parser.add_argument("--monitor",  action="store_true", help="Modo monitoreo continuo")
    parser.add_argument("-i","--interval", type=int, default=10)
    parser.add_argument("-o","--output",   default="arp_alerts.json")
    args = parser.parse_args()

    if args.monitor:
        monitor_arp(args.interval, args.output)
        return

    print(f"{Fore.CYAN}[*] Analizando tabla ARP...\n")
    entries = get_arp_table()

    if not entries:
        print(f"{Fore.YELLOW}[!] Sin entradas ARP. ¿Requiere root?")
        return

    print(f"  {Fore.CYAN}{'IP':<20} {'MAC':<20} {'Interfaz'}{Style.RESET_ALL}")
    print(f"  {Fore.GRAY}{'─'*50}{Style.RESET_ALL}")
    for e in entries:
        print(f"  {e['ip']:<20} {e['mac']:<20} {e.get('iface','')}")

    issues  = detect_duplicates(entries)
    gw_iss, gateway = check_gateway_mac(entries)
    issues += gw_iss

    if gateway:
        print(f"\n  {Fore.CYAN}Gateway detectado: {gateway}{Style.RESET_ALL}")

    print(f"\n{Fore.GRAY}{'─'*44}")
    if issues:
        print(f"\n{Fore.RED}[!] ANOMALÍAS DETECTADAS:{Style.RESET_ALL}")
        for issue in issues:
            c = Fore.RED if issue["level"] == "CRÍTICO" else Fore.YELLOW
            print(f"  {c}[{issue['level']}]{Style.RESET_ALL} {issue['message']}")
            print(f"    {Fore.GRAY}{issue['detail']}{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}[✓] Sin anomalías ARP detectadas")
        print(f"{Fore.CYAN}    Usa --monitor para vigilancia continua")

if __name__ == "__main__":
    main()
