#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════╗
║  05 · WHOIS & IP GEO OSINT           ║
║  Domain/IP intelligence gathering   ║
╚══════════════════════════════════════╝
Usage: python3 05_whois_geo.py -t example.com
"""

import socket, argparse, json, sys, re, requests
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)
requests.packages.urllib3.disable_warnings()

BANNER = f"""
{Fore.YELLOW}╔══════════════════════════════════════╗
║  🌍 WHOIS & IP GEO OSINT  v1.0      ║
║  Domain + IP intelligence            ║
╚══════════════════════════════════════╝{Style.RESET_ALL}
"""

def whois_query(target: str) -> str:
    """Raw WHOIS query."""
    whois_servers = {
        ".com": "whois.verisign-grs.com", ".net": "whois.verisign-grs.com",
        ".org": "whois.pir.org", ".io":  "whois.nic.io",
        ".co":  "whois.nic.co",  ".uk":  "whois.nic.uk",
        ".de":  "whois.denic.de", ".fr": "whois.nic.fr",
    }
    tld    = "." + target.rsplit(".",1)[-1].lower()
    server = whois_servers.get(tld, "whois.iana.org")
    try:
        with socket.create_connection((server, 43), timeout=10) as s:
            s.sendall((target + "\r\n").encode())
            resp = b""
            while True:
                chunk = s.recv(4096)
                if not chunk: break
                resp += chunk
        return resp.decode(errors="replace")
    except Exception as e:
        return f"Error WHOIS: {e}"

def parse_whois(raw: str) -> dict:
    info = {}
    patterns = {
        "registrar":     r"Registrar:\s*(.+)",
        "registered":    r"Creation Date:\s*(.+)",
        "expires":       r"Registry Expiry Date:\s*(.+)",
        "updated":       r"Updated Date:\s*(.+)",
        "status":        r"Domain Status:\s*(.+)",
        "name_servers":  r"Name Server:\s*(.+)",
        "registrant_org":r"Registrant Organization:\s*(.+)",
        "registrant_country":r"Registrant Country:\s*(.+)",
        "abuse_email":   r"Abuse Email:\s*(.+)",
    }
    for key, pat in patterns.items():
        m = re.findall(pat, raw, re.IGNORECASE)
        if m:
            info[key] = m[0].strip() if len(m)==1 else [x.strip() for x in m[:5]]
    return info

def ip_geolocation(ip: str) -> dict:
    """Free IP geolocation via ip-api.com."""
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,"
                         f"region,regionName,city,zip,lat,lon,isp,org,as,query",
                         timeout=8)
        data = r.json()
        if data.get("status") == "success":
            return data
        return {}
    except: return {}

def dns_records(domain: str) -> dict:
    records = {}
    record_types = ["A","AAAA","MX","NS","TXT","SOA","CNAME"]
    try:
        import dns.resolver
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                records[rtype] = [str(r) for r in answers]
            except: pass
    except ImportError:
        # Fallback sin dnspython
        try:
            records["A"] = list(socket.gethostbyname_ex(domain)[2])
        except: pass
    return records

def reverse_dns(ip: str) -> list:
    try:
        result = socket.gethostbyaddr(ip)
        return [result[0]] + result[1]
    except: return []

def check_blacklist(ip: str) -> list:
    """Check common DNSBL blacklists."""
    dnsbl_list = [
        "zen.spamhaus.org","bl.spamcop.net","dnsbl.sorbs.net",
        "b.barracudacentral.org","dnsbl-1.uceprotect.net",
    ]
    listed = []
    reversed_ip = ".".join(reversed(ip.split(".")))
    for dnsbl in dnsbl_list:
        lookup = f"{reversed_ip}.{dnsbl}"
        try:
            socket.gethostbyname(lookup)
            listed.append(dnsbl)
        except socket.gaierror:
            pass
    return listed

def print_section(title: str, data: dict | str):
    print(f"\n  {Fore.CYAN}═══ {title} ═══{Style.RESET_ALL}")
    if isinstance(data, str):
        for line in data.splitlines()[:20]:
            if line.strip():
                print(f"  {Fore.GRAY}{line}{Style.RESET_ALL}")
    elif isinstance(data, dict):
        for k, v in data.items():
            val = ", ".join(v) if isinstance(v, list) else str(v)
            print(f"  {Fore.YELLOW}{k:<20}{Style.RESET_ALL}: {val[:80]}")

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="WHOIS & IP Geo OSINT")
    parser.add_argument("-t","--target",  required=True, help="Dominio o IP")
    parser.add_argument("--no-whois",    action="store_true")
    parser.add_argument("--no-dns",      action="store_true")
    parser.add_argument("--no-geo",      action="store_true")
    parser.add_argument("--blacklist",   action="store_true")
    parser.add_argument("-o","--output", default=None)
    args = parser.parse_args()

    target  = args.target.strip().lower().replace("http://","").replace("https://","").split("/")[0]
    is_ip   = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target)
    result  = {"target": target}

    print(f"{Fore.CYAN}[*] Objetivo: {target}")
    print(f"{Fore.GRAY}{'─'*44}")

    # Resolver IP
    if not is_ip:
        try:
            ip = socket.gethostbyname(target)
            print(f"{Fore.GREEN}[+] IP resuelta: {ip}")
            result["ip"] = ip
        except:
            ip = None
            print(f"{Fore.YELLOW}[!] No se pudo resolver IP")
    else:
        ip = target

    # WHOIS
    if not args.no_whois and not is_ip:
        print(f"\n{Fore.CYAN}[*] Consulta WHOIS...")
        raw_whois  = whois_query(target)
        parsed     = parse_whois(raw_whois)
        result["whois"] = parsed
        print_section("WHOIS", parsed)

    # DNS Records
    if not args.no_dns and not is_ip:
        print(f"\n{Fore.CYAN}[*] Registros DNS...")
        dns_recs = dns_records(target)
        result["dns"] = dns_recs
        print_section("DNS RECORDS", dns_recs)

    # Reverse DNS
    if ip:
        rdns = reverse_dns(ip)
        if rdns:
            print(f"\n  {Fore.CYAN}Reverse DNS:{Style.RESET_ALL} {rdns}")
            result["rdns"] = rdns

    # Geo
    if not args.no_geo and ip:
        print(f"\n{Fore.CYAN}[*] Geolocalización IP...")
        geo = ip_geolocation(ip)
        if geo:
            result["geo"] = geo
            print(f"\n  {Fore.CYAN}═══ GEOLOCALIZACIÓN ═══{Style.RESET_ALL}")
            fields = [("País","country"),("Ciudad","city"),("ISP","isp"),
                      ("Org","org"),("AS","as"),("Lat/Lon","lat")]
            for label, key in fields:
                val = geo.get(key,"?")
                if key == "lat":
                    val = f"{geo.get('lat','?')}, {geo.get('lon','?')}"
                print(f"  {Fore.YELLOW}{label:<12}{Style.RESET_ALL}: {val}")

    # Blacklist check
    if args.blacklist and ip:
        print(f"\n{Fore.CYAN}[*] Verificando blacklists DNS...")
        listed = check_blacklist(ip)
        if listed:
            print(f"  {Fore.RED}[!] IP en {len(listed)} blacklist(s):")
            for bl in listed:
                print(f"    {Fore.RED}✗ {bl}{Style.RESET_ALL}")
        else:
            print(f"  {Fore.GREEN}[✓] IP no está en blacklists verificadas")
        result["blacklists"] = listed

    if args.output:
        with open(args.output,"w") as f:
            json.dump(result, f, indent=2, default=str)
        print(f"\n{Fore.CYAN}[*] Guardado: {args.output}")

if __name__ == "__main__":
    main()
