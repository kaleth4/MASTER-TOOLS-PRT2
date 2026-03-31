#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════╗
║  02 · SUBDOMAIN ENUMERATOR           ║
║  DNS brute-force + certificate recon ║
╚══════════════════════════════════════╝
Usage: python3 02_subdomain_enum.py -d example.com -w subdomains.txt
"""

import socket, argparse, json, concurrent.futures, sys, requests
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)
requests.packages.urllib3.disable_warnings()

BANNER = f"""
{Fore.YELLOW}╔══════════════════════════════════════╗
║  🌐 SUBDOMAIN ENUMERATOR  v1.0       ║
║  DNS brute-force + crt.sh recon      ║
╚══════════════════════════════════════╝{Style.RESET_ALL}
"""

DEFAULT_WORDLIST = [
    "www","mail","ftp","smtp","pop","imap","webmail","admin","portal",
    "api","dev","staging","test","beta","vpn","remote","support",
    "blog","shop","store","cdn","static","img","images","media",
    "docs","wiki","git","gitlab","jira","jenkins","dashboard",
    "monitor","grafana","kibana","elastic","db","database","sql",
    "mysql","postgres","redis","mongo","backup","files","upload",
    "download","mobile","app","web","ns1","ns2","mx","mx1","mx2",
    "autodiscover","autoconfig","cpanel","whm","plesk","phpmyadmin",
    "auth","oauth","login","sso","proxy","gateway","waf","firewall",
    "intranet","internal","corp","office","hr","finance","legal",
]

found_subdomains = []

def resolve_subdomain(subdomain: str, domain: str, timeout: float = 2.0) -> dict | None:
    fqdn = f"{subdomain}.{domain}"
    try:
        socket.setdefaulttimeout(timeout)
        ips = socket.gethostbyname_ex(fqdn)[2]
        return {"fqdn": fqdn, "ips": ips, "source": "dns_brute"}
    except: return None

def query_crtsh(domain: str) -> list:
    """Passive recon via crt.sh certificate transparency."""
    found = []
    try:
        r = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=15, verify=False
        )
        if r.status_code == 200:
            data = r.json()
            names = set()
            for entry in data:
                name = entry.get("name_value","").strip().lower()
                for n in name.split("\n"):
                    n = n.strip().lstrip("*.")
                    if n.endswith(domain) and n != domain:
                        names.add(n)
            for name in names:
                try:
                    ips = socket.gethostbyname_ex(name)[2]
                    found.append({"fqdn": name, "ips": ips, "source": "crt.sh"})
                except: pass
    except Exception as e:
        print(f"{Fore.YELLOW}[!] crt.sh error: {e}{Style.RESET_ALL}")
    return found

def http_probe(fqdn: str) -> dict:
    """Check if subdomain responds to HTTP/HTTPS."""
    result = {"http": False, "https": False, "title": "", "status": 0}
    for scheme in ["https","http"]:
        try:
            r = requests.get(f"{scheme}://{fqdn}", timeout=4,
                             verify=False, allow_redirects=True,
                             headers={"User-Agent":"Mozilla/5.0"})
            result[scheme] = True
            result["status"] = r.status_code
            import re
            m = re.search(r"<title>(.*?)</title>", r.text, re.IGNORECASE|re.DOTALL)
            result["title"] = m.group(1).strip()[:60] if m else ""
            break
        except: pass
    return result

def brute_force(domain: str, wordlist: list, workers: int, probe: bool) -> list:
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(resolve_subdomain, sub, domain): sub for sub in wordlist}
        for i, future in enumerate(concurrent.futures.as_completed(futures), 1):
            r = future.result()
            if r:
                if probe:
                    r["http_info"] = http_probe(r["fqdn"])
                results.append(r)
                http_icon = "🌐" if r.get("http_info",{}).get("https") or r.get("http_info",{}).get("http") else ""
                print(f"  {Fore.GREEN}[FOUND]{Style.RESET_ALL} "
                      f"{Fore.YELLOW}{r['fqdn']:<40}{Style.RESET_ALL} "
                      f"{Fore.CYAN}{r['ips']}{Style.RESET_ALL} {http_icon}")
                if probe and r.get("http_info",{}).get("title"):
                    print(f"          {Fore.GRAY}Title: {r['http_info']['title']}{Style.RESET_ALL}")
            else:
                sys.stdout.write(f"\r  {Fore.GRAY}[{i}/{len(wordlist)}] Probando...{Style.RESET_ALL}   ")
                sys.stdout.flush()
    print()
    return results

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Subdomain Enumerator")
    parser.add_argument("-d","--domain",   required=True)
    parser.add_argument("-w","--wordlist",  default=None)
    parser.add_argument("-o","--output",    default=None)
    parser.add_argument("--workers",        type=int, default=50)
    parser.add_argument("--crtsh",          action="store_true", default=True)
    parser.add_argument("--probe",          action="store_true", default=False,
                        help="HTTP probe cada subdominio encontrado")
    parser.add_argument("--no-brute",       action="store_true")
    args = parser.parse_args()

    print(f"{Fore.CYAN}[*] Dominio  : {args.domain}")
    print(f"{Fore.CYAN}[*] Workers  : {args.workers}")
    print(f"{Fore.GRAY}{'─'*44}\n")

    all_results = []
    start = datetime.now()

    # Passive recon via crt.sh
    if args.crtsh:
        print(f"{Fore.CYAN}[*] Buscando en crt.sh (Certificate Transparency)...")
        ct_results = query_crtsh(args.domain)
        if ct_results:
            for r in ct_results:
                print(f"  {Fore.MAGENTA}[crt.sh]{Style.RESET_ALL} "
                      f"{Fore.YELLOW}{r['fqdn']:<40}{Style.RESET_ALL} "
                      f"{Fore.CYAN}{r['ips']}{Style.RESET_ALL}")
            all_results.extend(ct_results)
        else:
            print(f"  {Fore.GRAY}Sin resultados en crt.sh{Style.RESET_ALL}")
        print()

    # Active brute force
    if not args.no_brute:
        wordlist = DEFAULT_WORDLIST
        if args.wordlist:
            try:
                with open(args.wordlist) as f:
                    wordlist = [l.strip() for l in f if l.strip()]
            except: print(f"{Fore.YELLOW}[!] Wordlist no encontrada, usando lista interna")

        print(f"{Fore.CYAN}[*] Brute-force DNS ({len(wordlist)} palabras)...\n")
        brute_results = brute_force(args.domain, wordlist, args.workers, args.probe)
        all_results.extend(brute_results)

    # Deduplication
    seen  = set()
    dedup = []
    for r in all_results:
        if r["fqdn"] not in seen:
            seen.add(r["fqdn"])
            dedup.append(r)

    elapsed = (datetime.now() - start).total_seconds()
    print(f"\n{Fore.GRAY}{'─'*44}")
    print(f"{Fore.GREEN}[✓] Subdominios únicos: {len(dedup)}")
    print(f"{Fore.CYAN}[*] Tiempo: {elapsed:.1f}s")

    if args.output:
        with open(args.output,"w") as f:
            json.dump({"domain":args.domain,"results":dedup}, f, indent=2)
        print(f"{Fore.CYAN}[*] Guardado: {args.output}")

if __name__ == "__main__":
    main()
