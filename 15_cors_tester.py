#!/usr/bin/env python3
"""15 · CORS MISCONFIGURATION TESTER — Detect CORS policy flaws"""

import requests, argparse, json
from colorama import Fore, Style, init
init(autoreset=True)
requests.packages.urllib3.disable_warnings()

BANNER = f"{Fore.RED}╔══════════════════════════════════════╗\n║  🌐 CORS TESTER  v1.0                ║\n║  Detect CORS misconfiguration        ║\n╚══════════════════════════════════════╝{Style.RESET_ALL}"

EVIL_ORIGINS = [
    "https://evil.com", "null", "https://evil.target.com",
    "https://target.com.evil.com", "http://localhost",
    "https://target.com%60.evil.com", "https://不存在.com",
]

def test_cors(url: str, origin: str, method: str = "GET", timeout: float = 8.0) -> dict:
    try:
        hdrs = {"Origin": origin, "User-Agent": "CORSTester/1.0",
                "Access-Control-Request-Method": method,
                "Access-Control-Request-Headers": "Authorization, Content-Type"}
        r    = requests.options(url, headers=hdrs, timeout=timeout, verify=False)
        acao = r.headers.get("Access-Control-Allow-Origin","")
        acac = r.headers.get("Access-Control-Allow-Credentials","")
        acam = r.headers.get("Access-Control-Allow-Methods","")
        acah = r.headers.get("Access-Control-Allow-Headers","")

        vuln   = False
        issues = []
        level  = "INFO"

        if acao == "*":
            issues.append("Wildcard (*) — permite cualquier origen")
            level = "MEDIO"
        if acao == origin and "evil" in origin:
            vuln = True
            issues.append(f"Origen malicioso reflejado: {origin}")
            level = "CRÍTICO"
        if origin == "null" and acao == "null":
            vuln = True
            issues.append("Origen 'null' aceptado — sandbox bypass")
            level = "CRÍTICO"
        if acac.lower() == "true" and acao != "*":
            if acao == origin:
                vuln = True
                issues.append("Credentials=true + origen reflejado = CSRF via CORS")
                level = "CRÍTICO"
            else:
                issues.append("Credentials=true con origen controlado")
                level = "ALTO"

        return {
            "url": url, "origin": origin, "status": r.status_code,
            "acao": acao, "acac": acac, "acam": acam,
            "vulnerable": vuln, "issues": issues, "level": level,
        }
    except Exception as e:
        return {"url":url,"origin":origin,"error":str(e),"vulnerable":False,"issues":[]}

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="CORS Tester")
    parser.add_argument("-u","--url",    required=True)
    parser.add_argument("-o","--output", default=None)
    parser.add_argument("--custom-origin", default=None)
    args = parser.parse_args()

    url     = args.url if args.url.startswith("http") else "https://" + args.url
    origins = EVIL_ORIGINS + ([args.custom_origin] if args.custom_origin else [])
    results = []

    print(f"\n{Fore.CYAN}[*] Testing CORS en: {url}\n")
    for origin in origins:
        r = test_cors(url, origin)
        results.append(r)
        if r.get("vulnerable"):
            print(f"  {Fore.RED}[VULNERABLE]{Style.RESET_ALL} Origin: {origin}")
            for issue in r["issues"]:
                print(f"    {Fore.RED}⚠ {issue}{Style.RESET_ALL}")
            print(f"    ACAO: {r.get('acao','?')}  ACAC: {r.get('acac','?')}")
        elif r.get("issues"):
            print(f"  {Fore.YELLOW}[ISSUE]{Style.RESET_ALL} Origin: {origin}")
            for issue in r["issues"]:
                print(f"    {Fore.YELLOW}⚠ {issue}{Style.RESET_ALL}")
        else:
            print(f"  {Fore.GREEN}[OK]{Style.RESET_ALL} {origin[:40]}")

    vulns = [r for r in results if r.get("vulnerable")]
    print(f"\n{Fore.GRAY}{'─'*44}")
    print(f"{Fore.RED if vulns else Fore.GREEN}Vulnerabilidades: {len(vulns)}/{len(origins)}")

    if args.output:
        with open(args.output,"w") as f: json.dump(results, f, indent=2)
        print(f"{Fore.CYAN}[*] Guardado: {args.output}")

if __name__ == "__main__":
    main()
