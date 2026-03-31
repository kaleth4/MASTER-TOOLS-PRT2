#!/usr/bin/env python3
"""10 · CVE SEARCH — Query NVD/MITRE for vulnerabilities"""

import requests, argparse, json, sys, re
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)
requests.packages.urllib3.disable_warnings()

BANNER = f"{Fore.RED}╔══════════════════════════════════════╗\n║  🐛 CVE SEARCH  v1.0                 ║\n║  NVD + MITRE vulnerability lookup    ║\n╚══════════════════════════════════════╝{Style.RESET_ALL}"

NVD_BASE  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MITRE_BASE= "https://cve.circl.lu/api"

def search_nvd(keyword: str = None, cve_id: str = None,
               severity: str = None, year: int = None,
               max_results: int = 20) -> list:
    params = {"resultsPerPage": min(max_results, 200)}
    if cve_id:     params["cveId"]           = cve_id.upper()
    if keyword:    params["keywordSearch"]    = keyword
    if severity:   params["cvssV3Severity"]   = severity.upper()
    if year:
        params["pubStartDate"] = f"{year}-01-01T00:00:00.000"
        params["pubEndDate"]   = f"{year}-12-31T23:59:59.999"

    try:
        r = requests.get(NVD_BASE, params=params, timeout=15,
                         headers={"User-Agent":"CVE-Search-Tool/1.0"})
        if r.status_code != 200:
            print(f"{Fore.YELLOW}[!] NVD HTTP {r.status_code}")
            return []
        data = r.json()
        return data.get("vulnerabilities", [])
    except Exception as e:
        print(f"{Fore.RED}[✗] NVD error: {e}")
        return []

def search_mitre(cve_id: str) -> dict:
    try:
        r = requests.get(f"{MITRE_BASE}/cve/{cve_id.upper()}", timeout=10)
        if r.status_code == 200:
            return r.json()
    except: pass
    return {}

def parse_cve(vuln: dict) -> dict:
    cve    = vuln.get("cve", {})
    cve_id = cve.get("id","?")
    desc_list = cve.get("descriptions",[])
    desc      = next((d["value"] for d in desc_list if d.get("lang")=="en"),"No description")

    # CVSS v3
    metrics = cve.get("metrics",{})
    cvss3   = metrics.get("cvssMetricV31",[]) or metrics.get("cvssMetricV30",[])
    cvss2   = metrics.get("cvssMetricV2",[])

    score = "N/A"; severity = "N/A"; vector = "N/A"
    if cvss3:
        data     = cvss3[0].get("cvssData",{})
        score    = data.get("baseScore","N/A")
        severity = data.get("baseSeverity","N/A")
        vector   = data.get("vectorString","N/A")
    elif cvss2:
        data     = cvss2[0].get("cvssData",{})
        score    = data.get("baseScore","N/A")
        severity = cvss2[0].get("baseSeverity","N/A")

    refs = [r.get("url","") for r in cve.get("references",[])[:5]]
    weaknesses = [w.get("description",[{}])[0].get("value","") for w in cve.get("weaknesses",[])]
    published  = cve.get("published","?")[:10]

    return {
        "id": cve_id, "description": desc[:300],
        "score": score, "severity": severity,
        "vector": vector, "published": published,
        "references": refs, "cwe": weaknesses[:3],
    }

def severity_color(severity: str) -> str:
    s = str(severity).upper()
    if s == "CRITICAL": return Fore.RED
    if s == "HIGH":     return Fore.RED
    if s == "MEDIUM":   return Fore.YELLOW
    if s == "LOW":      return Fore.CYAN
    return Fore.WHITE

def score_bar(score) -> str:
    try:
        s    = float(score)
        bars = int(s)
        return f"{'█'*bars}{'░'*(10-bars)} {s}"
    except: return str(score)

def print_cve(c: dict, compact: bool = False):
    sc = severity_color(c["severity"])
    print(f"\n  {Fore.CYAN}{c['id']}{Style.RESET_ALL}  "
          f"{sc}[{c['severity']}  {c['score']}]{Style.RESET_ALL}  "
          f"{Fore.GRAY}{c['published']}{Style.RESET_ALL}")
    if not compact:
        print(f"  {Fore.WHITE}{c['description'][:200]}{Style.RESET_ALL}")
        if c.get("vector"):
            print(f"  {Fore.GRAY}Vector: {c['vector']}{Style.RESET_ALL}")
        if c.get("cwe"):
            print(f"  {Fore.YELLOW}CWE: {', '.join(c['cwe'])}{Style.RESET_ALL}")
        if c.get("references"):
            print(f"  {Fore.GRAY}Refs: {c['references'][0]}{Style.RESET_ALL}")

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="CVE Search Tool")
    parser.add_argument("-k","--keyword",  default=None, help="Keyword (ej: Apache Log4j)")
    parser.add_argument("-c","--cve",      default=None, help="CVE ID específico")
    parser.add_argument("-s","--severity", default=None,
                        choices=["LOW","MEDIUM","HIGH","CRITICAL"],
                        help="Filtrar por severidad")
    parser.add_argument("-y","--year",     type=int, default=None)
    parser.add_argument("-n","--max",      type=int, default=10)
    parser.add_argument("--compact",       action="store_true")
    parser.add_argument("-o","--output",   default=None)
    args = parser.parse_args()

    if not any([args.keyword, args.cve]):
        args.keyword = input(f"{Fore.CYAN}Buscar CVE (keyword o ID): {Style.RESET_ALL}").strip()

    print(f"\n{Fore.CYAN}[*] Consultando NVD...\n")
    vulns = search_nvd(args.keyword, args.cve, args.severity, args.year, args.max)

    if not vulns:
        print(f"{Fore.YELLOW}[!] Sin resultados")
        return

    cves = [parse_cve(v) for v in vulns]

    # Ordenar por score
    cves.sort(key=lambda x: float(x["score"]) if str(x["score"]).replace(".","").isdigit() else 0, reverse=True)

    print(f"{Fore.CYAN}[*] Resultados: {len(cves)}\n")
    print(f"{'─'*60}")

    for c in cves:
        print_cve(c, args.compact)

    print(f"\n{Fore.GRAY}{'─'*60}")
    criticals = len([c for c in cves if str(c["severity"]).upper() in ("CRITICAL","HIGH")])
    print(f"{Fore.RED}Críticos/Altos: {criticals}/{len(cves)}")

    if args.output:
        with open(args.output,"w") as f:
            json.dump(cves, f, indent=2)
        print(f"{Fore.CYAN}[*] Guardado: {args.output}")

if __name__ == "__main__":
    main()
