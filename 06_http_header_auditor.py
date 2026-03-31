#!/usr/bin/env python3
"""06 · HTTP HEADER SECURITY AUDITOR — Deep header analysis + recommendations"""

import requests, argparse, json, sys
from colorama import Fore, Style, init
init(autoreset=True)
requests.packages.urllib3.disable_warnings()

BANNER = f"{Fore.CYAN}╔══════════════════════════════════════╗\n║  📋 HTTP HEADER AUDITOR  v1.0        ║\n║  Security headers deep analysis      ║\n╚══════════════════════════════════════╝{Style.RESET_ALL}"

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "level": "CRÍTICO", "required": True,
        "good_value": "max-age=31536000; includeSubDomains; preload",
        "desc": "Fuerza HTTPS — protege contra downgrade attacks",
        "check": lambda v: "max-age" in v and int(v.split("max-age=")[1].split(";")[0].strip()) >= 31536000,
    },
    "Content-Security-Policy": {
        "level": "ALTO", "required": True,
        "good_value": "default-src 'self'; script-src 'self'; object-src 'none'",
        "desc": "Previene XSS e inyección de contenido",
        "check": lambda v: "default-src" in v or "script-src" in v,
    },
    "X-Content-Type-Options": {
        "level": "MEDIO", "required": True,
        "good_value": "nosniff",
        "desc": "Previene MIME-type sniffing",
        "check": lambda v: v.strip().lower() == "nosniff",
    },
    "X-Frame-Options": {
        "level": "MEDIO", "required": True,
        "good_value": "DENY",
        "desc": "Previene Clickjacking",
        "check": lambda v: v.strip().upper() in ("DENY","SAMEORIGIN"),
    },
    "Referrer-Policy": {
        "level": "BAJO", "required": False,
        "good_value": "strict-origin-when-cross-origin",
        "desc": "Controla info en cabecera Referer",
        "check": lambda v: v.strip().lower() in ("no-referrer","strict-origin","strict-origin-when-cross-origin"),
    },
    "Permissions-Policy": {
        "level": "BAJO", "required": False,
        "good_value": "geolocation=(), microphone=(), camera=()",
        "desc": "Restringe acceso a APIs del navegador",
        "check": lambda v: len(v) > 5,
    },
    "X-XSS-Protection": {
        "level": "INFO", "required": False,
        "good_value": "0",
        "desc": "XSS filter heredado (CSP es preferido)",
        "check": lambda v: True,
    },
    "Cache-Control": {
        "level": "BAJO", "required": False,
        "good_value": "no-store, no-cache, must-revalidate",
        "desc": "Controla caché — relevante para páginas sensibles",
        "check": lambda v: "no-store" in v or "no-cache" in v,
    },
    "Cross-Origin-Embedder-Policy": {
        "level": "INFO", "required": False,
        "good_value": "require-corp",
        "desc": "COEP — aislamiento de origen cruzado",
        "check": lambda v: "require-corp" in v,
    },
    "Cross-Origin-Opener-Policy": {
        "level": "INFO", "required": False,
        "good_value": "same-origin",
        "desc": "COOP — protección contra Spectre/XS-Leaks",
        "check": lambda v: "same-origin" in v,
    },
}

LEAK_HEADERS = {
    "Server": "Revela software del servidor",
    "X-Powered-By": "Revela tecnología backend",
    "X-AspNet-Version": "Revela versión ASP.NET",
    "X-AspNetMvc-Version": "Revela versión MVC",
    "X-Generator": "Revela CMS/generador",
    "X-Drupal-Cache": "Revela Drupal",
    "X-Varnish": "Revela Varnish cache",
    "Via": "Revela proxies intermedios",
}

COOKIE_FLAGS = ["Secure","HttpOnly","SameSite"]

def analyze_cookies(resp: requests.Response) -> list:
    issues = []
    for cookie in resp.cookies:
        cookie_str = str(resp.headers.get("Set-Cookie",""))
        name = cookie.name
        if not cookie.secure:
            issues.append(("ALTO", f"Cookie '{name}' sin flag Secure"))
        if "httponly" not in cookie_str.lower() and "HttpOnly" not in cookie_str:
            if name in cookie_str:
                pass  # Puede estar ahí igualmente
        if "samesite" not in cookie_str.lower():
            issues.append(("MEDIO", f"Cookie '{name}' sin SameSite"))
    return issues

def analyze_csp(csp_value: str) -> list:
    issues = []
    if "'unsafe-inline'" in csp_value:
        issues.append("unsafe-inline detectado — permite XSS inline")
    if "'unsafe-eval'" in csp_value:
        issues.append("unsafe-eval detectado — permite eval() malicioso")
    if "http:" in csp_value:
        issues.append("Fuentes HTTP en CSP — posible downgrade")
    if "*" in csp_value and "wildcard" not in csp_value:
        issues.append("Wildcard (*) en CSP — demasiado permisivo")
    return issues

def grade_score(passed: int, total: int, critical_fail: int) -> str:
    if critical_fail >= 2: return "F"
    ratio = passed / max(total, 1)
    if ratio >= 0.9: return "A"
    if ratio >= 0.75: return "B"
    if ratio >= 0.6: return "C"
    if ratio >= 0.4: return "D"
    return "F"

def audit(url: str) -> dict:
    if not url.startswith("http"): url = "https://" + url
    result = {"url": url, "headers_present": [], "headers_missing": [],
              "leaks": [], "cookie_issues": [], "csp_issues": [], "grade": "?"}
    try:
        resp = requests.get(url, timeout=10, verify=False, allow_redirects=True,
                            headers={"User-Agent":"Mozilla/5.0 SecurityAudit/1.0"})
        result["status"]    = resp.status_code
        result["final_url"] = resp.url
        hdrs = {k.lower(): v for k,v in resp.headers.items()}

        passed = 0; critical_fail = 0
        for header, info in SECURITY_HEADERS.items():
            h_lower = header.lower()
            if h_lower in hdrs:
                val = hdrs[h_lower]
                ok  = True
                try: ok = info["check"](val)
                except: pass
                result["headers_present"].append({
                    "header": header, "value": val[:100], "ok": ok,
                    "level": info["level"], "desc": info["desc"],
                })
                if ok: passed += 1
                if not ok and info["level"] in ("CRÍTICO","ALTO"):
                    result["headers_missing"].append({
                        "header": header, "level": info["level"],
                        "desc": f"Presente pero mal configurado",
                        "recommended": info["good_value"],
                    })
                if header == "Content-Security-Policy":
                    result["csp_issues"] = analyze_csp(val)
            else:
                if info["required"]:
                    result["headers_missing"].append({
                        "header": header, "level": info["level"],
                        "desc": info["desc"], "recommended": info["good_value"],
                    })
                    if info["level"] == "CRÍTICO": critical_fail += 1

        for header, desc in LEAK_HEADERS.items():
            if header.lower() in hdrs:
                result["leaks"].append({"header": header,
                                         "value": hdrs[header.lower()][:80],
                                         "desc": desc})
        result["cookie_issues"] = analyze_cookies(resp)
        total  = len([h for h,i in SECURITY_HEADERS.items() if i["required"]])
        result["grade"] = grade_score(passed, total, critical_fail)
    except requests.exceptions.ConnectionError:
        result["error"] = "No se pudo conectar"
    except Exception as e:
        result["error"] = str(e)
    return result

def print_result(r: dict):
    grade_c = {"A":Fore.GREEN,"B":Fore.CYAN,"C":Fore.YELLOW,"D":Fore.RED,"F":Fore.RED}.get(r["grade"],Fore.WHITE)
    print(f"\n  {Fore.CYAN}URL   : {r.get('final_url', r['url'])}")
    print(f"  Status: {r.get('status','?')}")
    print(f"  {grade_c}Grade : {r['grade']}{Style.RESET_ALL}\n")

    if r.get("headers_missing"):
        print(f"  {Fore.RED}Headers Faltantes/Mal configurados:{Style.RESET_ALL}")
        for h in r["headers_missing"]:
            c = Fore.RED if h["level"] in ("CRÍTICO","ALTO") else Fore.YELLOW
            print(f"    {c}[{h['level']}]{Style.RESET_ALL} {h['header']}")
            print(f"           {Fore.GRAY}{h['desc']}{Style.RESET_ALL}")
            print(f"           {Fore.GREEN}→ {h['recommended']}{Style.RESET_ALL}")

    if r.get("headers_present"):
        print(f"\n  {Fore.GREEN}Headers Presentes:{Style.RESET_ALL}")
        for h in r["headers_present"]:
            ok_icon = f"{Fore.GREEN}✓" if h["ok"] else f"{Fore.YELLOW}⚠"
            print(f"    {ok_icon}{Style.RESET_ALL} {h['header']:<35} {Fore.GRAY}{h['value'][:40]}{Style.RESET_ALL}")

    if r.get("leaks"):
        print(f"\n  {Fore.YELLOW}Information Disclosure:{Style.RESET_ALL}")
        for l in r["leaks"]:
            print(f"    {Fore.YELLOW}⚠{Style.RESET_ALL} {l['header']}: {Fore.RED}{l['value']}{Style.RESET_ALL}")
            print(f"      {Fore.GRAY}{l['desc']}{Style.RESET_ALL}")

    if r.get("csp_issues"):
        print(f"\n  {Fore.YELLOW}CSP Issues:{Style.RESET_ALL}")
        for issue in r["csp_issues"]:
            print(f"    {Fore.YELLOW}⚠ {issue}{Style.RESET_ALL}")

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="HTTP Header Security Auditor")
    parser.add_argument("-t","--target",  help="URL o dominio")
    parser.add_argument("-f","--file",    default=None, help="Lista de URLs")
    parser.add_argument("-o","--output",  default=None)
    args = parser.parse_args()

    urls = []
    if args.file:
        with open(args.file) as f:
            urls = [l.strip() for l in f if l.strip()]
    elif args.target:
        urls = [args.target]
    else:
        urls = [input(f"{Fore.CYAN}URL: {Style.RESET_ALL}").strip()]

    results = []
    for url in urls:
        print(f"\n{Fore.CYAN}[*] Auditando: {url}{Style.RESET_ALL}")
        r = audit(url)
        print_result(r)
        results.append(r)

    if args.output:
        with open(args.output,"w") as f: json.dump(results, f, indent=2)
        print(f"\n{Fore.CYAN}[*] Guardado: {args.output}")

if __name__ == "__main__":
    main()
