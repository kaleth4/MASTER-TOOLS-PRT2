#!/usr/bin/env python3
"""09 · LOG ANALYZER — Security analysis of web/system logs"""

import re, argparse, json, os, sys
from collections import Counter
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)

BANNER = f"{Fore.CYAN}╔══════════════════════════════════════╗\n║  📋 LOG ANALYZER  v1.0               ║\n║  Apache/Nginx/Auth log security scan ║\n╚══════════════════════════════════════╝{Style.RESET_ALL}"

# Patrones de amenazas en logs web
WEB_THREATS = [
    ("SQL_INJECTION",  "CRÍTICO", r"(union\s+select|select\s+\*|drop\s+table|insert\s+into|'--|\bOR\b\s+1=1|1=1--|xp_cmdshell)", ),
    ("XSS",            "ALTO",   r"(<script|javascript:|onerror=|onload=|alert\(|document\.cookie)",),
    ("PATH_TRAVERSAL", "ALTO",   r"(\.\./|\.\.\\|%2e%2e%2f|%252e%252e)",),
    ("CMD_INJECTION",  "CRÍTICO", r"(;.*?(cat|ls|whoami|id|pwd|wget|curl|bash|sh)\b|\|.*?(cat|ls|whoami))",),
    ("SCANNER",        "MEDIO",  r"(nikto|sqlmap|nmap|masscan|zgrab|nuclei|burpsuite|acunetix|nessus)",),
    ("SHELL_UPLOAD",   "CRÍTICO", r"(\.php\?|\.asp\?|\.aspx\?|\.jsp\?|webshell|c99|r57|cmd=|exec=)",),
    ("AUTH_BYPASS",    "ALTO",   r"(admin'--|password'--|bypass|' or '1'='1)",),
    ("SENSITIVE_PATH", "MEDIO",  r"(/etc/passwd|/etc/shadow|/proc/self|/sys/|\.git/|\.env|config\.php|wp-config)",),
]

# Patrones en auth.log / secure
AUTH_THREATS = [
    ("FAILED_LOGIN",   r"Failed password|authentication failure|Invalid user"),
    ("ROOT_LOGIN",     r"Accepted.*root|session opened for user root"),
    ("SUDO_ESCALATION",r"sudo:.*COMMAND"),
    ("SSH_SCAN",       r"Invalid user|Did not receive identification"),
]

APACHE_PATTERN = re.compile(
    r'(\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]*?)"\s+(\d+)\s+(\d+|-)'
    r'(?:\s+"([^"]*?)")?\s*(?:"([^"]*?)")?'
)

def parse_apache_log(line: str) -> dict | None:
    m = APACHE_PATTERN.match(line)
    if not m: return None
    return {
        "ip": m.group(1), "time": m.group(2),
        "request": m.group(3), "status": int(m.group(4)),
        "size": m.group(5), "referer": m.group(6) or "",
        "ua": m.group(7) or "",
    }

def analyze_web_log(path: str, limit: int = 50000) -> dict:
    result = {
        "type": "web", "path": path,
        "total_lines": 0, "parsed": 0,
        "threats": [], "top_ips": [], "top_paths": [],
        "status_dist": {}, "error_5xx": [], "brute_force": [],
    }
    ip_counter   = Counter()
    path_counter = Counter()
    ip_errors    = Counter()

    try:
        with open(path, "r", errors="ignore") as f:
            lines = f.readlines()[-limit:]
    except PermissionError:
        result["error"] = f"Sin permisos para leer {path}"
        return result

    result["total_lines"] = len(lines)

    for line in lines:
        parsed = parse_apache_log(line)
        if parsed:
            result["parsed"] += 1
            ip   = parsed["ip"]
            req  = parsed["request"].lower()
            stat = parsed["status"]

            ip_counter[ip] += 1
            path_counter[parsed["request"].split()[1] if " " in parsed["request"] else parsed["request"]] += 1

            sc = str(stat)[0]
            result["status_dist"][sc] = result["status_dist"].get(sc, 0) + 1

            if stat >= 500:
                result["error_5xx"].append({"ip":ip,"request":parsed["request"],"status":stat})

            if stat == 401 or stat == 403:
                ip_errors[ip] += 1

            # Check threats
            for threat_type, level, pattern in WEB_THREATS:
                if re.search(pattern, req + " " + parsed.get("ua",""), re.IGNORECASE):
                    result["threats"].append({
                        "type": threat_type, "level": level,
                        "ip": ip, "request": parsed["request"][:120],
                        "status": stat,
                    })
                    break

    # Brute force: >50 401/403 de misma IP
    for ip, count in ip_errors.items():
        if count >= 20:
            result["brute_force"].append({"ip":ip,"count":count,"level":"ALTO" if count<100 else "CRÍTICO"})

    result["top_ips"]   = ip_counter.most_common(10)
    result["top_paths"] = path_counter.most_common(10)
    result["error_5xx"] = result["error_5xx"][:20]
    return result

def analyze_auth_log(path: str) -> dict:
    result = {"type":"auth","path":path,"threats":[],"failed_ips":Counter(),"stats":{}}
    try:
        with open(path,"r",errors="ignore") as f:
            lines = f.readlines()[-20000:]
    except PermissionError:
        result["error"] = f"Sin permisos (requiere root)"
        return result

    for line in lines:
        for ttype, pattern in AUTH_THREATS:
            if re.search(pattern, line, re.IGNORECASE):
                ip_m = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
                ip   = ip_m.group(1) if ip_m else "?"
                if ttype == "FAILED_LOGIN":
                    result["failed_ips"][ip] += 1
                else:
                    result["threats"].append({"type":ttype,"line":line.strip()[:150],"ip":ip})
                break

    # Brute force IPs
    for ip, count in result["failed_ips"].most_common(20):
        if count >= 5:
            result["threats"].append({
                "type":  "BRUTE_FORCE",
                "level": "CRÍTICO" if count > 100 else "ALTO",
                "ip":    ip,
                "count": count,
            })

    result["failed_ips"] = dict(result["failed_ips"].most_common(10))
    return result

def print_web_result(r: dict):
    print(f"\n  {Fore.CYAN}Archivo : {r['path']}")
    print(f"  Líneas  : {r['total_lines']:,}  Parseadas: {r['parsed']:,}")
    print(f"  Status  : {r['status_dist']}")

    threats = r.get("threats",[])
    if threats:
        print(f"\n  {Fore.RED}Amenazas ({len(threats)}):{Style.RESET_ALL}")
        by_type = Counter(t["type"] for t in threats)
        for ttype, count in by_type.most_common():
            level = next((t["level"] for t in threats if t["type"]==ttype), "?")
            c = Fore.RED if level == "CRÍTICO" else Fore.YELLOW
            print(f"    {c}[{level}]{Style.RESET_ALL} {ttype}: {count} eventos")

    bf = r.get("brute_force",[])
    if bf:
        print(f"\n  {Fore.RED}Brute Force IPs:{Style.RESET_ALL}")
        for b in bf:
            print(f"    {Fore.RED}{b['ip']}: {b['count']} errores 401/403{Style.RESET_ALL}")

    if r.get("top_ips"):
        print(f"\n  {Fore.CYAN}Top IPs:{Style.RESET_ALL}")
        for ip, cnt in r["top_ips"][:5]:
            print(f"    {ip:<20} {cnt} requests")

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Log Analyzer")
    parser.add_argument("-f","--file",   required=True, help="Archivo de log")
    parser.add_argument("--type",        choices=["web","auth","auto"], default="auto")
    parser.add_argument("-o","--output", default=None)
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"{Fore.RED}[✗] Archivo no encontrado: {args.file}"); sys.exit(1)

    print(f"\n{Fore.CYAN}[*] Analizando: {args.file}\n")

    # Auto-detect tipo
    log_type = args.type
    if log_type == "auto":
        fname = os.path.basename(args.file).lower()
        log_type = "auth" if any(x in fname for x in ["auth","secure","syslog"]) else "web"

    if log_type == "web":
        r = analyze_web_log(args.file)
        print_web_result(r)
    else:
        r = analyze_auth_log(args.file)
        print(f"\n  {Fore.RED}Amenazas: {len(r.get('threats',[]))}{Style.RESET_ALL}")
        for t in r.get("threats",[])[:20]:
            c = Fore.RED if t.get("level") in ("CRÍTICO","ALTO") else Fore.YELLOW
            print(f"  {c}[{t['type']}]{Style.RESET_ALL} IP:{t['ip']} {t.get('line',t.get('count',''))}")

    if args.output:
        with open(args.output,"w") as f:
            json.dump(r, f, indent=2, default=str)
        print(f"\n{Fore.CYAN}[*] Reporte: {args.output}")

if __name__ == "__main__":
    main()
