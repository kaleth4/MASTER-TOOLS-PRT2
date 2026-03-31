#!/usr/bin/env python3
"""07 · DIRECTORY BRUTEFORCER — Web path discovery"""

import requests, argparse, json, sys, concurrent.futures, time
from colorama import Fore, Style, init
init(autoreset=True)
requests.packages.urllib3.disable_warnings()

BANNER = f"{Fore.RED}╔══════════════════════════════════════╗\n║  📂 DIR BRUTEFORCER  v1.0            ║\n║  Web path discovery & enumeration    ║\n╚══════════════════════════════════════╝{Style.RESET_ALL}"

DEFAULT_PATHS = [
    "admin","administrator","login","wp-admin","panel","dashboard","portal",
    "api","api/v1","api/v2","graphql","rest","swagger","swagger-ui.html",
    "backup","backups","db","database","dump","sql","old","archive",
    ".git",".git/config",".env",".env.bak","config.php","wp-config.php",
    "robots.txt","sitemap.xml","crossdomain.xml","security.txt",
    "phpinfo.php","info.php","test.php","server-status","server-info",
    "phpmyadmin","mysql","pma","adminer","adminer.php",
    "uploads","upload","files","media","static","assets","images",
    "logs","log","error_log","access_log","debug.log",
    "console","shell","cmd","exec","eval",
    "docs","documentation","swagger","redoc","api-docs",
    "health","healthz","metrics","status","ping","alive",
    "jenkins","gitlab","bitbucket","sonar","nexus","artifactory",
    "kibana","grafana","prometheus","zabbix","nagios",
    "secret","secrets","private","internal","intranet","vpn",
    "user","users","profile","account","accounts","register","signup",
    "reset","forgot","password","change-password",
]

INTERESTING_STATUS = [200, 201, 204, 301, 302, 307, 401, 403, 500]
POSITIVE_STATUS    = [200, 201, 204, 301, 302, 307]

found_paths = []

def probe_path(base_url: str, path: str, timeout: float,
               follow_redirects: bool) -> dict | None:
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    try:
        r = requests.get(url, timeout=timeout, verify=False,
                         allow_redirects=follow_redirects,
                         headers={"User-Agent":"Mozilla/5.0 DirBrute/1.0"})
        if r.status_code in INTERESTING_STATUS:
            import re
            title_m = re.search(r"<title>(.*?)</title>", r.text, re.IGNORECASE|re.DOTALL)
            title   = title_m.group(1).strip()[:50] if title_m else ""
            return {
                "path":        path,
                "url":         url,
                "status":      r.status_code,
                "size":        len(r.content),
                "title":       title,
                "interesting": r.status_code in POSITIVE_STATUS or r.status_code == 403,
            }
    except requests.exceptions.Timeout:
        pass
    except Exception:
        pass
    return None

def status_color(code: int) -> str:
    if code == 200: return Fore.GREEN
    if code in (201,204): return Fore.CYAN
    if code in (301,302,307): return Fore.YELLOW
    if code == 401: return Fore.MAGENTA
    if code == 403: return Fore.YELLOW
    if code == 500: return Fore.RED
    return Fore.WHITE

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Directory Bruteforcer")
    parser.add_argument("-u","--url",      required=True)
    parser.add_argument("-w","--wordlist",  default=None)
    parser.add_argument("-x","--ext",       default="",    help="Extensiones: php,html,txt")
    parser.add_argument("-t","--threads",   type=int, default=20)
    parser.add_argument("--timeout",        type=float, default=5.0)
    parser.add_argument("--no-follow",      action="store_true")
    parser.add_argument("-o","--output",    default=None)
    args = parser.parse_args()

    base_url = args.url if args.url.startswith("http") else "http://" + args.url

    wordlist = DEFAULT_PATHS[:]
    if args.wordlist:
        try:
            with open(args.wordlist) as f:
                wordlist = [l.strip() for l in f if l.strip()]
        except: print(f"{Fore.YELLOW}[!] Wordlist no encontrada, usando interna")

    # Expandir extensiones
    if args.ext:
        exts = args.ext.split(",")
        extended = wordlist[:]
        for path in wordlist:
            if "." not in path:
                for ext in exts:
                    extended.append(f"{path}.{ext.strip('.')}")
        wordlist = extended

    print(f"{Fore.CYAN}[*] URL     : {base_url}")
    print(f"{Fore.CYAN}[*] Paths   : {len(wordlist)}")
    print(f"{Fore.CYAN}[*] Threads : {args.threads}")
    print(f"{Fore.GRAY}{'─'*44}\n")

    start = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {
            ex.submit(probe_path, base_url, p, args.timeout, not args.no_follow): p
            for p in wordlist
        }
        done = 0
        for future in concurrent.futures.as_completed(futures):
            done += 1
            r = future.result()
            if r:
                found_paths.append(r)
                sc = status_color(r["status"])
                print(f"  {sc}[{r['status']}]{Style.RESET_ALL} "
                      f"{Fore.CYAN}/{r['path']:<35}{Style.RESET_ALL} "
                      f"{Fore.GRAY}{r['size']:6}B  {r['title'][:40]}{Style.RESET_ALL}")
            else:
                sys.stdout.write(f"\r  {Fore.GRAY}[{done}/{len(wordlist)}] Escaneando...{Style.RESET_ALL}   ")
                sys.stdout.flush()

    elapsed = time.time() - start
    print(f"\n\n{Fore.GRAY}{'─'*44}")
    print(f"{Fore.GREEN}[✓] Encontrados : {len(found_paths)}")
    print(f"{Fore.CYAN}[*] Tiempo      : {elapsed:.1f}s")

    critical = [r for r in found_paths if any(x in r["path"] for x in [".git",".env","backup","admin","config","log","sql"])]
    if critical:
        print(f"\n{Fore.RED}[!] Rutas de alto riesgo:{Style.RESET_ALL}")
        for r in critical:
            print(f"    {Fore.RED}{r['url']}{Style.RESET_ALL}")

    if args.output:
        with open(args.output,"w") as f: json.dump(found_paths, f, indent=2)
        print(f"{Fore.CYAN}[*] Guardado: {args.output}")

if __name__ == "__main__":
    main()
