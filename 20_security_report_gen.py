#!/usr/bin/env python3
"""20 · SECURITY REPORT GENERATOR — Aggregate findings into professional report"""

import json, argparse, os, sys
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)

BANNER = f"{Fore.CYAN}╔══════════════════════════════════════╗\n║  📄 SECURITY REPORT GENERATOR  v1.0 ║\n║  Aggregate findings → HTML report   ║\n╚══════════════════════════════════════╝{Style.RESET_ALL}"

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Report — {target}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #c9d1d9; }}
  .header {{ background: linear-gradient(135deg, #1a1f2e, #0d1117); border-bottom: 2px solid #21262d;
             padding: 40px; }}
  .header h1 {{ font-size: 2rem; color: #58a6ff; font-weight: 700; }}
  .header .meta {{ color: #8b949e; margin-top: 8px; font-size: 0.9rem; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 32px 20px; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px,1fr));
                   gap: 16px; margin: 24px 0; }}
  .summary-card {{ background: #161b22; border: 1px solid #21262d; border-radius: 8px;
                   padding: 20px; text-align: center; }}
  .summary-card .count {{ font-size: 2.5rem; font-weight: 700; }}
  .summary-card .label {{ font-size: 0.8rem; color: #8b949e; margin-top: 4px; text-transform: uppercase; }}
  .critical .count {{ color: #f85149; }} .high .count {{ color: #d29922; }}
  .medium .count {{ color: #f0883e; }} .low .count {{ color: #3fb950; }}
  .info .count {{ color: #58a6ff; }}
  .section {{ margin: 32px 0; }}
  .section h2 {{ font-size: 1.2rem; color: #58a6ff; border-bottom: 1px solid #21262d;
                 padding-bottom: 8px; margin-bottom: 16px; }}
  .finding {{ background: #161b22; border: 1px solid #21262d; border-radius: 8px;
              padding: 16px; margin: 12px 0; border-left: 4px solid; }}
  .finding.CRÍTICO {{ border-left-color: #f85149; }}
  .finding.ALTO {{ border-left-color: #d29922; }}
  .finding.MEDIO {{ border-left-color: #f0883e; }}
  .finding.BAJO {{ border-left-color: #3fb950; }}
  .finding.INFO {{ border-left-color: #58a6ff; }}
  .finding-header {{ display: flex; justify-content: space-between; align-items: flex-start; }}
  .finding-title {{ font-weight: 600; font-size: 1rem; color: #e6edf3; }}
  .badge {{ padding: 2px 10px; border-radius: 12px; font-size: 0.75rem; font-weight: 600;
             text-transform: uppercase; }}
  .badge.CRÍTICO {{ background: #3d1a1a; color: #f85149; }}
  .badge.ALTO {{ background: #2d2008; color: #d29922; }}
  .badge.MEDIO {{ background: #2d1800; color: #f0883e; }}
  .badge.BAJO {{ background: #0d2a0d; color: #3fb950; }}
  .badge.INFO {{ background: #0d1b2d; color: #58a6ff; }}
  .finding-detail {{ margin-top: 8px; font-size: 0.85rem; color: #8b949e; }}
  .finding-code {{ background: #0d1117; border: 1px solid #21262d; border-radius: 4px;
                   padding: 8px 12px; margin-top: 8px; font-family: monospace;
                   font-size: 0.8rem; color: #79c0ff; overflow-x: auto; word-break: break-all; }}
  .tool-section {{ background: #161b22; border: 1px solid #21262d; border-radius: 8px;
                   padding: 20px; margin: 12px 0; }}
  .tool-header {{ display: flex; justify-content: space-between; font-weight: 600;
                  color: #e6edf3; margin-bottom: 12px; }}
  .grade {{ font-size: 1.8rem; font-weight: 700; }}
  .grade-A {{ color: #3fb950; }} .grade-B {{ color: #58a6ff; }}
  .grade-C {{ color: #f0883e; }} .grade-D,.grade-F {{ color: #f85149; }}
  .footer {{ text-align: center; padding: 32px; color: #8b949e; font-size: 0.8rem;
             border-top: 1px solid #21262d; margin-top: 40px; }}
  .progress-bar {{ background: #21262d; border-radius: 4px; height: 8px; margin: 8px 0; }}
  .progress-fill {{ height: 100%; border-radius: 4px; background: #58a6ff; }}
  table {{ width: 100%; border-collapse: collapse; margin: 12px 0; }}
  th {{ background: #21262d; color: #8b949e; padding: 8px 12px; text-align: left; font-size: 0.8rem; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #21262d; font-size: 0.85rem; }}
  tr:hover td {{ background: #161b22; }}
</style>
</head>
<body>
<div class="header">
  <div style="max-width:1100px;margin:0 auto">
    <h1>🔐 Security Assessment Report</h1>
    <div class="meta">
      Target: <strong>{target}</strong> &nbsp;|&nbsp;
      Date: <strong>{date}</strong> &nbsp;|&nbsp;
      Auditor: <strong>{auditor}</strong> &nbsp;|&nbsp;
      Tools: <strong>{tool_count}</strong>
    </div>
  </div>
</div>

<div class="container">
  <div class="summary-grid">
    <div class="summary-card critical"><div class="count">{critical}</div><div class="label">Critical</div></div>
    <div class="summary-card high"><div class="count">{high}</div><div class="label">High</div></div>
    <div class="summary-card medium"><div class="count">{medium}</div><div class="label">Medium</div></div>
    <div class="summary-card low"><div class="count">{low}</div><div class="label">Low</div></div>
    <div class="summary-card info"><div class="count">{total}</div><div class="label">Total</div></div>
  </div>

  {sections}

  <div class="footer">
    Generated by CyberToolkit v2.0 | kaleth4 | {date}<br>
    This report is confidential. Handle according to your organization's data classification policy.
  </div>
</div>
</body>
</html>"""

FINDING_TEMPLATE = """
<div class="finding {level}">
  <div class="finding-header">
    <div class="finding-title">{title}</div>
    <span class="badge {level}">{level}</span>
  </div>
  <div class="finding-detail">{detail}</div>
  {code_block}
</div>"""

def load_json_results(path: str) -> dict:
    try:
        with open(path) as f:
            return json.load(f)
    except Exception as e:
        return {"error": str(e)}

def extract_findings(data, source_name: str) -> list:
    findings = []
    def process(obj, depth=0):
        if depth > 5: return
        if isinstance(obj, list):
            for item in obj: process(item, depth+1)
        elif isinstance(obj, dict):
            level = obj.get("level","") or obj.get("severity","") or obj.get("risk","")
            level = str(level).upper()
            if level in ("CRÍTICO","ALTO","MEDIO","BAJO","CRITICAL","HIGH","MEDIUM","LOW","INFO"):
                level_map = {"CRITICAL":"CRÍTICO","HIGH":"ALTO","MEDIUM":"MEDIO","LOW":"BAJO"}
                level = level_map.get(level, level)
                msg   = (obj.get("message") or obj.get("msg") or obj.get("desc") or
                         obj.get("description") or obj.get("type") or "Finding")
                detail= (obj.get("detail") or obj.get("url") or obj.get("payload") or
                         obj.get("match") or obj.get("note") or "")
                findings.append({
                    "level":  level,
                    "title":  f"[{source_name}] {str(msg)[:100]}",
                    "detail": str(detail)[:200],
                    "source": source_name,
                })
            for v in obj.values(): process(v, depth+1)
    process(data)
    return findings

def generate_html(target: str, auditor: str, all_findings: list,
                  tool_summaries: list) -> str:
    by_level = {"CRÍTICO":[],"ALTO":[],"MEDIO":[],"BAJO":[],"INFO":[]}
    for f in all_findings:
        lvl = f.get("level","INFO")
        by_level.setdefault(lvl, []).append(f)

    sections_html = ""

    # Executive summary table
    sections_html += """
<div class="section">
  <h2>📊 Executive Summary</h2>
  <table>
    <tr><th>Severity</th><th>Count</th><th>Risk Level</th></tr>"""
    for lvl, color, risk in [
        ("CRÍTICO","#f85149","Critical — Immediate action required"),
        ("ALTO",   "#d29922","High — Fix within 7 days"),
        ("MEDIO",  "#f0883e","Medium — Fix within 30 days"),
        ("BAJO",   "#3fb950","Low — Fix in next release"),
    ]:
        count = len(by_level.get(lvl,[]))
        sections_html += f"""
    <tr>
      <td><span style="color:{color};font-weight:600">{lvl}</span></td>
      <td><strong>{count}</strong></td>
      <td style="color:#8b949e">{risk}</td>
    </tr>"""
    sections_html += "</table></div>"

    # Findings by severity
    for lvl in ("CRÍTICO","ALTO","MEDIO","BAJO"):
        findings = by_level.get(lvl,[])
        if not findings: continue
        sections_html += f"""
<div class="section">
  <h2>{'🔴' if lvl=='CRÍTICO' else '🟡' if lvl=='ALTO' else '🟠' if lvl=='MEDIO' else '🟢'} {lvl} ({len(findings)})</h2>"""
        for f in findings[:50]:  # cap at 50 per level
            code_block = f'<div class="finding-code">{f["detail"]}</div>' if f.get("detail") else ""
            sections_html += FINDING_TEMPLATE.format(
                level=lvl, title=f["title"],
                detail=f.get("source",""), code_block=code_block
            )
        sections_html += "</div>"

    # Tool summaries
    if tool_summaries:
        sections_html += '<div class="section"><h2>🛠️ Tool Results</h2>'
        for ts in tool_summaries:
            grade = ts.get("grade","?")
            grade_class = f"grade-{grade}" if grade in "ABCDF" else ""
            sections_html += f"""
<div class="tool-section">
  <div class="tool-header">
    <span>{ts['name']}</span>
    <span class="grade {grade_class}">{grade}</span>
  </div>
  <div style="color:#8b949e;font-size:0.85rem">{ts.get('summary','')}</div>
</div>"""
        sections_html += "</div>"

    return HTML_TEMPLATE.format(
        target=target, date=datetime.now().strftime("%Y-%m-%d %H:%M"),
        auditor=auditor, tool_count=len(tool_summaries),
        critical=len(by_level.get("CRÍTICO",[])),
        high=len(by_level.get("ALTO",[])),
        medium=len(by_level.get("MEDIO",[])),
        low=len(by_level.get("BAJO",[])),
        total=len(all_findings),
        sections=sections_html,
    )

def generate_markdown(target: str, auditor: str, all_findings: list) -> str:
    by_level = {}
    for f in all_findings:
        by_level.setdefault(f.get("level","INFO"),[]).append(f)

    md = f"""# Security Assessment Report

**Target:** {target}  
**Date:** {datetime.now().strftime("%Y-%m-%d %H:%M")}  
**Auditor:** {auditor}  

---

## Executive Summary

| Severity | Count |
|----------|-------|
| CRÍTICO  | {len(by_level.get('CRÍTICO',[]))} |
| ALTO     | {len(by_level.get('ALTO',[]))} |
| MEDIO    | {len(by_level.get('MEDIO',[]))} |
| BAJO     | {len(by_level.get('BAJO',[]))} |
| **TOTAL**| **{len(all_findings)}** |

---

"""
    for lvl in ("CRÍTICO","ALTO","MEDIO","BAJO"):
        findings = by_level.get(lvl,[])
        if not findings: continue
        md += f"## {lvl} ({len(findings)})\n\n"
        for f in findings[:30]:
            md += f"### {f['title']}\n"
            md += f"- **Level:** {lvl}\n"
            md += f"- **Source:** {f.get('source','?')}\n"
            if f.get("detail"):
                md += f"- **Detail:** `{f['detail'][:150]}`\n"
            md += "\n"

    md += f"\n---\n*Generated by CyberToolkit v2.0 | kaleth4*\n"
    return md

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Security Report Generator")
    parser.add_argument("-t","--target",   default="Target System")
    parser.add_argument("-a","--auditor",  default="Kaled Corcho | kaleth4")
    parser.add_argument("-i","--inputs",   nargs="+", default=[], help="JSON result files")
    parser.add_argument("-d","--dir",      default=None, help="Dir with JSON files")
    parser.add_argument("-o","--output",   default="security_report.html")
    parser.add_argument("--format",        choices=["html","md","both"], default="html")
    parser.add_argument("--demo",          action="store_true")
    args = parser.parse_args()

    input_files = list(args.inputs)
    if args.dir and os.path.isdir(args.dir):
        for fname in os.listdir(args.dir):
            if fname.endswith(".json"):
                input_files.append(os.path.join(args.dir, fname))

    all_findings   = []
    tool_summaries = []

    if args.demo:
        all_findings = [
            {"level":"CRÍTICO","title":"[vuln_scanner] Redis sin auth — puerto 6379 abierto",
             "detail":"IP: 192.168.1.50 — Redis expuesto sin contraseña","source":"Vuln Scanner"},
            {"level":"CRÍTICO","title":"[sqli_tester] SQL Injection en param 'id'",
             "detail":"Error MySQL detectado con payload: '","source":"SQLi Tester"},
            {"level":"CRÍTICO","title":"[dir_bruteforcer] .env expuesto",
             "detail":"https://target.com/.env — DB_PASSWORD visible","source":"Dir Bruteforcer"},
            {"level":"ALTO","title":"[tls_checker] Certificado expira en 5 días",
             "detail":"cert CN: *.target.com expires 2024-01-10","source":"TLS Checker"},
            {"level":"ALTO","title":"[cors_tester] Origen malicioso reflejado",
             "detail":"ACAO: https://evil.com  ACAC: true","source":"CORS Tester"},
            {"level":"ALTO","title":"[http_header] Content-Security-Policy faltante",
             "detail":"Protege contra XSS — usar default-src 'self'","source":"Header Auditor"},
            {"level":"ALTO","title":"[log_analyzer] Brute force desde 45.33.32.156",
             "detail":"847 intentos fallidos SSH en 10 minutos","source":"Log Analyzer"},
            {"level":"MEDIO","title":"[header_auditor] X-Frame-Options faltante",
             "detail":"Permite clickjacking — usar X-Frame-Options: DENY","source":"Header Auditor"},
            {"level":"MEDIO","title":"[wifi_analyzer] Red WEP detectada",
             "detail":"SSID: OldRouter — WEP roto en minutos","source":"WiFi Analyzer"},
            {"level":"BAJO","title":"[phishing_analyzer] URL con TLD sospechoso",
             "detail":"http://paypa1-login.tk — keyword suplantación","source":"Phishing Analyzer"},
        ]
        tool_summaries = [
            {"name":"Vuln Scanner","grade":"F","summary":"3 puertos críticos: Redis(6379), Telnet(23), MongoDB(27017)"},
            {"name":"TLS Checker","grade":"B","summary":"TLSv1.3, cipher AES-256-GCM — cert expira en 5 días"},
            {"name":"Header Auditor","grade":"C","summary":"CSP y X-Frame-Options faltantes"},
            {"name":"Dir Bruteforcer","grade":"D","summary":".env y .git expuestos"},
            {"name":"CORS Tester","grade":"F","summary":"Origen evil.com reflejado con credentials=true"},
        ]
        print(f"{Fore.YELLOW}[!] Modo DEMO — usando datos sintéticos\n")

    # Load real JSON files
    for fpath in input_files:
        if not os.path.isfile(fpath): continue
        name = os.path.splitext(os.path.basename(fpath))[0]
        data = load_json_results(fpath)
        found = extract_findings(data, name)
        all_findings.extend(found)
        if isinstance(data, dict):
            grade   = data.get("grade","?")
            summary = f"{len(found)} hallazgos extraídos"
            tool_summaries.append({"name":name,"grade":grade,"summary":summary})
        print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} {name}: {len(found)} hallazgos")

    by_level = {}
    for f in all_findings:
        by_level.setdefault(f.get("level","INFO"),[]).append(f)

    print(f"\n{Fore.CYAN}[*] Target   : {args.target}")
    print(f"{Fore.CYAN}[*] Findings : {len(all_findings)}")
    print(f"{Fore.RED}    CRÍTICO  : {len(by_level.get('CRÍTICO',[]))}")
    print(f"{Fore.YELLOW}    ALTO     : {len(by_level.get('ALTO',[]))}")
    print(f"{Fore.WHITE}{'─'*44}\n")

    if args.format in ("html","both"):
        html = generate_html(args.target, args.auditor, all_findings, tool_summaries)
        out  = args.output if args.output.endswith(".html") else args.output+".html"
        with open(out,"w",encoding="utf-8") as f: f.write(html)
        print(f"{Fore.GREEN}[✓] HTML Report: {out}")

    if args.format in ("md","both"):
        md  = generate_markdown(args.target, args.auditor, all_findings)
        out = args.output.replace(".html","") + ".md"
        with open(out,"w",encoding="utf-8") as f: f.write(md)
        print(f"{Fore.GREEN}[✓] Markdown Report: {out}")

if __name__ == "__main__":
    main()
