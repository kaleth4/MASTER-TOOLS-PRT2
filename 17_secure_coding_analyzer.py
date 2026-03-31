#!/usr/bin/env python3
"""17 · SECURE CODING ANALYZER — Static analysis for Python security issues"""

import ast, os, re, argparse, json, sys
from colorama import Fore, Style, init
init(autoreset=True)

BANNER = f"{Fore.CYAN}╔══════════════════════════════════════╗\n║  🛡️  SECURE CODING ANALYZER  v1.0   ║\n║  Python static security analysis     ║\n╚══════════════════════════════════════╝{Style.RESET_ALL}"

DANGEROUS_CALLS = {
    "eval":         ("CRÍTICO", "eval() puede ejecutar código arbitrario"),
    "exec":         ("CRÍTICO", "exec() puede ejecutar código arbitrario"),
    "compile":      ("ALTO",    "compile() + exec es equivalente a eval()"),
    "os.system":    ("ALTO",    "os.system() — usa subprocess con lista de args"),
    "os.popen":     ("ALTO",    "os.popen() — vulnerable a command injection"),
    "subprocess.call":("MEDIO", "Verifica que no use shell=True"),
    "subprocess.run": ("MEDIO", "Verifica que no use shell=True"),
    "pickle.loads":  ("CRÍTICO","pickle.loads — deserialización insegura"),
    "pickle.load":   ("CRÍTICO","pickle.load — deserialización insegura"),
    "marshal.loads": ("CRÍTICO","marshal.loads — deserialización insegura"),
    "yaml.load":     ("ALTO",   "yaml.load sin Loader — usa yaml.safe_load"),
    "hashlib.md5":   ("MEDIO",  "MD5 criptográficamente roto — usa SHA-256+"),
    "hashlib.sha1":  ("MEDIO",  "SHA-1 débil — usa SHA-256+"),
    "random.random": ("BAJO",   "random no es criptográficamente seguro — usa secrets"),
    "random.choice": ("BAJO",   "random.choice no es seguro para tokens/passwords"),
    "tempfile.mktemp":("MEDIO","mktemp tiene race condition — usa mkstemp"),
    "input":         ("BAJO",   "En Python 2, input() evalúa código (Python 3 OK)"),
}

SECRET_PATTERNS = [
    (r"(?i)(password|passwd|pwd|secret|api_key|apikey|auth_token|access_token|private_key)\s*=\s*['\"](.{4,})['\"]",
     "CRÍTICO", "Posible secreto/credencial hardcodeada"),
    (r"(?i)(aws_access_key_id|aws_secret|AKIA[0-9A-Z]{16})",
     "CRÍTICO", "AWS Key hardcodeada"),
    (r"ghp_[a-zA-Z0-9]{36}",
     "CRÍTICO", "GitHub Personal Access Token"),
    (r"(?i)(Bearer\s+[a-zA-Z0-9\-._~+/]{20,})",
     "ALTO",    "Bearer token en código"),
    (r"(?i)DEBUG\s*=\s*True",
     "MEDIO",   "DEBUG=True — no usar en producción"),
    (r"(?i)ALLOWED_HOSTS\s*=\s*\[.*['\"]?\*['\"]?",
     "ALTO",    "ALLOWED_HOSTS con wildcard (*) en Django"),
    (r"verify\s*=\s*False",
     "MEDIO",   "SSL verification deshabilitada"),
    (r"SSL_VERIFY\s*=\s*False",
     "MEDIO",   "SSL verification deshabilitada"),
]

SQL_PATTERNS = [
    (r'(?i)(execute|query)\s*\(\s*f["\']|\.format\(|%\s*\(',
     "CRÍTICO", "Posible SQL injection — usa queries parametrizadas"),
    (r'(?i)SELECT\s+.*\+\s*\w+|SELECT.*%s.*%\s',
     "ALTO",    "Concatenación en query SQL"),
]

class SecurityVisitor(ast.NodeVisitor):
    def __init__(self):
        self.findings = []

    def visit_Call(self, node):
        func_name = ""
        try:
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                parts = []
                current = node.func
                while isinstance(current, ast.Attribute):
                    parts.insert(0, current.attr)
                    current = current.value
                if isinstance(current, ast.Name):
                    parts.insert(0, current.id)
                func_name = ".".join(parts)
        except: pass

        if func_name in DANGEROUS_CALLS:
            level, msg = DANGEROUS_CALLS[func_name]
            self.findings.append({"type":"DANGEROUS_CALL","level":level,
                                   "msg":msg,"func":func_name,
                                   "line":node.lineno})
            # Check shell=True for subprocess
            if "subprocess" in func_name:
                for kw in node.keywords:
                    if getattr(kw.arg,"","")==""  : pass
                    if kw.arg == "shell":
                        if isinstance(kw.value, ast.Constant) and kw.value.value:
                            self.findings.append({
                                "type":"DANGEROUS_CALL","level":"CRÍTICO",
                                "msg":"shell=True en subprocess — command injection risk",
                                "func":func_name,"line":node.lineno,
                            })
        self.generic_visit(node)

    def visit_Assert(self, node):
        self.findings.append({"type":"ASSERT","level":"BAJO",
                               "msg":"assert puede deshabilitarse con -O — no usar para seguridad",
                               "line":node.lineno})
        self.generic_visit(node)

def analyze_file(path: str) -> dict:
    result = {"file":path,"findings":[],"score":0}
    try:
        with open(path,"r",encoding="utf-8",errors="ignore") as f:
            source = f.read()
    except Exception as e:
        result["error"] = str(e); return result

    # AST analysis
    try:
        tree    = ast.parse(source)
        visitor = SecurityVisitor()
        visitor.visit(tree)
        result["findings"].extend(visitor.findings)
    except SyntaxError as e:
        result["findings"].append({"type":"SYNTAX_ERROR","level":"INFO",
                                    "msg":str(e),"line":getattr(e,"lineno",0)})

    # Regex patterns
    for i, line in enumerate(source.splitlines(), 1):
        for pattern, level, msg in SECRET_PATTERNS:
            if re.search(pattern, line):
                m = re.search(pattern, line)
                value = m.group(0)[:60] if m else ""
                result["findings"].append({"type":"SECRET","level":level,
                                            "msg":msg,"line":i,"match":value})
        for pattern, level, msg in SQL_PATTERNS:
            if re.search(pattern, line):
                result["findings"].append({"type":"SQL_INJECTION","level":level,
                                            "msg":msg,"line":i})

    counts = {"CRÍTICO":5,"ALTO":3,"MEDIO":1,"BAJO":0}
    result["score"] = sum(counts.get(f.get("level","BAJO"),0) for f in result["findings"])
    return result

def print_result(r: dict):
    print(f"\n  {Fore.CYAN}{r['file']}{Style.RESET_ALL}  Score: {r['score']}")
    by_level = {}
    for f in r["findings"]:
        l = f.get("level","?")
        by_level.setdefault(l,[]).append(f)

    for level in ("CRÍTICO","ALTO","MEDIO","BAJO","INFO"):
        for f in by_level.get(level,[]):
            c = Fore.RED if level in ("CRÍTICO","ALTO") else Fore.YELLOW if level=="MEDIO" else Fore.GRAY
            print(f"  {c}[{level}]{Style.RESET_ALL} Line {f.get('line','?'):4}  {f.get('msg','')}")
            if f.get("match"):
                print(f"             {Fore.GRAY}{f['match'][:60]}{Style.RESET_ALL}")
            if f.get("func"):
                print(f"             {Fore.GRAY}Función: {f['func']}{Style.RESET_ALL}")

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Secure Coding Analyzer")
    parser.add_argument("-f","--file",  help="Archivo Python")
    parser.add_argument("-d","--dir",   help="Directorio a escanear")
    parser.add_argument("-o","--output",default=None)
    args = parser.parse_args()

    files = []
    if args.dir:
        for root,dirs,filenames in os.walk(args.dir):
            dirs[:] = [d for d in dirs if d not in (".git","node_modules","__pycache__",".venv")]
            for fname in filenames:
                if fname.endswith(".py"):
                    files.append(os.path.join(root,fname))
    elif args.file:
        files = [args.file]
    else:
        files = [input(f"{Fore.CYAN}Archivo Python: {Style.RESET_ALL}").strip()]

    all_results = []
    total_findings = 0
    for fpath in files:
        r = analyze_file(fpath)
        if r["findings"]:
            print_result(r)
            total_findings += len(r["findings"])
        all_results.append(r)

    print(f"\n{Fore.GRAY}{'─'*44}")
    print(f"{Fore.CYAN}[*] Archivos analizados : {len(files)}")
    print(f"{Fore.RED}[!] Total findings      : {total_findings}")

    if args.output:
        with open(args.output,"w") as f: json.dump(all_results, f, indent=2, default=str)
        print(f"{Fore.CYAN}[*] Guardado: {args.output}")

if __name__ == "__main__":
    main()
