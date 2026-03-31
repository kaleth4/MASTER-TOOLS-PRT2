#!/usr/bin/env python3
"""19 · CRYPTO ANALYZER — Analyze cryptographic implementations"""

import hashlib, base64, re, argparse, json, math
from colorama import Fore, Style, init
init(autoreset=True)

BANNER = f"{Fore.MAGENTA}╔══════════════════════════════════════╗\n║  🔐 CRYPTO ANALYZER  v1.0            ║\n║  Identify & assess crypto usage      ║\n╚══════════════════════════════════════╝{Style.RESET_ALL}"

WEAK_ALGOS = {
    "md5":      ("CRÍTICO", "Roto desde 2004 — colisiones en segundos"),
    "sha1":     ("ALTO",    "Roto en 2017 (SHAttered) — usar SHA-256+"),
    "des":      ("CRÍTICO", "Llave 56 bits — roto en horas"),
    "3des":     ("ALTO",    "Vulnerable a SWEET32 — deprecado"),
    "rc4":      ("CRÍTICO", "Biases estadísticos — prohibido en TLS"),
    "md4":      ("CRÍTICO", "Completamente roto"),
    "blowfish": ("MEDIO",   "Bloque 64 bits — vulnerable a SWEET32 en volumen alto"),
    "ecb":      ("CRÍTICO", "ECB mode revela patrones — nunca usar"),
    "cbc":      ("MEDIO",   "CBC con padding oracle — preferir GCM/CCM"),
}

STRONG_ALGOS = {
    "sha256", "sha384", "sha512", "sha3_256", "sha3_512",
    "blake2b", "blake2s", "aes_gcm", "chacha20", "argon2",
    "bcrypt", "scrypt", "pbkdf2",
}

def detect_encoding(data: str) -> list:
    detections = []
    # Base64
    b64_pattern = r'^[A-Za-z0-9+/]+={0,2}$'
    if re.match(b64_pattern, data.strip()) and len(data.strip()) % 4 == 0:
        try:
            decoded = base64.b64decode(data.strip())
            detections.append(("Base64", decoded[:50].hex()))
        except: pass
    # Hex
    if re.match(r'^[0-9a-fA-F]+$', data.strip()) and len(data.strip()) % 2 == 0:
        detections.append(("Hex", f"Longitud: {len(data.strip())//2} bytes"))
    # URL encoded
    if '%' in data:
        try:
            import urllib.parse
            decoded = urllib.parse.unquote(data)
            if decoded != data:
                detections.append(("URL-encoded", decoded[:80]))
        except: pass
    return detections

def identify_hash(data: str) -> list:
    data = data.strip()
    candidates = []
    length = len(data)
    if re.match(r'^[0-9a-fA-F]+$', data, re.IGNORECASE):
        hash_map = {
            32:  [("MD5","CRÍTICO"),("NTLM","CRÍTICO")],
            40:  [("SHA-1","ALTO")],
            56:  [("SHA-224","BAJO")],
            64:  [("SHA-256","SEGURO")],
            96:  [("SHA-384","SEGURO")],
            128: [("SHA-512","SEGURO")],
            8:   [("CRC32","INFO")],
        }
        candidates = hash_map.get(length, [])
    elif data.startswith("$2"):
        candidates = [("bcrypt","SEGURO")]
    elif data.startswith("$argon2"):
        candidates = [("Argon2","SEGURO")]
    elif data.startswith("$6$"):
        candidates = [("SHA-512-crypt","SEGURO")]
    elif data.startswith("$1$"):
        candidates = [("MD5-crypt","CRÍTICO")]
    elif data.startswith("$5$"):
        candidates = [("SHA-256-crypt","MEDIO")]
    return candidates

def entropy_analysis(data: str) -> dict:
    if not data: return {}
    freq  = {}
    for c in data: freq[c] = freq.get(c,0)+1
    total = len(data)
    ent   = -sum((f/total)*math.log2(f/total) for f in freq.values())
    return {
        "entropy": round(ent,3),
        "max_entropy": round(math.log2(len(freq)),3),
        "unique_chars": len(freq),
        "note": "Alta entropía → cifrado/compresión/aleatoriedad" if ent > 6 else
                "Entropía media → posible encoding" if ent > 4 else
                "Baja entropía → texto o patrón predecible",
    }

def analyze_code_crypto(code: str) -> list:
    findings = []
    patterns = [
        (r"(?i)\b(md5|md4)\b",        "MD5/MD4 en código", "CRÍTICO"),
        (r"(?i)\b(sha1|sha-1)\b",     "SHA-1 en código",   "ALTO"),
        (r"(?i)\bDES\b(?!c)",         "DES en código",     "CRÍTICO"),
        (r"(?i)\bRC4\b",              "RC4 en código",     "CRÍTICO"),
        (r"(?i)AES.*ECB|ECB.*AES",    "AES-ECB detectado", "CRÍTICO"),
        (r"(?i)mode=ECB|ECB_mode",    "ECB mode",          "CRÍTICO"),
        (r"random\.random\(\)|random\.randint", "random() para crypto","MEDIO"),
        (r"(?i)hardcoded.*key|key\s*=\s*['\"][0-9a-fA-F]{16,}", "Clave hardcodeada","CRÍTICO"),
    ]
    for pat, msg, level in patterns:
        for m in re.finditer(pat, code):
            findings.append({"level":level,"msg":msg,"match":m.group(0)[:40]})
    return findings

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Crypto Analyzer")
    sub = parser.add_subparsers(dest="cmd")

    det_p = sub.add_parser("detect", help="Detectar encoding/hash de un valor")
    det_p.add_argument("data")

    code_p = sub.add_parser("code", help="Analizar código por usos crypto")
    code_p.add_argument("-f","--file", required=True)

    ent_p = sub.add_parser("entropy", help="Calcular entropía")
    ent_p.add_argument("data")

    args = parser.parse_args()

    if args.cmd == "detect":
        print(f"\n{Fore.CYAN}[*] Analizando: {args.data[:60]}...\n")
        # Hash identification
        hashes = identify_hash(args.data)
        if hashes:
            print(f"  {Fore.CYAN}Posibles hashes:{Style.RESET_ALL}")
            for name, level in hashes:
                c = Fore.GREEN if level=="SEGURO" else Fore.RED if level=="CRÍTICO" else Fore.YELLOW
                print(f"    {c}[{level}]{Style.RESET_ALL} {name}")
        # Encoding detection
        encodings = detect_encoding(args.data)
        if encodings:
            print(f"\n  {Fore.CYAN}Encodings detectados:{Style.RESET_ALL}")
            for enc, val in encodings:
                print(f"    {Fore.YELLOW}{enc}{Style.RESET_ALL}: {val[:60]}")
        # Entropy
        ent = entropy_analysis(args.data)
        print(f"\n  {Fore.CYAN}Entropía: {ent.get('entropy')} bits")
        print(f"  {Fore.GRAY}{ent.get('note')}{Style.RESET_ALL}")

    elif args.cmd == "code":
        import os
        if not os.path.isfile(args.file):
            print(f"{Fore.RED}[✗] Archivo no encontrado"); return
        with open(args.file,"r",errors="ignore") as f:
            code = f.read()
        findings = analyze_code_crypto(code)
        print(f"\n{Fore.CYAN}[*] Analizando: {args.file}")
        if findings:
            print(f"  {Fore.RED}Problemas crypto ({len(findings)}):{Style.RESET_ALL}")
            for f in findings:
                c = Fore.RED if f["level"]=="CRÍTICO" else Fore.YELLOW
                print(f"    {c}[{f['level']}]{Style.RESET_ALL} {f['msg']}: {Fore.GRAY}{f['match']}{Style.RESET_ALL}")
        else:
            print(f"  {Fore.GREEN}✓ Sin problemas crypto detectados")

    elif args.cmd == "entropy":
        ent = entropy_analysis(args.data)
        for k,v in ent.items():
            print(f"  {Fore.YELLOW}{k:<15}{Style.RESET_ALL}: {v}")

    else:
        val = input(f"{Fore.CYAN}Valor a analizar: {Style.RESET_ALL}").strip()
        hashes = identify_hash(val)
        for name, level in hashes:
            print(f"  {name}: {level}")
        encodings = detect_encoding(val)
        for enc, decoded in encodings:
            print(f"  {enc}: {decoded[:60]}")

if __name__ == "__main__":
    main()
