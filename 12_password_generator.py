#!/usr/bin/env python3
"""12 · SECURE PASSWORD GENERATOR — Policy-based password generation"""

import secrets, string, argparse, json, math, re
from colorama import Fore, Style, init
init(autoreset=True)

BANNER = f"{Fore.GREEN}╔══════════════════════════════════════╗\n║  🔐 PASSWORD GENERATOR  v1.0         ║\n║  Policy-based + bulk generation      ║\n╚══════════════════════════════════════╝{Style.RESET_ALL}"

PROFILES = {
    "web":    {"length":16,"upper":True,"lower":True,"digits":True,"symbols":True,"symbols_set":"!@#$%"},
    "admin":  {"length":24,"upper":True,"lower":True,"digits":True,"symbols":True,"symbols_set":"!@#$%^&*-_=+"},
    "pin":    {"length":6, "upper":False,"lower":False,"digits":True,"symbols":False},
    "wifi":   {"length":20,"upper":True,"lower":True,"digits":True,"symbols":True,"symbols_set":"!@#$-_"},
    "api":    {"length":32,"upper":True,"lower":True,"digits":True,"symbols":False},
    "max":    {"length":64,"upper":True,"lower":True,"digits":True,"symbols":True,"symbols_set":string.punctuation},
}

WORDLIST_SAMPLE = [
    "ocean","mountain","thunder","crystal","forest","dragon","castle",
    "silver","golden","purple","shadow","falcon","tiger","river","cloud",
    "storm","blade","shield","frost","flame","swift","brave","quiet","solar",
    "lunar","comet","orbit","pixel","cyber","logic","byte","data","matrix",
]

def entropy(length: int, charset_size: int) -> float:
    return round(length * math.log2(max(charset_size,1)), 1)

def crack_time(ent: float) -> str:
    combos  = 2**ent
    per_sec = 1e12  # 1 trillion/s (GPU cluster)
    secs    = combos / per_sec
    if secs < 1:       return "< 1 segundo"
    if secs < 60:      return f"{secs:.0f}s"
    if secs < 3600:    return f"{secs/60:.0f} min"
    if secs < 86400:   return f"{secs/3600:.0f} horas"
    if secs < 2592000: return f"{secs/86400:.0f} días"
    if secs < 3.15e7:  return f"{secs/2592000:.0f} meses"
    return f"{secs/3.15e7:.2e} años"

def build_charset(upper,lower,digits,symbols,symbols_set,exclude_ambiguous,extra) -> str:
    chars = ""
    if lower:   chars += string.ascii_lowercase
    if upper:   chars += string.ascii_uppercase
    if digits:  chars += string.digits
    if symbols: chars += symbols_set if symbols_set else string.punctuation
    if extra:   chars += extra
    if exclude_ambiguous:
        for c in "0O1lI|`'\"`\\": chars = chars.replace(c,"")
    return chars

def generate_password(length:int, charset:str, required_sets:list) -> str:
    while True:
        pwd = "".join(secrets.choice(charset) for _ in range(length))
        ok  = all(any(c in pwd for c in rset) for rset in required_sets if rset)
        if ok: return pwd

def generate_passphrase(words:int, separator:str, capitalize:bool, add_number:bool) -> str:
    parts = [secrets.choice(WORDLIST_SAMPLE) for _ in range(words)]
    if capitalize: parts = [p.capitalize() for p in parts]
    phrase = separator.join(parts)
    if add_number: phrase += str(secrets.randbelow(9999)).zfill(4)
    return phrase

def generate_pin(length:int) -> str:
    return "".join(str(secrets.randbelow(10)) for _ in range(length))

def apply_profile(profile_name:str) -> dict:
    return PROFILES.get(profile_name, PROFILES["web"])

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Secure Password Generator")
    sub = parser.add_subparsers(dest="cmd")

    # Password
    pw_p = sub.add_parser("password", help="Generar contraseñas")
    pw_p.add_argument("-l","--length",    type=int, default=16)
    pw_p.add_argument("-n","--count",     type=int, default=5)
    pw_p.add_argument("--no-upper",       action="store_true")
    pw_p.add_argument("--no-lower",       action="store_true")
    pw_p.add_argument("--no-digits",      action="store_true")
    pw_p.add_argument("--no-symbols",     action="store_true")
    pw_p.add_argument("--symbols-set",    default="!@#$%^&*-_=+?")
    pw_p.add_argument("--exclude-ambiguous", action="store_true")
    pw_p.add_argument("--extra",          default="")
    pw_p.add_argument("--profile",        choices=list(PROFILES.keys()), default=None)

    # Passphrase
    pp_p = sub.add_parser("passphrase", help="Generar passphrases")
    pp_p.add_argument("-w","--words",     type=int, default=4)
    pp_p.add_argument("-n","--count",     type=int, default=5)
    pp_p.add_argument("-s","--separator", default="-")
    pp_p.add_argument("--capitalize",     action="store_true", default=True)
    pp_p.add_argument("--add-number",     action="store_true", default=True)

    # PIN
    pin_p = sub.add_parser("pin", help="Generar PINs")
    pin_p.add_argument("-l","--length",   type=int, default=6)
    pin_p.add_argument("-n","--count",    type=int, default=5)

    # Bulk
    bulk_p = sub.add_parser("bulk", help="Generación masiva")
    bulk_p.add_argument("-n","--count",   type=int, required=True)
    bulk_p.add_argument("-l","--length",  type=int, default=16)
    bulk_p.add_argument("-o","--output",  required=True)
    bulk_p.add_argument("--profile",      choices=list(PROFILES.keys()), default="web")

    args = parser.parse_args()

    if args.cmd == "password" or args.cmd is None:
        if args.cmd is None:
            # interactive
            print("1) Contraseña  2) Passphrase  3) PIN")
            op = input(f"{Fore.CYAN}Opción: {Style.RESET_ALL}").strip()
            if op=="2":
                args.cmd="passphrase"; args.words=4; args.count=5; args.separator="-"; args.capitalize=True; args.add_number=True
            elif op=="3":
                args.cmd="pin"; args.length=6; args.count=5
            else:
                args.cmd="password"; args.length=16; args.count=5; args.no_upper=False; args.no_lower=False; args.no_digits=False; args.no_symbols=False; args.symbols_set="!@#$%"; args.exclude_ambiguous=False; args.extra=""; args.profile=None

        if args.cmd == "password":
            cfg = apply_profile(args.profile) if args.profile else {}
            length  = cfg.get("length", args.length)
            upper   = cfg.get("upper",  not args.no_upper)
            lower   = cfg.get("lower",  not args.no_lower)
            digits  = cfg.get("digits", not args.no_digits)
            symbols = cfg.get("symbols",not args.no_symbols)
            sym_set = cfg.get("symbols_set", args.symbols_set)

            charset = build_charset(upper,lower,digits,symbols,sym_set,
                                    args.exclude_ambiguous if hasattr(args,"exclude_ambiguous") else False,
                                    args.extra if hasattr(args,"extra") else "")
            if not charset:
                print(f"{Fore.RED}[✗] Charset vacío"); return

            req = []
            if upper:   req.append(string.ascii_uppercase)
            if lower:   req.append(string.ascii_lowercase)
            if digits:  req.append(string.digits)
            if symbols: req.append(sym_set)

            ent  = entropy(length, len(charset))
            ct   = crack_time(ent)
            print(f"\n{Fore.CYAN}[*] Charset: {len(charset)} chars  Entropía: {ent} bits  Crack: {ct}\n")

            for i in range(getattr(args,"count",5)):
                pwd = generate_password(length, charset, req)
                print(f"  {Fore.GREEN}[{i+1:02}]{Style.RESET_ALL} {Fore.YELLOW}{pwd}{Style.RESET_ALL}")

    if args.cmd == "passphrase":
        ent = entropy(args.words * 5, len(WORDLIST_SAMPLE))
        ct  = crack_time(ent)
        print(f"\n{Fore.CYAN}[*] {args.words} palabras  Entropía: ~{ent} bits  Crack: {ct}\n")
        for i in range(args.count):
            pp = generate_passphrase(args.words, args.separator, args.capitalize, args.add_number)
            print(f"  {Fore.GREEN}[{i+1:02}]{Style.RESET_ALL} {Fore.YELLOW}{pp}{Style.RESET_ALL}")

    elif args.cmd == "pin":
        print(f"\n{Fore.CYAN}[*] PIN {args.length} dígitos\n")
        for i in range(args.count):
            pin = generate_pin(args.length)
            print(f"  {Fore.GREEN}[{i+1:02}]{Style.RESET_ALL} {Fore.YELLOW}{pin}{Style.RESET_ALL}")

    elif args.cmd == "bulk":
        cfg = apply_profile(args.profile)
        charset = build_charset(cfg["upper"],cfg["lower"],cfg["digits"],
                                cfg["symbols"],cfg.get("symbols_set","!@#"),False,"")
        req = [string.ascii_uppercase, string.ascii_lowercase, string.digits]
        passwords = [generate_password(args.length, charset, req) for _ in range(args.count)]
        with open(args.output,"w") as f:
            f.write("\n".join(passwords))
        print(f"\n{Fore.GREEN}[✓] {args.count} contraseñas guardadas en {args.output}")

if __name__ == "__main__":
    main()
