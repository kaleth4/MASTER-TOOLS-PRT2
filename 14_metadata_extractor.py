#!/usr/bin/env python3
"""14 · METADATA EXTRACTOR — OSINT from file metadata"""

import os, sys, json, argparse, struct, re
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)

BANNER = f"{Fore.YELLOW}╔══════════════════════════════════════╗\n║  🔍 METADATA EXTRACTOR  v1.0         ║\n║  OSINT from images, PDFs & docs      ║\n╚══════════════════════════════════════╝{Style.RESET_ALL}"

def extract_image_metadata(path: str) -> dict:
    meta = {"type": "image", "file": path}
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS, GPSTAGS
        img  = Image.open(path)
        meta["format"] = img.format
        meta["size"]   = img.size
        meta["mode"]   = img.mode
        exif = img._getexif()
        if exif:
            exif_data = {}
            gps_data  = {}
            for tag_id, value in exif.items():
                tag = TAGS.get(tag_id, tag_id)
                if tag == "GPSInfo":
                    for gps_tag, gps_val in value.items():
                        gps_data[GPSTAGS.get(gps_tag, gps_tag)] = str(gps_val)
                elif isinstance(value, (str, int, float)):
                    exif_data[str(tag)] = str(value)[:200]
            meta["exif"] = exif_data
            if gps_data:
                meta["gps"] = gps_data
    except ImportError:
        meta["note"] = "pip install Pillow para metadatos EXIF completos"
    except Exception as e:
        meta["error"] = str(e)
    return meta

def extract_pdf_metadata(path: str) -> dict:
    meta = {"type": "pdf", "file": path}
    try:
        with open(path, "rb") as f:
            content = f.read()
        # Parse PDF info dict manually
        patterns = {
            "Author":   rb"/Author\s*\(([^)]+)\)",
            "Creator":  rb"/Creator\s*\(([^)]+)\)",
            "Producer": rb"/Producer\s*\(([^)]+)\)",
            "Title":    rb"/Title\s*\(([^)]+)\)",
            "Subject":  rb"/Subject\s*\(([^)]+)\)",
            "Keywords": rb"/Keywords\s*\(([^)]+)\)",
            "CreationDate": rb"/CreationDate\s*\(([^)]+)\)",
            "ModDate":      rb"/ModDate\s*\(([^)]+)\)",
        }
        info = {}
        for key, pattern in patterns.items():
            m = re.search(pattern, content)
            if m:
                info[key] = m.group(1).decode(errors="replace").strip()
        meta["info"] = info
        # Count pages
        pages = len(re.findall(rb"/Type\s*/Page[^s]", content))
        meta["pages"] = pages
        # PDF version
        ver = re.search(rb"%PDF-(\d+\.\d+)", content)
        meta["version"] = ver.group(1).decode() if ver else "?"
        # Detect JavaScript (suspicious)
        if b"/JavaScript" in content or b"/JS" in content:
            meta["warning"] = "ALTO: JavaScript embebido en PDF"
        # Detect embedded files
        if b"/EmbeddedFile" in content:
            meta["warning2"] = "MEDIO: Archivos embebidos detectados"
    except Exception as e:
        meta["error"] = str(e)
    return meta

def extract_office_metadata(path: str) -> dict:
    meta = {"type":"office","file":path}
    try:
        import zipfile, xml.etree.ElementTree as ET
        with zipfile.ZipFile(path) as z:
            files = z.namelist()
            meta["components"] = files[:20]
            # Core properties
            if "docProps/core.xml" in files:
                with z.open("docProps/core.xml") as f:
                    tree   = ET.parse(f)
                    root   = tree.getroot()
                    ns     = {"dc":   "http://purl.org/dc/elements/1.1/",
                              "cp":   "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
                              "dcterms":"http://purl.org/dc/terms/"}
                    props  = {}
                    for child in root.iter():
                        tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                        if child.text: props[tag] = child.text.strip()
                    meta["core_properties"] = props
            # App properties
            if "docProps/app.xml" in files:
                with z.open("docProps/app.xml") as f:
                    tree  = ET.parse(f)
                    root  = tree.getroot()
                    props = {}
                    for child in root.iter():
                        tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                        if child.text: props[tag] = child.text.strip()
                    meta["app_properties"] = props
    except Exception as e:
        meta["error"] = str(e)
    return meta

def extract_basic_metadata(path: str) -> dict:
    stat = os.stat(path)
    return {
        "file":     path,
        "size":     stat.st_size,
        "created":  datetime.fromtimestamp(stat.st_ctime).isoformat(),
        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
        "accessed": datetime.fromtimestamp(stat.st_atime).isoformat(),
        "extension":os.path.splitext(path)[1].lower(),
    }

def detect_type(path: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    if ext in (".jpg",".jpeg",".png",".tiff",".tif",".heic",".heif"): return "image"
    if ext == ".pdf": return "pdf"
    if ext in (".docx",".xlsx",".pptx",".odt",".ods",".odp"): return "office"
    return "generic"

def print_meta(meta: dict):
    for k,v in meta.items():
        if k in ("file","type","exif","gps","info","core_properties","app_properties","components"):
            continue
        print(f"  {Fore.YELLOW}{k:<20}{Style.RESET_ALL}: {str(v)[:80]}")

    if "exif" in meta:
        print(f"\n  {Fore.CYAN}EXIF Data:{Style.RESET_ALL}")
        for k,v in list(meta["exif"].items())[:20]:
            print(f"    {k:<25}: {str(v)[:60]}")

    if "gps" in meta:
        print(f"\n  {Fore.RED}GPS Data (PRIVACIDAD):{Style.RESET_ALL}")
        for k,v in meta["gps"].items():
            print(f"    {Fore.RED}{k:<25}: {v}{Style.RESET_ALL}")

    if "info" in meta:
        print(f"\n  {Fore.CYAN}PDF Info:{Style.RESET_ALL}")
        for k,v in meta["info"].items():
            print(f"    {k:<25}: {v}")

    for key in ("core_properties","app_properties"):
        if key in meta:
            print(f"\n  {Fore.CYAN}{key.replace('_',' ').title()}:{Style.RESET_ALL}")
            for k,v in meta[key].items():
                print(f"    {k:<25}: {v[:60]}")

    for w_key in ("warning","warning2"):
        if w_key in meta:
            print(f"\n  {Fore.RED}⚠ {meta[w_key]}{Style.RESET_ALL}")

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Metadata Extractor")
    parser.add_argument("-f","--file",   help="Archivo a analizar")
    parser.add_argument("-d","--dir",    help="Directorio (analizar todos)")
    parser.add_argument("-o","--output", default=None)
    args = parser.parse_args()

    files = []
    if args.dir:
        for root,dirs,filenames in os.walk(args.dir):
            for fname in filenames:
                files.append(os.path.join(root, fname))
    elif args.file:
        files = [args.file]
    else:
        files = [input(f"{Fore.CYAN}Archivo: {Style.RESET_ALL}").strip()]

    all_meta = []
    for fpath in files:
        if not os.path.isfile(fpath):
            print(f"{Fore.RED}[✗] No encontrado: {fpath}"); continue
        print(f"\n{Fore.CYAN}[*] {fpath}{Style.RESET_ALL}")
        basic = extract_basic_metadata(fpath)
        ftype = detect_type(fpath)
        if ftype == "image":   meta = {**basic, **extract_image_metadata(fpath)}
        elif ftype == "pdf":   meta = {**basic, **extract_pdf_metadata(fpath)}
        elif ftype == "office":meta = {**basic, **extract_office_metadata(fpath)}
        else:                  meta = basic
        print_meta(meta)
        all_meta.append(meta)

    if args.output:
        with open(args.output,"w") as f:
            json.dump(all_meta, f, indent=2, default=str)
        print(f"\n{Fore.CYAN}[*] Guardado: {args.output}")

if __name__ == "__main__":
    main()
