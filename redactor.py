import cv2
import pytesseract
import re
import argparse
from pathlib import Path

# --- PATTERN ---
# Common TLD whitelist to avoid false positives on bare domains
_TLD = r'(?:com|it|org|net|io|dev|gov|edu|co|uk|fr|de|es|eu|info|biz|app|cloud|tech|online|store|xyz|me|ai|local)'

PATTERNS = {
    # URL completi: http(s)://, ftp://, www. + path/query/fragment
    "url": rf'\b(?:https?|ftp)://[A-Za-z0-9._~\-]+(?:\.[A-Za-z]{{2,}})?(?::\d+)?(?:/[^\s<>"\'()]*)?|\bwww\.[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+(?:/[^\s<>"\'()]*)?',

    # Dominio nudo con TLD whitelisted (es: example.com, sub.foo.it/path)
    "domain": rf'\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{{0,61}}[A-Za-z0-9])?\.)+{_TLD}\b(?:/[^\s<>"\'()]*)?',

    # Email RFC-lite: TLD solo lettere, 2+ char
    "email": r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b',

    # IPv4 con range validi 0-255
    "ipv4": r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?::\d{1,5})?\b',

    # IPv6 (forma piena/compressa base)
    "ipv6": r'\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b',

    # MAC address
    "mac": r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b',

    # Host header / Host: campo con porta opzionale
    "host_line": r'(?i)\bhost\s*[:=]\s*([A-Za-z0-9\.\-]+(?::\d{1,5})?)',

    # Username con label IT/EN. \b non \n. Valore alfanumerico+._-
    "username": r'(?i)\b(?:nome\s*utente|username|user(?:name)?|utente|login|account)\s*[:=]\s*([A-Za-z][A-Za-z0-9_.\-]{2,30})\b',

    # Telefono internazionale/IT: prefisso +XX o 00XX, 8-13 cifre totali
    "phone": r'(?:(?<![\w\d])(?:\+|00)\d{1,3}[\s\.\-]?)?(?:\(\d{2,4}\)[\s\.\-]?)?\d{2,4}[\s\.\-]?\d{2,4}[\s\.\-]?\d{2,4}\b',
}

# AUTO_KEYWORDS ora regex con word boundary (no substring match)
AUTO_KEYWORDS = [
    r'\bhttps?\b', r'\bwww\b', r'\bftp\b',
    r'\.(?:com|it|org|net|io|dev|eu|co|uk)\b',
    r'@[A-Za-z0-9]', r'\bemail\b', r'\bmail\b', r'\be-?mail\b',
    r'\btel(?:efono)?\b', r'\bphone\b', r'\bmobile\b', r'\bcell(?:ulare)?\b',
    r'\bhost\b', r'\bhostname\b', r'\busername\b', r'\butente\b',
    r'\bnome\s*utente\b', r'\bpassword\b', r'\bpwd\b', r'\blogin\b',
]

def preprocess(img):
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    return cv2.threshold(gray, 150, 255, cv2.THRESH_BINARY)[1]

def build_checks(args):
    checks = []
    enabled = []

    if args.url:
        checks += [PATTERNS["url"], PATTERNS["domain"]]
        enabled.append("url")

    if args.email:
        checks.append(PATTERNS["email"])
        enabled.append("email")

    #if args.phone:
        #checks.append(PATTERNS["phone"])
        #enabled.append("phone")

    if args.host:
        checks.append(PATTERNS["host_line"])
        enabled.append("host")

    if args.username:
        checks.append(PATTERNS["username"])
        enabled.append("username")

    return checks, enabled

def auto_mode():
    # default intelligente: pattern precisi, no substring match
    checks = [
        PATTERNS["url"],
        PATTERNS["domain"],
        PATTERNS["email"],
        PATTERNS["ipv4"],
        PATTERNS["ipv6"],
        PATTERNS["mac"],
        PATTERNS["host_line"],
        PATTERNS["username"],
    ]
    return checks

def contains_custom(text, custom_list):
    return any(x.lower() in text.lower() for x in custom_list)

def contains_auto_keyword(text):
    return any(re.search(k, text, re.IGNORECASE) for k in AUTO_KEYWORDS)

def should_redact(text, checks, custom_hosts, custom_orgs, auto=False):
    if not text.strip():
        return False

    # pattern espliciti
    if any(re.search(p, text, re.IGNORECASE) for p in checks):
        return True

    # custom
    if custom_hosts and contains_custom(text, custom_hosts):
        return True

    if custom_orgs and contains_custom(text, custom_orgs):
        return True

    # fallback intelligente
    if auto and contains_auto_keyword(text):
        return True

    return False

def redact_image(image_path, output_path, checks, custom_hosts, custom_orgs, auto):
    img = cv2.imread(str(image_path))
    proc = preprocess(img)

    data = pytesseract.image_to_data(proc, output_type=pytesseract.Output.DICT)

    lines = {}
    for i in range(len(data['text'])):
        key = (data['block_num'][i], data['par_num'][i], data['line_num'][i])
        lines.setdefault(key, []).append(i)

    for indices in lines.values():
        full_text = " ".join(data['text'][i] for i in indices)

        if should_redact(full_text, checks, custom_hosts, custom_orgs, auto):
            for i in indices:
                x = data['left'][i]
                y = data['top'][i]
                w = data['width'][i]
                h = data['height'][i]
                cv2.rectangle(img, (x, y), (x+w, y+h), (0,0,0), -1)

    cv2.imwrite(str(output_path), img)

# --- TEXT/HTML REDACT ---
TEXT_EXTS = {".html", ".htm", ".txt", ".md", ".xml", ".json", ".csv", ".log"}
REDACT_MARK = "█"

def _mask(match):
    s = match.group(0)
    return REDACT_MARK * max(len(s), 5)

def redact_text_content(text, checks, custom_hosts, custom_orgs):
    # pattern espliciti
    for pat in checks:
        text = re.sub(pat, _mask, text, flags=re.IGNORECASE)
    # custom strings: word-boundary case-insensitive
    for word in list(custom_hosts) + list(custom_orgs):
        if not word.strip():
            continue
        text = re.sub(re.escape(word), _mask, text, flags=re.IGNORECASE)
    return text

def redact_text_file(path, output_path, checks, custom_hosts, custom_orgs):
    try:
        raw = path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        print(f"[!] Skip {path.name}: {e}")
        return
    out = redact_text_content(raw, checks, custom_hosts, custom_orgs)
    output_path.write_text(out, encoding="utf-8")

def main():
    parser = argparse.ArgumentParser(description="Image redaction (offline, auto mode)")

    parser.add_argument("--input", required=False, help="Cartella immagini input")
    parser.add_argument("--output", required=False, help="Cartella immagini output")
    parser.add_argument("--input-text", required=False, help="Cartella file testuali (html/txt/md/xml/json/csv/log)")
    parser.add_argument("--output-text", required=False, help="Cartella output testi")

    parser.add_argument("--url", action="store_true")
    parser.add_argument("--email", action="store_true")
    #parser.add_argument("--phone", action="store_true")
    parser.add_argument("--host", action="store_true")
    parser.add_argument("--username", action="store_true")

    parser.add_argument("--custom-hosts", nargs="*", default=[])
    parser.add_argument("--custom-orgs", nargs="*", default=[])

    args = parser.parse_args()

    checks, enabled = build_checks(args)

    auto = False
    if not enabled:
        print("[*] AUTO MODE attivo (nessun flag specificato)")
        checks = auto_mode()
        auto = True
    else:
        print(f"[*] Modalità manuale: {enabled}")

    if not args.input and not args.input_text:
        parser.error("Specifica almeno --input o --input-text")

    # IMMAGINI
    if args.input:
        if not args.output:
            parser.error("--output richiesto con --input")
        input_folder = Path(args.input)
        output_folder = Path(args.output)
        output_folder.mkdir(parents=True, exist_ok=True)
        for file in input_folder.iterdir():
            if file.suffix.lower() in [".png", ".jpg", ".jpeg"]:
                out = output_folder / file.name
                print(f"[+] IMG: {file.name}")
                redact_image(file, out, checks, args.custom_hosts, args.custom_orgs, auto)

    # TESTI / HTML
    if args.input_text:
        if not args.output_text:
            parser.error("--output-text richiesto con --input-text")
        text_in = Path(args.input_text)
        text_out = Path(args.output_text)
        text_out.mkdir(parents=True, exist_ok=True)
        for file in text_in.rglob("*"):
            if file.is_file() and file.suffix.lower() in TEXT_EXTS:
                rel = file.relative_to(text_in)
                out = text_out / rel
                out.parent.mkdir(parents=True, exist_ok=True)
                print(f"[+] TXT: {rel}")
                redact_text_file(file, out, checks, args.custom_hosts, args.custom_orgs)

if __name__ == "__main__":
    main()
