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

    # --- HTTP / Burp Suite headers (request/response dump) ---
    # NB: termina su < (tag HTML), newline, " o virgolette → funziona su HTML single-line
    # Set-Cookie / Cookie: nome header + valore
    "cookie_line": r'(?i)\b(?:Set-Cookie|Cookie)\s*:\s*[^<\r\n"\']{1,4096}',

    # Authorization: Bearer/Basic/Digest
    "auth_line": r'(?i)\bAuthorization\s*:\s*[^<\r\n"\']{1,4096}',

    # Header API key / token tipici
    "api_key_header": r'(?i)\bX-(?:API[\-_]?Key|Auth[\-_]?Token|Access[\-_]?Token|Csrf[\-_]?Token|Session[\-_]?Token|Refresh[\-_]?Token|Forwarded[\-_]?For|Real[\-_]?IP)\s*:\s*[^<\r\n"\']{1,4096}',

    # Bearer / Basic token inline (anche fuori da header)
    "bearer_token": r'\bBearer\s+[A-Za-z0-9\-_=\.~+/]{8,}={0,2}',
    "basic_token": r'\bBasic\s+[A-Za-z0-9+/=]{8,}={0,2}',

    # JWT (3 segmenti base64url)
    "jwt": r'\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b',

    # Cookie session noti: nome=valore
    "session_cookie": r'(?i)\b(?:JSESSIONID|PHPSESSID|ASPSESSIONID[A-Z0-9]+|ASP\.NET_SessionId|connect\.sid|laravel_session|session_id|sessionid|csrftoken|XSRF-TOKEN|access_token|refresh_token|id_token|auth_token|api_key|apikey)=[^;\s"\'<>&]+',

    # Session cookie generici: qualsiasi *session*=value o *session*:value
    "session_generic": r'(?i)\b[\w\-]*session[\w\-]*\s*[:=]\s*["\']?[^;\s"\'<>&,]{4,}["\']?',

    # API key generiche: chiave=valore lungo (32+ char base64-like)
    "generic_secret": r'(?i)\b(?:api[_\-]?key|secret|token|password|passwd|pwd)[\s]*[:=][\s]*["\']?[A-Za-z0-9+/=_\-\.]{16,}["\']?',

    # Path/route applicativo: /seg1/seg2/seg3... (3+ segmenti) ± querystring
    # Cattura href, dump HTTP, JS inline anche senza scheme http(s)://
    "path_route": r'(?<![A-Za-z0-9])/(?:[A-Za-z][A-Za-z0-9_\-]{2,}/){2,}[A-Za-z0-9][A-Za-z0-9_\-\.]*(?:\?[^\s<>"\'()]{1,512})?',

    # Query/URL secret: ?code=, ?token=, ?key=, ?auth=, ?sid=, ?tk=, ?session=
    "query_secret": r'(?i)(?<![A-Za-z0-9])(?:code|token|key|auth|secret|pass|sid|tk|session|nonce|state|csrf|otp)=[A-Za-z0-9_\-\.]{6,}',

    # Identificatore camelCase lungo (12+ char, mix lower+upper)
    # cattura: categorialavorativa, aggiornaInformazioniUtente, ecc.
    # esclude: ALLCAPS (gestiti altrove), parole tutte lower (no segnale)
    # NB: (?-i:...) forza case-sensitive anche se chiamato con re.IGNORECASE
    "long_camel": r'(?-i:\b(?=[A-Za-z]*[a-z])(?=[A-Za-z]*[A-Z])[A-Za-z]{12,}\b)',
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

OCR_CONFIG = r'--oem 1 --psm 6 -l ita+eng'

def _preprocess_passes(img):
    """Genera multi-pass per gestire sia testo scuro/chiaro che bande miste.
    Returns: lista di immagini binarie, scale factor (per remap coordinate)."""
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

    # upscale: 3x se piccola, 2x media, 1x grande
    h, w = gray.shape
    if max(h, w) < 1000:
        scale = 3
    elif max(h, w) < 2000:
        scale = 2
    else:
        scale = 1
    if scale > 1:
        gray = cv2.resize(gray, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC)

    denoised = cv2.bilateralFilter(gray, 5, 50, 50)

    # PASS 1: testo scuro su chiaro (Otsu standard)
    _, p1 = cv2.threshold(denoised, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)

    # PASS 2: testo chiaro su scuro (invert + CLAHE + Otsu)
    inv = cv2.bitwise_not(denoised)
    clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8))
    eq = clahe.apply(inv)
    _, p2 = cv2.threshold(eq, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)

    # PASS 3: adaptive threshold (gestisce variazioni locali, banner colorati)
    p3 = cv2.adaptiveThreshold(denoised, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                               cv2.THRESH_BINARY, 31, 10)

    # PASS 4: testo chiaro su scuro con bande miste (invert+CLAHE + adaptive aggressivo)
    p4 = cv2.adaptiveThreshold(eq, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                               cv2.THRESH_BINARY, 51, 15)

    return [p1, p2, p3, p4], scale

def preprocess(img):
    """Compat: ritorna primo pass."""
    passes, _ = _preprocess_passes(img)
    return passes[0]

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
        # HTTP / Burp
        PATTERNS["cookie_line"],
        PATTERNS["auth_line"],
        PATTERNS["api_key_header"],
        PATTERNS["bearer_token"],
        PATTERNS["basic_token"],
        PATTERNS["jwt"],
        PATTERNS["session_cookie"],
        PATTERNS["session_generic"],
        PATTERNS["generic_secret"],
        # smart fallback (path/route, query secret, identificatori camelCase)
        PATTERNS["path_route"],
        PATTERNS["query_secret"],
        PATTERNS["long_camel"],
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

def _ocr_correct(text):
    """Correzioni euristiche per errori OCR comuni prima del match regex."""
    fixes = [
        (r'\(at\)', '@'), (r'\[at\]', '@'), (r'\s+at\s+', '@'),
        (r'\(dot\)', '.'), (r'\[dot\]', '.'),
        (r'\bhxxp', 'http'), (r'\bhttps?\s*:\s*//', lambda m: 'https://' if 's' in m.group(0).lower() else 'http://'),
    ]
    out = text
    for pat, rep in fixes:
        out = re.sub(pat, rep, out, flags=re.IGNORECASE)
    return out

def redact_image(image_path, output_path, checks, custom_hosts, custom_orgs, auto):
    img = cv2.imread(str(image_path))
    passes, scale = _preprocess_passes(img)

    # multi-pass: ogni pass cattura testo che gli altri perdono
    # (chiaro/scuro, contrasto locale variabile)
    # pass 0,1: conf>=30 (Otsu, alta qualità)
    # pass 2,3: conf>=5 (adaptive, bande scure rumorose) — sicuro perché redact solo se regex matcha
    for pass_idx, proc in enumerate(passes):
        min_conf = 30 if pass_idx < 2 else 5
        data = pytesseract.image_to_data(proc, output_type=pytesseract.Output.DICT, config=OCR_CONFIG)
        lines = {}
        for i in range(len(data['text'])):
            try:
                conf = int(data['conf'][i])
            except (ValueError, TypeError):
                conf = -1
            if conf < min_conf or not data['text'][i].strip():
                continue
            key = (data['block_num'][i], data['par_num'][i], data['line_num'][i])
            lines.setdefault(key, []).append(i)

        for indices in lines.values():
            raw_text = " ".join(data['text'][i] for i in indices)
            full_text = _ocr_correct(raw_text)

            if should_redact(full_text, checks, custom_hosts, custom_orgs, auto):
                for i in indices:
                    x = int(data['left'][i] / scale)
                    y = int(data['top'][i] / scale)
                    w = int(data['width'][i] / scale)
                    h = int(data['height'][i] / scale)
                    # padding 2px per coprire descender/strikethrough
                    cv2.rectangle(img, (max(x-2,0), max(y-2,0)),
                                  (x+w+2, y+h+2), (0, 0, 0), -1)

    cv2.imwrite(str(output_path), img)

# --- TEXT/HTML REDACT ---
TEXT_EXTS = {".html", ".htm", ".txt", ".md", ".xml", ".json", ".csv", ".log"}
REDACT_MARK = "█"

def _mask(match):
    s = match.group(0)
    return REDACT_MARK * max(len(s), 5)

def redact_text_content(text, checks, custom_hosts, custom_orgs):
    # custom PRIMA dei pattern: evita che domain/url consumino substring custom
    # sort length DESC: parole lunghe prima, evita match parziali che bloccano i superset
    customs = sorted(
        {w for w in (list(custom_hosts) + list(custom_orgs)) if w.strip()},
        key=len, reverse=True
    )
    for word in customs:
        text = re.sub(re.escape(word), _mask, text, flags=re.IGNORECASE)
    # pattern regex
    for pat in checks:
        text = re.sub(pat, _mask, text, flags=re.IGNORECASE)
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
    #usare uno di questi due per fare un po da jolly
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
