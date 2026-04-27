# Redactor

Tool offline per oscurare informazioni sensibili (URL, email, IP, host, username, telefoni, MAC, domini) da **immagini** (OCR via Tesseract) e **file testuali** (HTML / TXT / MD / XML / JSON / CSV / LOG).

Pensato per screenshot di terminali, documenti tecnici, dump HTTP e simili: lavora in locale, niente API esterne. Io l'ho progettato per Offuscare Dati da poter passare in modo sicuro all'AI di turno.

## Requisiti

- Python 3.8+
- Tesseract OCR (con lingue `ita` + `eng`)
- Pacchetti Python: `opencv-python`, `pytesseract`

```bash
# Debian/Ubuntu
sudo apt install tesseract-ocr tesseract-ocr-ita
pip install opencv-python pytesseract
```

## Pattern riconosciuti

### Base
| Categoria   | Esempi                                          |
|-------------|-------------------------------------------------|
| `url`       | `https://foo.com/path`, `www.bar.it`, `ftp://…` |
| `domain`    | `example.com`, `sub.foo.it/path` (TLD whitelist)|
| `email`     | `user@dominio.tld`                              |
| `ipv4`      | `192.168.1.1`, `10.0.0.1:8080`                  |
| `ipv6`      | `fe80::1`, `2001:db8::1`                        |
| `mac`       | `aa:bb:cc:dd:ee:ff`                             |
| `host_line` | `Host: foo.bar.com`                             |
| `username`  | `username: pippo`, `nome utente: pluto`         |
| `phone`     | `+39 333 1234567`, `0039-02-1234567`            |

### HTTP / Burp Suite (dump request/response, screenshot Burp)
| Categoria        | Esempi                                          |
|------------------|-------------------------------------------------|
| `cookie_line`    | `Set-Cookie: foo=bar; Path=/`, `Cookie: sid=…`  |
| `auth_line`      | `Authorization: Bearer …`, `Authorization: Basic …` |
| `api_key_header` | `X-API-Key: …`, `X-Csrf-Token: …`, `X-Forwarded-For: …` |
| `bearer_token`   | `Bearer eyJ…`                                   |
| `basic_token`    | `Basic dXNlcjpwYXNz`                            |
| `jwt`            | `eyJhbGciOi….payload.sig`                       |
| `session_cookie` | `JSESSIONID=…`, `PHPSESSID=…`, `XSRF-TOKEN=…`   |
| `session_generic`| qualsiasi `*session*=value`                     |
| `generic_secret` | `api_key=…`, `password=…`, `token=…` (16+ char) |

### Smart fallback (no scheme richiesto)
| Categoria     | Esempi                                                     |
|---------------|------------------------------------------------------------|
| `path_route`  | `/api/v2/users/details`, `/Accrediti/testata/30?code=…` |
| `query_secret`| `?code=ABC123`, `?token=…`, `?sid=…`, `?nonce=…`, `?csrf=…` |
| `long_camel`  | `AccreditiGiornalisti`, `aggiornaInformazioniUtente` |

I pattern sono volutamente **precisi**: niente match parziali su parole comuni (`mailbox`, `ghost`, `hostname` non vengono toccate per errore).
`long_camel` è case-sensitive (`(?-i:...)`): identificatori ALLCAPS (`HTTPSCONNECTION`) non vengono redatti.

## Uso

### Solo immagini

```bash
python3 redactor.py --input ./img_in --output ./img_out
```

### Solo testi/HTML

```bash
python3 redactor.py --input-text ./html_in --output-text ./html_out
```

### Entrambi insieme

```bash
python3 redactor.py \
  --input ./img_in --output ./img_out \
  --input-text ./html_in --output-text ./html_out
```

### Modalità manuale (solo categorie scelte)

```bash
python3 redactor.py --input ./img_in --output ./img_out --url --email
```

Senza flag → **AUTO mode** (tutti i pattern attivi + fallback keyword).

### Custom strings

Per oscurare parole arbitrarie in aggiunta ai pattern automatici:

```bash
python3 redactor.py \
  --input ./img_in --output ./img_out \
  --custom-orgs organizzazione ufficio reparto \
  --custom-hosts mioserver1 mioserver2
```

Match **substring case-insensitive**.

## Output

### Immagini
- **Bbox full-line** sulla riga matchata: copre da prima a ultima parola, spazi inclusi → **nessun char-count leak**.
- **Padding**: 25% line height verticale (descender), 50% line height orizzontale (punteggiatura/micro-OCR-miss).
- **Multi-pass OCR (4 pass)** per screenshot misti chiaro/scuro (es. dump Burp con bande dark): Otsu, invert+CLAHE+Otsu, adaptive threshold, invert+CLAHE+adaptive aggressivo.
- **Confidence adattiva per pass**: pass 1-2 conf≥30 (Otsu pulito), pass 3-4 conf≥5 (adaptive rumoroso, sicuro perché redact solo su match regex).
- **Verify-loop**: dopo redact ri-OCR + re-redact fino a 3 iterazioni → garantisce zero residui OCR'able.

### Testi
- **Placeholder fissi per categoria**, niente length leak:

| Pattern matchato       | Sostituito con          |
|------------------------|-------------------------|
| `url`                  | `[URL_REDATTO]`         |
| `domain`               | `[DOMINIO_REDATTO]`     |
| `email`                | `[EMAIL_REDATTA]`       |
| `ipv4` / `ipv6`        | `[IP_REDATTO]` / `[IPV6_REDATTO]` |
| `mac`                  | `[MAC_REDATTO]`         |
| `host_line`            | `[HOST_REDATTO]`        |
| `username`             | `[UTENTE_REDATTO]`      |
| `cookie_line`          | `[COOKIE_REDATTO]`      |
| `auth_line`            | `[AUTH_REDATTA]`        |
| `api_key_header`       | `[API_KEY_REDATTA]`     |
| `bearer_token`         | `[BEARER_REDATTO]`      |
| `basic_token`          | `[BASIC_REDATTO]`       |
| `jwt`                  | `[JWT_REDATTO]`         |
| `session_*`            | `[SESSION_REDATTA]`     |
| `generic_secret`       | `[SEGRETO_REDATTO]`     |
| `path_route`           | `[PATH_REDATTO]`        |
| `query_secret`         | `[QUERY_REDATTA]`       |
| `long_camel`           | `[ID_REDATTO]`          |
| custom strings         | `[CUSTOM_REDATTO]`      |

- Custom strings applicati **prima** dei pattern, ordinati per lunghezza DESC.
- Pattern ordinati: specifici (jwt, bearer, cookie, auth, email…) **prima** di generici (domain, ipv4, generic_secret) → evita che pattern generici consumino substring di match più precisi.
- Funziona su HTML su singola riga (export CherryTree): pattern HTTP terminano su `<` / newline / quote.

## Sicurezza by default

Tool progettato per essere **safe-by-default** senza flag `--strict`:

- ❌ **Niente length leak** sui testi (placeholder fissi, non `█ × len(s)`).
- ❌ **Niente char-count leak** sulle immagini (bbox full-line, non per-word).
- ✅ **Verify-loop OCR** post-redact (max 3 iter) → no residui visibili.
- ✅ **Pattern ordering** previene leak da match parziali.
- ✅ **PNG output** lossless senza metadata (cv2.imwrite default).

### Limiti residui (side-channel)
- **Context leak**: tag HTML, prefissi (`Set-Cookie:`, `code=`) intatti → categoria nota.
- **Pattern-disclosure**: codice pubblico → attaccante conosce categorie redatte.
- **Multi-source correlation**: se il dato è leak'd altrove → riconoscibile via contesto.
- **OCR coverage**: se Tesseract non legge una parte (font esotici, watermark) → non redatta. Mitigato da multi-pass + verify-loop ma non azzerato.

Per uso forense/legale: aggiungi review manuale + strip metadata esplicito (`exiftool -all=`).

## Estensioni testuali supportate

`.html`, `.htm`, `.txt`, `.md`, `.xml`, `.json`, `.csv`, `.log`

Scansione **ricorsiva**, struttura cartelle preservata in output.

## Flag completi

| Flag              | Descrizione                                  |
|-------------------|----------------------------------------------|
| `--input`         | Cartella immagini input                      |
| `--output`        | Cartella immagini output                     |
| `--input-text`    | Cartella file testuali input (ricorsivo)     |
| `--output-text`   | Cartella testi output                        |
| `--url`           | Attiva pattern URL/dominio                   |
| `--email`         | Attiva pattern email                         |
| `--host`          | Attiva pattern `Host:`                       |
| `--username`      | Attiva pattern username                      |
| `--custom-hosts`  | Lista host/stringhe custom da oscurare       |
| `--custom-orgs`   | Lista nomi/stringhe custom da oscurare       |

## Licenza

MIT
