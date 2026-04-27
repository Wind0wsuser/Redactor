# Redactor

Tool offline per oscurare informazioni sensibili (URL, email, IP, host, username, telefoni, MAC, domini) da **immagini** (OCR via Tesseract) e **file testuali** (HTML / TXT / MD / XML / JSON / CSV / LOG).

Pensato per screenshot di terminali, documenti tecnici, dump HTTP e simili: lavora in locale, niente API esterne.

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

I pattern sono volutamente **precisi**: niente match parziali su parole comuni (`mailbox`, `ghost`, `hostname` non vengono toccate per errore).

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
  --custom-orgs camera ufficio reparto \
  --custom-hosts mioserver1 mioserver2
```

Match **substring case-insensitive**.

## Output

- **Immagini**: rettangoli neri sopra le parole identificate dall'OCR.
- **Testi**: i match sono sostituiti con blocchi `█` di lunghezza ≈ originale, preservando struttura HTML/JSON.

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
