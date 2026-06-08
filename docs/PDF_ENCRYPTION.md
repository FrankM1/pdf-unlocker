# How PDF password encryption works (and why short passwords lose)

A practical explainer aimed at understanding *password recovery*, written from
unlocking real bank-statement PDFs. It covers the **standard security handler**
(the password-based scheme almost every bank uses).

## The big picture

A PDF isn't encrypted *with your password directly*. Instead:

1. The file is encrypted with a random **file encryption key** (RC4 or AES).
2. That key is wrapped so it can be re-derived from a **password**.
3. The `/Encrypt` dictionary stores verification data (`/O`, `/U`, …) so a reader
   can check whether a typed password is correct **before** decrypting anything.

Password *recovery* therefore never attacks the cipher — it just replays step 3
for many candidate passwords until one verifies. That check is a handful of
hashes, so it's fast, and the only thing protecting the document is how hard the
password is to guess.

## The `/Encrypt` dictionary

Key fields (readable without any password):

| Field | Meaning |
|---|---|
| `/V`, `/R` | algorithm version / revision (decides the math below) |
| `/Length` | key size in bits (40, 128, 256) |
| `/P` | permission flags (signed 32-bit; feeds the key derivation) |
| `/O` | owner-password verification value (32 bytes for R≤4, 48 for R≥5) |
| `/U` | user-password verification value |
| `/OE`, `/UE` | wrapped keys (R5/R6 only) |
| `/EncryptMetadata` | whether metadata is encrypted (affects the key on R≥4) |
| trailer `/ID[0]` | the file ID, also mixed into the key (R≤4) |

There are two passwords: the **user** password (open/read) and the **owner**
password (permissions). Either opens the file. Banks sometimes set only one — so
a recovery tool must check **both** `/U` and `/O`.

## Revisions 2–4: MD5 + RC4 (the weak, common case)

These are what most older statements use (M-Pesa = R3, many others R4).

**Algorithm 2 — derive the key from the user password:**
1. Pad/truncate the password to exactly 32 bytes using the fixed PDF pad string.
2. `key = MD5(padded_pw + O + P_as_4_bytes_LE + ID0 [+ 0xFFFFFFFF if R≥4 and
   metadata not encrypted])`.
3. If R≥3, hash the first *keylen* bytes 50 more times: `key = MD5(key[:keylen])`.
4. Keep the first *keylen* bytes (5 for 40-bit, 16 for 128-bit).

**Algorithm 4/5 — compute the expected `/U` and compare:**
- R2: `U = RC4(key, PAD)`.
- R3+: `U = RC4(key, MD5(PAD + ID0))`, then 19 more RC4 passes with
  `key XOR i` for i = 1..19. Compare the first 16 bytes to stored `/U`.

If they match, the password is right. The whole check is ~50 MD5s + RC4 — i.e.
**microseconds**. RC4 is also cryptographically weak, so tools like hashcat run
this on a GPU at millions–billions of guesses/sec.

**Owner password (Algorithm 7):** derive an owner key from the candidate
(`MD5(pad(pw))`, 50× on R≥3), RC4-decrypt `/O` to recover the padded *user*
password, then validate that via Algorithm 4/5.

## Revisions 5–6: AES-256 + SHA (the strong case)

R6 (PDF 2.0) and the deprecated R5 store `/U` as `hash(32) + validationSalt(8) +
keySalt(8)`:
- **R5:** `SHA-256(password + validationSalt)` compared to `/U[:32]`. (Validation
  needs only SHA-256 — no AES — so it's still brute-checkable, just per-guess
  slower than RC4.)
- **R6:** a hardened loop (Algorithm 2.B) of SHA-256/384/512 + AES-128-CBC
  rounds — deliberately slow, and AES-256 has no practical cryptanalytic break.
  Recovery here depends entirely on a weak/short password.

## Why these statements were crackable

Nothing about the cipher was broken. The passwords are **short and structured**:

| Bank | Rule (from the statement emails) | Search space |
|---|---|---|
| M-Pesa | national ID / passport number | a few ×10⁷ |
| Chase / SBM | account digits 3–12 | fixed once you know the account |
| Co-op | 7 digits after the first 5 | 10⁷ |
| Standard Chartered | 6 middle digits of the account | 10⁶ |
| Stanbic | a customer-set password (often a short PIN) | tiny |

With a 6-digit password on RC4, the entire space is 1,000,000 guesses — seconds
on a GPU, minutes in Python. The real secret is the ID/account number, not the
encryption. **Lesson: password-protecting a PDF with a derivable number is
obfuscation, not security.**

## The brute-force math

`time ≈ space / rate`. Rates here:
- pikepdf (this tool), re-parses each try: ~1,000/sec/core → ~8k/sec on 8 cores.
- a hand-rolled RC4 verifier (no re-parse): ~100k/sec/core.
- hashcat on a GPU (RC4 PDF, mode 10500): 10⁷–10⁹/sec.

So 6 digits (10⁶): pikepdf ≈ 2 min parallel, hashcat ≈ instant. 8 digits (10⁸):
pikepdf ≈ hours, hashcat ≈ seconds.

## Going faster with hashcat

hashcat needs the PDF's hash in John/“`$pdf$`” format. The fields come straight
from the `/Encrypt` dict (`V,R,Length,P,/O,/U,/ID`):

```
$pdf$<V>*<R>*<keylen_bits>*<P_signed>*<EncryptMetadata 0|1>*<idlen>*<idhex>*<Ulen>*<Uhex>*<Olen>*<Ohex>
```

`pdf_unlocker.py hash` emits exactly this (no `pdf2john` needed) and prints the
right mode on stderr. Pick the hashcat mode by revision: **R2-4 → `-m 10500`**,
**R5 → `-m 10600`**, **R6 → `-m 10700`**.

```bash
python pdf_unlocker.py hash statement.pdf > hash.txt        # writes $pdf$...
hashcat -m 10500 -a 3 hash.txt '?d?d?d?d?d?d'               # 6-digit mask
```

Batch many files into one hashfile — hashcat tests each candidate against every
loaded salt in the same kernel run, so cracking 33 statements costs little more
than one, and it removes each hash from the active set as it falls:

```bash
for f in *.pdf; do python pdf_unlocker.py hash "$f"; done > all.txt
hashcat -m 10500 -a 3 all.txt --increment --increment-min 6 --increment-max 8 \
        '?d?d?d?d?d?d?d?d' -o cracked.txt
```

**Validate the extractor before trusting it.** The `$pdf$` field order (and the
U-before-O convention) is easy to get wrong, and a wrong hash just fails to crack
silently. Confirm the whole pipeline against a *known* password first: re-encrypt
any PDF at the target revision with a password you set, emit its hash, and check
hashcat recovers it.

```bash
python - <<'PY'
import pikepdf as P
with P.open("any.pdf") as pdf:                 # source must be unencrypted
    pdf.save("fix.pdf", encryption=P.Encryption(user="12345678", owner="12345678",
                                                 R=3, aes=False, metadata=False))
PY
python pdf_unlocker.py hash fix.pdf > fix.hash
printf '12345678\n' | hashcat -m 10500 fix.hash    # must report ...:12345678
```

(pikepdf needs `aes=False, metadata=False` for R3; qpdf rejects AES/encrypted
metadata below R4. The resulting file still has no `/EncryptMetadata` key, so the
extractor reports `encMeta=1` — same as real R3 statements.)

## References

- ISO 32000-1 §7.6 (standard security handler), ISO 32000-2 (AES-256/R6).
- John the Ripper `pdf2john.py`; hashcat modes 10400–10700.
- pypdf `_encryption.py` (`AlgV4`, `AlgV5`) — readable Python implementations of
  all the algorithms above.
