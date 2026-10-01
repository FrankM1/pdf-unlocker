# pdf-unlocker-experiment

A small, hackable tool for recovering passwords on **your own** encrypted PDFs
(originally built to unlock years of personal bank statements). It's also a
hands-on way to learn how PDF encryption actually works — see
[`docs/PDF_ENCRYPTION.md`](docs/PDF_ENCRYPTION.md).

> Use this only on documents you are authorized to open. It recovers passwords
> by trying candidates fast; it does not break the cryptography itself.

## Install

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## Use

> New to this? See [`docs/USAGE.md`](docs/USAGE.md) for a plain, step-by-step
> walkthrough. The reference below is denser.

```bash
# What encryption does this PDF use?
python pdf_unlocker.py info statement.pdf
#   encrypted: True / R: 3 / algorithm: RC4-128

# Derive the password from known structure (the bank rules).
# Fastest path when you know the account number / ID.
python pdf_unlocker.py derive statement.pdf --account 1234567890123
python pdf_unlocker.py derive statement.pdf --id 12345678
python pdf_unlocker.py derive statement.pdf --date "01 Jan 1990"

# Brute-force a numeric password (parallel across all CPU cores).
python pdf_unlocker.py brute statement.pdf --min 4 --max 6

# Try a wordlist.
python pdf_unlocker.py wordlist statement.pdf candidates.txt

# Emit the $pdf$ hash for hashcat/john (prints the right -m mode on stderr).
python pdf_unlocker.py hash statement.pdf > hash.txt

# Write an unlocked copy once you have the password.
python pdf_unlocker.py unlock statement.pdf --password 1234 -o statement_open.pdf
# (derive/brute/wordlist also accept -o to save the unlocked copy when found)
```

## How it decides

`verify()` uses **pikepdf** (qpdf) to attempt opening with each candidate, so it
correctly handles every PDF revision (RC4 R2–4, AES-256 R5–6) and accepts the
**user or owner** password. A candidate check is one `pikepdf.open()`
(~1k/sec/core); brute runs them in parallel.

## Why bank statements are crackable

The passwords are short, structured **numbers** (national IDs, slices of the
account number, 4-digit PINs) and older statements use **weak RC4**. So the real
defense is the secrecy of your ID/account number, not the cipher. The
[encryption explainer](docs/PDF_ENCRYPTION.md) covers the math.

## Speed & the fast path

pikepdf is ~1,000 tries/sec/core (it re-parses the doc each try). That's fine for
small spaces (6 digits ≈ minutes parallel) but slow for an 8-digit space
(~hours). For large brute jobs use **hashcat** (installed: `hashcat 7.1.2`) — it
does millions/sec (~5 MH/s on an M1 Pro GPU). The `hash` subcommand emits the
`$pdf$` hash directly (no `pdf2john` needed); pick `-m 10500` for R2–4, `-m 10600`
for R5, `-m 10700` for R6. See
[`docs/PDF_ENCRYPTION.md`](docs/PDF_ENCRYPTION.md) § "Going faster with hashcat"
for the batch + known-password validation workflow.

## Status & handoff

See [`HANDOFF.md`](HANDOFF.md) for what's already discovered (per-bank password
rules, encryption revisions, what's unlocked vs pending) so another session can
continue.
