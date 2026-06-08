# Handoff — state of the PDF unlock work

Pick-up notes for another session. This project was split out of the
`email-scanner` project (`~/GitHub/email-scanner`), which scans/classifies the
emails and has the production `--decrypt` path. This repo is the standalone
experimentation + cracking tool.

## Goal

Unlock ~10 years of the owner's personal bank-statement PDFs (their own
documents). Most are recoverable from a few secrets + per-bank derivation rules;
a minority are not.

## Where the data lives

- **Email cache:** `~/gmail_pdf_cache/*.eml` — 1684 messages (all PDF-bearing
  Gmail mail), fetched once so we iterate offline. Built by
  `email-scanner/scripts/cache_gmail.py`.
- **Secrets (NOT in git):** `~/.config/email-scanner/pdf_secrets.txt` — the
  owner's ID, account numbers, Stanbic password, DOB, one per line. The
  email-scanner `--decrypt` reads it; this tool's `derive` takes them as flags.
  **Never commit real secrets to either repo.**
- **Organized output:** `~/Statements Final 2/` (bank folders + `_Locked/<bank>/`
  for still-protected files).

## Per-bank password rules (discovered from the statement emails)

| Bank | Encryption | Password rule |
|---|---|---|
| M-Pesa / Safaricom | RC4-40/128 (R2/R3) | "original identification document" = **national ID** (or **passport**/military for older ones) |
| Chase Bank Kenya / SBM | RC4/AES-128 (R4), some AES-256 (R5) | **account digits 3–12** (e.g. acct `00 1234567 8901` → `1234567890`) |
| Co-op Bank | RC4/AES-128 (R4) + AES-256 (R5) | **7 digits after the first 5** of the account (email example: `01136190856100` → `1908561`) |
| Standard Chartered | RC4/AES-128 (R4) | **6 middle digits** of the account (`01234 XXXXXX 12` → `XXXXXX`) |
| Stanbic | AES-128 (R4) | a **customer-set password** (this owner's is a 4-digit PIN; it's in `pdf_secrets.txt`) |

`pdf_unlocker.py derive` auto-generates all these slices from a raw account
number, so you can pass `--account <full number>` and it tries the right cut.

## Progress (updated)

SCB and M-Pesa are now **done**; only Co-op remains. Still locked:

| Group | Count | Why / what's needed |
|---|---|---|
| ~~M-Pesa~~ | ~~33~~ → **0** | **DONE.** Cracked via hashcat (`-m 10500`) in 4s — each statement uses its **own unique 6-digit code** (OTP-style, NOT the national ID). Unlocked copies in `~/Statements Final 2/M-Pesa/*_unlocked.pdf`. |
| ~~Standard Chartered~~ | ~~4~~ → **0** | **DONE.** All four open with **`‹SCB-PW-REDACTED›`** (the account's 6 middle digits; same account → same password). pikepdf brute found it in ~40s/file. Unlocked copies in `~/Statements Final 2/Standard_Chartered/*_unlocked.pdf`. |
| Co-op (R4) | ~~5~~ → **0** | **DONE.** All 5 R4 (2018-2022) open with **`‹COOP-R4-PW-REDACTED›`** (the "7 digits after the first 5" of the account — same for every statement, found via hashcat `-m 10500` 7-digit mask in seconds). Unlocked copies in `~/Statements Final 2/Co-op_Bank/*_unlocked.pdf`. |
| Co-op (R5) | ~~2~~ → **0** | **DONE.** The 2 AES-256 statements (2023, 2024) open with **`‹COOP-R5-PW-REDACTED›`** (9 digits, NOT account-derived like the R4 ones). Found via hashcat `-m 10600` (836 MH/s) 9-digit sweep. Required fixing the extractor's R≥5 `$pdf$` layout (U/O zero-padded to 127 + `/UE`,`/OE` fields) and `pip install cryptography` so pypdf can read AES PDFs. Unlocked copies in `~/Statements Final 2/Co-op_Bank/*_unlocked.pdf`. |
| `_Unsorted` | 26 → **7 left** | **16 of 26 unlocked.** The 19 R2 + 7 R3/R4 split by hashcat mode (R2 → `-m 10400`, R3/R4 → `-m 10500`). **16 R2 cracked** (short shared PINs by doc family: `0804_E*`=`‹PIN-REDACTED›`, `payslip*`=`‹PIN-REDACTED›`, `Unit_Trust_Statement*`=`‹PIN-REDACTED›`). **3 are not real PDFs** (saved HTTP/HTML error pages — `Unit_Trust_Business_Confirmation*` — unrecoverable). **7 R3/R4 forms still locked** (`AccountOpening*`, `Application_Form_3`, `IID`, `KSPXX092`, `Notification_Addendum`): resisted numeric ≤9-digit, Kenyan-phone `07########`, lowercase 3-6, and name-mutation wordlists. Likely institution-set/longer passwords — left as low-value. |

> **Note — an active file-organizer watches `~/Statements Final 2/`.** Once a file
> is decrypted and readable it may be auto-moved to a categorized folder (e.g. the
> 4 unlocked `Unit_Trust_Statement` copies were moved from `_Unsorted/` to
> `Cytonne/`). Unlocked copies are never lost, but don't assume they stay in the
> folder you wrote them to — `find ~/"Statements Final 2" -name '*_unlocked.pdf'`.

> **M-Pesa rule correction:** the per-bank table above says M-Pesa = national ID.
> That holds for the *older* statements (already among the 376). The 33 that were
> still locked are **recent** statements that instead use a per-statement 6-digit
> code — NOT a shared secret, so they don't go in `pdf_secrets.txt`. They were
> brute-forced individually (trivial: 10⁶ each, all 33 in one hashcat run).

## Tooling state

- `pdf_unlocker.py` — works: `info`, `hash` (NEW: emits `$pdf$` for hashcat),
  `derive`, `brute` (parallel pikepdf), `wordlist`, `unlock`. Verifier = pikepdf
  (correct for all revisions + user/owner). Speed ~1k/sec/core.
- **Environment:** deps are NOT installed system-wide (the old env was gone). A
  venv now lives at `.venv/` (python3.13, pikepdf 10.7, pypdf 6.13). Run as
  `.venv/bin/python pdf_unlocker.py …`. Recreate with
  `python3.13 -m venv .venv && .venv/bin/pip install -r requirements.txt`.
- `hashcat 7.1.2` (Homebrew) is now **wired up and validated** end-to-end on the
  M1 Pro GPU (Metal/OpenCL, ~5.2 MH/s on `-m 10500`). No `pdf2john` needed —
  `pdf_unlocker.py hash` produces the `$pdf$` string directly. See
  docs/PDF_ENCRYPTION.md § "Going faster with hashcat" for the batch + known-
  password validation workflow.

## Known WIP / gotchas

- A **fast pure-Python verifier** was attempted (calling pypdf `AlgV4`) to beat
  pikepdf's ~1k/sec. It hit `ValueError: Invalid key size (16) for RC4` from
  `cryptography`'s decrepit RC4 on R4 files (version mismatch in pypdf's RC4
  path). Resolve by: pinning/patching the RC4 call, or implementing the MD5/RC4
  standard handler by hand (R2 was verified correct that way; R3+/U needs
  debugging), or just use hashcat for speed. pikepdf is correct meanwhile.
- pikepdf opens *unencrypted* PDFs with ANY password — always gate on
  `is_encrypted()` first when validating logic.
- `/P` must be packed **unsigned** (`struct.pack("<I")`) for pypdf's AlgV4.
- Some R5 files have **no `/ID`** in the trailer — handle missing `/ID`.

## Suggested next steps

1. **Co-op (the only group left).** Best path: get the owner's real Co-op
   account number → `derive --account <number>` unlocks all 7 instantly (rule:
   7 digits after the first 5). If the number is unavailable, brute:
   - 5×R4: hashcat `-m 10500` over the 7-digit space — seconds. (pikepdf brute
     `--min 7 --max 7` also works, ≈17 min/file.)
   - 2×R5 (AES-256): hashcat `-m 10600` (R5 = single SHA-256/guess, still fast).
   Workflow is identical to the M-Pesa run that's now documented.
2. SCB **‹SCB-PW-REDACTED›** and the 33 M-Pesa codes were **not** added to
   `pdf_secrets.txt`: SCB's is account-derived (re-derivable from the account
   number) and the M-Pesa ones are per-statement throwaways. If you want
   email-scanner's `--decrypt` to reproduce these, add the SCB **account number**
   (so `derive` regenerates `‹SCB-PW-REDACTED›`); the M-Pesa OTPs can't be re-derived, so
   keep the `*_unlocked.pdf` copies as the source of truth for those.
3. (Optional, learning) Finish the fast pure-Python verifier — now lower value
   since hashcat handles the big spaces. docs/PDF_ENCRYPTION.md has the algorithm.
4. Materialize: the SCB + M-Pesa `*_unlocked.pdf` copies are already in
   `~/Statements Final 2/<bank>/`. Once Co-op is done, remove the corresponding
   `_Locked/<bank>/` originals if you want a clean tree.
