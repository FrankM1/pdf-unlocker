"""pdf-unlocker-experiment — recover passwords for YOUR OWN encrypted PDFs.

A small, hackable tool for experimenting with PDF password recovery. It uses
pikepdf (qpdf under the hood) to test candidate passwords, which correctly
handles every PDF encryption revision (RC4 R2-4 and AES-256 R5-6) and accepts
either the user OR the owner password.

Strategies (compose them):
  - derive   : build candidates from known structure (account-number slices,
               IDs, dates) — see derive_candidates(). Instant when you know the
               account number; this is how the bank password rules work.
  - brute    : try every numeric password of length N (parallel across cores).
  - wordlist : try lines from a file.

Then optionally write an UNLOCKED copy.

See docs/PDF_ENCRYPTION.md for how PDF password validation actually works, and
HANDOFF.md for the per-bank rules already discovered.

CLI examples:
    python pdf_unlocker.py info statement.pdf
    python pdf_unlocker.py derive statement.pdf --account 1234567890123
    python pdf_unlocker.py brute  statement.pdf --min 4 --max 6
    python pdf_unlocker.py unlock statement.pdf --password 1234 -o out.pdf
"""

from __future__ import annotations

import argparse
import io
import os
import re
import sys
import time
from collections.abc import Iterable, Iterator
from concurrent.futures import ProcessPoolExecutor

import pikepdf


# --------------------------------------------------------------- verify / info


def is_encrypted(pdf_bytes: bytes) -> bool:
    try:
        with pikepdf.open(io.BytesIO(pdf_bytes)):
            return False
    except pikepdf.PasswordError:
        return True
    except Exception:
        return False


def verify(pdf_bytes: bytes, password: str) -> bool:
    """True if ``password`` opens the PDF (user or owner)."""
    try:
        with pikepdf.open(io.BytesIO(pdf_bytes), password=password):
            return True
    except pikepdf.PasswordError:
        return False
    except Exception:
        return False


def info(pdf_bytes: bytes) -> dict:
    """Encryption metadata (revision, algorithm) without the password."""
    import pypdf

    r = pypdf.PdfReader(io.BytesIO(pdf_bytes))
    if not r.is_encrypted:
        return {"encrypted": False}
    enc = r.trailer["/Encrypt"].get_object()
    R = int(enc["/R"])
    algo = {2: "RC4-40", 3: "RC4-128", 4: "RC4/AES-128", 5: "AES-256", 6: "AES-256"}
    return {
        "encrypted": True,
        "V": int(enc.get("/V", 0)),
        "R": R,
        "bits": int(enc.get("/Length", 40)),
        "algorithm": algo.get(R, "?"),
    }


def _raw(obj) -> bytes:
    """Bytes of a pypdf string object (/O, /U, /ID element)."""
    obj = obj.get_object() if hasattr(obj, "get_object") else obj
    if hasattr(obj, "original_bytes"):
        return obj.original_bytes
    if isinstance(obj, bytes):
        return obj
    return obj.encode("latin-1")


# hashcat / John "$pdf$" hash modes by revision:
#   R2 (RC4-40)               -> hashcat -m 10400  (PDF 1.1-1.3, Acrobat 2-4)
#   R3/R4 (RC4-128, AES-128)  -> hashcat -m 10500  (PDF 1.4-1.6, Acrobat 5-8)
#   R5 (AES-256)              -> hashcat -m 10600  (PDF 1.7 L3, Acrobat 9)
#   R6 (AES-256)              -> hashcat -m 10700  (PDF 1.7 L8, Acrobat 10-11)
_HASHCAT_MODE = {2: 10400, 3: 10500, 4: 10500, 5: 10600, 6: 10700}


def pdf_hash(pdf_bytes: bytes) -> str:
    """Extract the ``$pdf$`` hash string (John/hashcat format).

    Field order matches hashcat's PDF modes (validated end-to-end against a
    known-password fixture):
        $pdf$ V * R * bits * P * encMeta * idlen * id * ulen * U * olen * O
    ``P`` is the signed 32-bit permissions int; ``encMeta`` is 1 when the
    document metadata is encrypted (the default), else 0.
    """
    import pypdf

    r = pypdf.PdfReader(io.BytesIO(pdf_bytes))
    if not r.is_encrypted:
        raise ValueError("not encrypted")
    enc = r.trailer["/Encrypt"].get_object()
    V = int(enc.get("/V", 0))
    R = int(enc["/R"])
    bits = int(enc.get("/Length", 40))
    P = int(enc["/P"])
    if P > 0x7FFFFFFF:  # normalise to signed 32-bit
        P -= 0x100000000
    em = enc.get("/EncryptMetadata", True)
    em = 0 if (em is False or str(em).lower() == "false") else 1
    O = _raw(enc["/O"])
    U = _raw(enc["/U"])
    id_arr = r.trailer.get("/ID")
    id0 = _raw(id_arr[0]) if id_arr else b""
    if R >= 5:
        # R5/R6 (hashcat -m 10600/10700): /U and /O are 48 bytes zero-padded to
        # 127, plus the wrapped keys /UE and /OE (32 bytes). Matches pdf2john.
        UE = _raw(enc["/UE"])
        OE = _raw(enc["/OE"])
        pad = lambda b: (b + b"\x00" * 127)[:127]
        return (
            f"$pdf${V}*{R}*{bits}*{P}*{em}*"
            f"{len(id0)}*{id0.hex()}*"
            f"127*{pad(U).hex()}*"
            f"127*{pad(O).hex()}*"
            f"{len(UE)}*{UE.hex()}*"
            f"{len(OE)}*{OE.hex()}"
        )
    return (
        f"$pdf${V}*{R}*{bits}*{P}*{em}*"
        f"{len(id0)}*{id0.hex()}*"
        f"{len(U)}*{U.hex()}*"
        f"{len(O)}*{O.hex()}"
    )


def hashcat_mode(pdf_bytes: bytes) -> int:
    """The hashcat -m mode number for this file's encryption revision."""
    import pypdf

    r = pypdf.PdfReader(io.BytesIO(pdf_bytes))
    R = int(r.trailer["/Encrypt"].get_object()["/R"])
    return _HASHCAT_MODE.get(R, 0)


# ------------------------------------------------------------------- candidates


def derive_candidates(
    accounts: list[str] | None = None,
    ids: list[str] | None = None,
    dates: list[str] | None = None,
) -> list[str]:
    """Candidate passwords from known structure (the bank rules).

    - account slices: digits 3-12 (Chase/SBM), 7 after first 5 (Co-op),
      6 middle (Standard Chartered), plus last-N variants.
    - ids: as-is (M-Pesa = national ID / passport).
    - dates: 'DD Mon YYYY' or digits -> DDMMYYYY / YYYYMMDD / DDMMYY ...
    """
    out: list[str] = []
    for acc in accounts or []:
        d = re.sub(r"\D", "", acc)
        out.append(acc)
        if d:
            out.append(d)
        if d.isdigit() and len(d) >= 7:
            out += [d[2:12], d[5:12], d[5:11], d[-10:], d[-7:], d[-6:], d[-5:], d[-4:]]
    for i in ids or []:
        out.append(i.strip())
        out.append(re.sub(r"\D", "", i))
    for dt in dates or []:
        out += _date_formats(dt)
    # de-dup, drop empties
    seen, res = set(), []
    for c in out:
        if c and c not in seen:
            seen.add(c)
            res.append(c)
    return res


_MONTHS = {m: i for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], 1)}


def _date_formats(text: str) -> list[str]:
    """Turn '01 Jan 1990' / '01/01/1990' into common password encodings."""
    t = text.lower().replace(",", " ")
    m = re.search(r"(\d{1,2})\D+([a-z]{3,}|\d{1,2})\D+(\d{2,4})", t)
    if not m:
        digits = re.sub(r"\D", "", text)
        return [digits] if digits else []
    d = int(m.group(1))
    mo = _MONTHS.get(m.group(2)[:3], None) or int(m.group(2))
    y = int(m.group(3))
    y4 = y if y > 99 else (1900 + y if y > 30 else 2000 + y)
    y2 = y4 % 100
    return [
        f"{d:02d}{mo:02d}{y4}", f"{y4}{mo:02d}{d:02d}", f"{d:02d}{mo:02d}{y2:02d}",
        f"{mo:02d}{d:02d}{y4}", f"{d:02d}{mo:02d}", f"{y4}",
    ]


def digit_candidates(min_len: int, max_len: int) -> Iterator[str]:
    for length in range(min_len, max_len + 1):
        for n in range(10**length):
            yield f"{n:0{length}d}"


# --------------------------------------------------------------------- cracking


def crack(pdf_bytes: bytes, candidates: Iterable[str]) -> str | None:
    for pw in candidates:
        if verify(pdf_bytes, pw):
            return pw
    return None


_SHARED: bytes | None = None  # per-worker PDF bytes (avoid re-pickling each task)


def _init_worker(pdf_bytes: bytes) -> None:
    global _SHARED
    _SHARED = pdf_bytes


def _try_range(args) -> str | None:
    start, end, length = args
    for n in range(start, end):
        pw = f"{n:0{length}d}"
        if verify(_SHARED, pw):
            return pw
    return None


def brute_digits(
    pdf_bytes: bytes, min_len: int, max_len: int, workers: int = 0
) -> str | None:
    """Parallel numeric brute force across CPU cores."""
    workers = workers or os.cpu_count() or 4
    for length in range(min_len, max_len + 1):
        total = 10**length
        chunk = max(5000, total // (workers * 16) + 1)
        tasks = [(s, min(s + chunk, total), length) for s in range(0, total, chunk)]
        with ProcessPoolExecutor(
            max_workers=workers, initializer=_init_worker, initargs=(pdf_bytes,)
        ) as ex:
            for result in ex.map(_try_range, tasks):
                if result is not None:
                    ex.shutdown(cancel_futures=True)
                    return result
    return None


def unlock_to_bytes(pdf_bytes: bytes, password: str) -> bytes:
    """Return an UNENCRYPTED copy of the PDF (raises on wrong password)."""
    out = io.BytesIO()
    with pikepdf.open(io.BytesIO(pdf_bytes), password=password) as pdf:
        pdf.save(out)  # saving without encryption strips the password
    return out.getvalue()


# ------------------------------------------------------------------------- CLI


def _read(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="pdf_unlocker", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("info", help="show encryption details")
    s.add_argument("pdf")

    s = sub.add_parser("hash", help="emit the $pdf$ hash for hashcat/john")
    s.add_argument("pdf")
    s.add_argument("--label", action="store_true",
                   help="prefix the hash with 'path:' (john colon format)")

    s = sub.add_parser("derive", help="try structure-based candidates")
    s.add_argument("pdf")
    s.add_argument("--account", action="append", default=[])
    s.add_argument("--id", action="append", default=[])
    s.add_argument("--date", action="append", default=[])
    s.add_argument("-o", "--out", help="write unlocked copy here if found")

    s = sub.add_parser("brute", help="parallel numeric brute force")
    s.add_argument("pdf")
    s.add_argument("--min", type=int, default=4)
    s.add_argument("--max", type=int, default=6)
    s.add_argument("--workers", type=int, default=0)
    s.add_argument("-o", "--out")

    s = sub.add_parser("wordlist", help="try passwords from a file")
    s.add_argument("pdf")
    s.add_argument("wordlist")
    s.add_argument("-o", "--out")

    s = sub.add_parser("unlock", help="write an unlocked copy with a known password")
    s.add_argument("pdf")
    s.add_argument("--password", required=True)
    s.add_argument("-o", "--out", required=True)

    args = p.parse_args(argv)
    data = _read(args.pdf)

    if args.cmd == "info":
        for k, v in info(data).items():
            print(f"{k}: {v}")
        return 0

    if args.cmd == "hash":
        try:
            h = pdf_hash(data)
        except ValueError as e:
            print(f"cannot hash {args.pdf}: {e}", file=sys.stderr)
            return 1
        print(f"{args.pdf}:{h}" if args.label else h)
        print(f"hashcat mode: -m {hashcat_mode(data)}", file=sys.stderr)
        return 0

    if args.cmd == "unlock":
        if not verify(data, args.password):
            print("wrong password", file=sys.stderr)
            return 1
        with open(args.out, "wb") as f:
            f.write(unlock_to_bytes(data, args.password))
        print(f"unlocked -> {args.out}")
        return 0

    t0 = time.time()
    if args.cmd == "derive":
        pw = crack(data, derive_candidates(args.account, args.id, args.date))
    elif args.cmd == "brute":
        pw = brute_digits(data, args.min, args.max, args.workers)
    elif args.cmd == "wordlist":
        pw = crack(data, (line.strip() for line in open(args.wordlist)))
    else:
        return 2

    dt = time.time() - t0
    if pw is None:
        print(f"no password found ({dt:.0f}s)")
        return 1
    print(f"FOUND password: {pw}  ({dt:.0f}s)")
    if getattr(args, "out", None):
        with open(args.out, "wb") as f:
            f.write(unlock_to_bytes(data, pw))
        print(f"unlocked -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
