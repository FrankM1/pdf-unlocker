# How to use this tool

This tool opens a locked PDF when the PDF is yours. It guesses the password
for you. Here is how to use it, step by step.

## What you need first

You run the tool with the Python inside the `.venv` folder. Always start by
going into the project folder:

```bash
cd /path/to/pdf-unlocker-experiment
```

If the `.venv` folder is missing, make it once:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

To keep the commands short, save the path to your PDF in a shortcut called `F`:

```bash
F="/path/to/my_statement.pdf"
```

Now every command below can just say `"$F"` instead of the long path.

## Step 1: look at the PDF

This tells you what kind of lock the PDF has.

```bash
.venv/bin/python pdf_unlocker.py info "$F"
```

You do not need to understand the answer. It just confirms the file is locked.

## Step 2: find the password and open it

Pick one of these three. Try them in order.

### A. You know a number (fastest)

If you know the bank account number or your ID number, give it to the tool.
It opens the file right away.

```bash
.venv/bin/python pdf_unlocker.py derive "$F" --account 1234567890123 -o "${F%.pdf}_open.pdf"
.venv/bin/python pdf_unlocker.py derive "$F" --id 12345678 -o "${F%.pdf}_open.pdf"
```

### B. You do not know the password (let it guess)

The tool tries every number until one works. Most bank PINs are 4 digits, so
start there.

```bash
.venv/bin/python pdf_unlocker.py brute "$F" --min 4 --max 4 -o "${F%.pdf}_open.pdf"
```

If that finds nothing, let it try longer numbers:

```bash
.venv/bin/python pdf_unlocker.py brute "$F" --min 4 --max 6 -o "${F%.pdf}_open.pdf"
```

When it works you will see a line like this:

```
FOUND password: 1234  (1s)
unlocked -> /path/to/my_statement_open.pdf
```

### C. You already know the password

Just open it:

```bash
.venv/bin/python pdf_unlocker.py unlock "$F" --password 1234 -o "${F%.pdf}_open.pdf"
```

## Where the open file goes

The `-o` part says where to save the unlocked copy. The examples above save a
new file next to the original, with `_open` added to the name. Your original
locked file is never changed.

## If guessing is too slow

Longer passwords (7 digits or more) take a while with `brute`. For those, use
hashcat, which is much faster. See
[`PDF_ENCRYPTION.md`](PDF_ENCRYPTION.md), section "Going faster with hashcat".

## A full example

```bash
cd /path/to/pdf-unlocker-experiment
F="/path/to/my_statement.pdf"
.venv/bin/python pdf_unlocker.py brute "$F" --min 4 --max 4 -o "${F%.pdf}_open.pdf"
```

That opened the file in about one second. The password was a 4-digit PIN.
