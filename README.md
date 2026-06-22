# PLDM Parser

A Python parser for **PLDM** (Platform Level Data Model, DSP0240/DSP0248) frames
transported over **MCTP** (DSP0236), with optional support for the Intel
OOB-MSM / sideband transport prefix used in Intel platforms.

## References

- DMTF DSP0240 — PLDM Base Specification
- DMTF DSP0245 — PLDM IDs and Codes
- DMTF DSP0248 — PLDM for Platform Monitoring and Control
- DMTF DSP0236 — MCTP Base Specification
- Intel OOB-MSM PLDM documentation

## Features

- Decodes the Intel sideband transport prefix (12 bytes), MCTP transport header,
  MCTP message type, PLDM common header, and PLDM payload.
- Distinguishes PLDM **requests** vs **responses** automatically.
- Decodes the PLDM Platform `GetPDR` (0x51) command and response, including
  the common PDR header.
- Decodes the **Terminus Locator PDR** (Type 1) body.
- Tolerant input: accepts `:`, ` `, `-`, `,`, newlines, and `0x` prefixes.

## Layout

```
pldm_parser/
  __init__.py
  hexutil.py         # hex stream tokenizer / BitReader
  transport.py       # Intel sideband prefix
  mctp.py            # MCTP transport header + message type
  pldm.py            # PLDM common header (request/response)
  pdr.py             # PDR header + Terminus Locator PDR
  pldm_platform.py   # Platform commands (GetPDR request/response)
  parser.py          # Top-level frame parser
  cli.py             # `python -m pldm_parser` CLI
tests/
  test_parser.py
```

## Usage

### Graphical app (recommended)

Double-click [run_app.bat](run_app.bat) on Windows, or:

```bash
python run_app.py
```

The window has:
- a left **input panel** (paste hex, supports `:` / spaces / `-` / `,` / newlines),
- a **toolbar** with Intel-prefix mode (auto / force on / force off) and a Parse button,
- a right results area with a **structured tree** tab and a **text report** tab,
- menu items to load examples, open hex files, and save the report.

Keyboard: `Ctrl+Enter` parses, `Ctrl+O` opens a file, `Ctrl+S` saves the report.

### Command line

```bash
python -m pldm_parser "72:00:10:05:00:41:30:7F:00:40:1A:B4:01:09:11:C8:01:88:02:51:00:00:00:00:00:00:00:00:01:50:00:00:00"
```

### Tests

```bash
python -m pytest -q
```

## Build a Windows .exe

A standalone Windows executable can be built with [PyInstaller](https://pyinstaller.org).
Two convenience entry points are provided:

### One-click

Double-click [build_exe.bat](build_exe.bat). It installs PyInstaller if needed,
cleans previous build output, and produces a single-file GUI executable at
`dist/PLDM_Parser.exe`.

### Manual

```bash
python build_exe.py                 # single-file GUI exe -> dist/PLDM_Parser.exe
python build_exe.py --onedir        # one-folder bundle  -> dist/PLDM_Parser/
python build_exe.py --console       # keep a console window for debugging
python build_exe.py --icon path\to\app.ico
python build_exe.py --clean         # wipe build/ and dist/ first
```

Or use the spec file directly:

```bash
pip install pyinstaller
pyinstaller PLDM_Parser.spec
```

The resulting `.exe` is fully self-contained — no Python installation required
on the target machine.

