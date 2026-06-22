"""Build a Windows .exe of the PLDM Parser GUI using PyInstaller.

Usage:
    python build_exe.py            # one-file GUI exe in ./dist/PLDM_Parser.exe
    python build_exe.py --onedir   # one-folder distribution in ./dist/PLDM_Parser/
    python build_exe.py --console  # keep a console window (useful for debugging)
    python build_exe.py --clean    # remove build artifacts first

Requires PyInstaller; installed automatically if missing.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
APP_NAME = "PLDM_Parser"
ENTRYPOINT = ROOT / "run_app.py"


def _ensure_pyinstaller() -> None:
    try:
        import PyInstaller  # noqa: F401
        return
    except ImportError:
        pass
    print("PyInstaller not found -- installing...")
    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", "--upgrade", "pyinstaller"]
    )


def _clean() -> None:
    for sub in ("build", "dist"):
        target = ROOT / sub
        if target.exists():
            print(f"  removing {target}")
            shutil.rmtree(target, ignore_errors=True)
    spec_garbage = ROOT / f"{APP_NAME}.spec.bak"
    if spec_garbage.exists():
        spec_garbage.unlink()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Build PLDM Parser .exe")
    p.add_argument("--onedir", action="store_true",
                   help="Produce a one-folder bundle instead of a single-file exe.")
    p.add_argument("--console", action="store_true",
                   help="Keep the console window (useful for debugging).")
    p.add_argument("--clean", action="store_true",
                   help="Delete build/ and dist/ before building.")
    p.add_argument("--icon", default=None,
                   help="Path to an .ico file to use as the app icon.")
    args = p.parse_args(argv)

    if args.clean:
        print("Cleaning previous build artifacts...")
        _clean()

    _ensure_pyinstaller()

    cmd: list[str] = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--name", APP_NAME,
        "--onedir" if args.onedir else "--onefile",
        "--console" if args.console else "--windowed",
    ]

    if args.icon:
        icon_path = Path(args.icon).resolve()
        if not icon_path.is_file():
            print(f"ERROR: icon file not found: {icon_path}", file=sys.stderr)
            return 2
        cmd += ["--icon", str(icon_path)]

    cmd.append(str(ENTRYPOINT))

    print("Running:")
    print(" ", " ".join(f'"{c}"' if " " in c else c for c in cmd))
    print()

    rc = subprocess.call(cmd, cwd=str(ROOT))
    if rc != 0:
        print(f"\nBuild failed with exit code {rc}.", file=sys.stderr)
        return rc

    out = ROOT / "dist" / (f"{APP_NAME}.exe" if not args.onedir else APP_NAME)
    print(f"\nBuild complete -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
