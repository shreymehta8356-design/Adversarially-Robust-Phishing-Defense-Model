#!/usr/bin/env python3
"""One command to get PhishGuard running.

    python start.py

That is the whole thing. This script checks your Python, creates a private
environment, installs what is needed, trains a model if there isn't one, and
opens the console in your browser.

It is deliberately written in old, boring Python with no imports beyond the
standard library, so that it runs on whatever interpreter you happen to have
and can tell you *why* if something is wrong -- including "your Python is too
old", which a modern script would not survive long enough to say.
"""

import os
import platform
import shutil
import subprocess
import sys
import time
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV = ROOT / ".venv"
MIN_PYTHON = (3, 10)

IS_WINDOWS = platform.system() == "Windows"
BIN = VENV / ("Scripts" if IS_WINDOWS else "bin")
PYTHON = BIN / ("python.exe" if IS_WINDOWS else "python")
PHISHGUARD = BIN / ("phishguard.exe" if IS_WINDOWS else "phishguard")

# Colour only when the terminal is a real one that will render it.
_COLOUR = sys.stdout.isatty() and not IS_WINDOWS
G = "\033[32m" if _COLOUR else ""
Y = "\033[33m" if _COLOUR else ""
R = "\033[31m" if _COLOUR else ""
B = "\033[1m" if _COLOUR else ""
X = "\033[0m" if _COLOUR else ""

STEPS = 5


def head(n, text):
    print("\n%s[%d/%d] %s%s" % (B, n, STEPS, text, X))


def ok(text):
    print("      %sok%s  %s" % (G, X, text))


def warn(text):
    print("      %s!%s   %s" % (Y, X, text))


def die(problem, fix):
    print("\n%sStopped: %s%s" % (R, problem, X))
    print("\nHow to fix it:\n  %s\n" % fix)
    sys.exit(1)


def run(cmd, why, quiet=True):
    """Run a command; on failure show its output and stop with advice."""
    try:
        result = subprocess.run(
            [str(c) for c in cmd],
            cwd=str(ROOT),
            stdout=subprocess.PIPE if quiet else None,
            stderr=subprocess.STDOUT if quiet else None,
            text=True,
        )
    except OSError as exc:
        die("could not run %s (%s)" % (cmd[0], exc), why)
    if result.returncode != 0:
        if quiet and result.stdout:
            print("\n--- output ---")
            print(result.stdout.strip()[-2500:])
            print("--- end ---")
        die("the previous command failed", why)
    return result


# --------------------------------------------------------------------------
def step_1_check_python():
    head(1, "Checking your Python")
    version = sys.version_info
    printable = "%d.%d.%d" % (version[0], version[1], version[2])
    if version < MIN_PYTHON:
        die(
            "this project needs Python %d.%d or newer, and you are running %s"
            % (MIN_PYTHON[0], MIN_PYTHON[1], printable),
            "Install a newer Python from https://www.python.org/downloads/ and\n"
            "  then run this script again with it, for example:\n"
            "      python3.12 start.py",
        )
    ok("Python %s" % printable)
    ok("%s %s" % (platform.system(), platform.machine()))


def step_2_create_environment():
    head(2, "Creating a private environment (.venv)")
    if PYTHON.exists():
        ok("already exists, reusing it")
        return
    print("      this keeps the project's packages separate from your system Python")
    try:
        venv.EnvBuilder(with_pip=True, clear=False).create(str(VENV))
    except Exception as exc:
        die(
            "could not create the environment (%s)" % exc,
            "On Debian or Ubuntu you may need:\n"
            "      sudo apt install python3-venv\n"
            "  Then run this script again.",
        )
    if not PYTHON.exists():
        die(
            "the environment was created but has no Python in it",
            "Delete the .venv folder and run this script again.",
        )
    ok("created at %s" % VENV)


def step_3_install():
    head(3, "Installing PhishGuard and what it needs")
    print("      first time only, and it needs the internet (about a minute)")
    run(
        [PYTHON, "-m", "pip", "install", "--upgrade", "pip", "--quiet"],
        "Check that you are online. If you are behind a proxy, set the\n"
        "  HTTPS_PROXY environment variable and try again.",
    )
    run(
        [PYTHON, "-m", "pip", "install", "-e", ".", "--quiet"],
        "The install failed and its output is above. The most common causes are\n"
        "  no internet connection, or a Python that is too old.\n"
        "  If you are offline, connect and run this script again.",
    )
    ok("installed")


def step_4_check_and_train():
    head(4, "Checking this machine can run it")
    result = subprocess.run(
        [str(PHISHGUARD), "doctor"], cwd=str(ROOT),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    output = result.stdout or ""
    for line in output.splitlines():
        if "[FAIL]" in line or "[WARN]" in line:
            print("      " + line.strip())
    if result.returncode != 0:
        print(output)
        die(
            "this machine is missing something PhishGuard needs",
            "The FAIL lines above say what, and each one names the command that\n"
            "  fixes it. Fix those, then run this script again.",
        )
    ok("environment is good")

    has_model = (ROOT / "artifacts" / "models" / "current").exists()
    if has_model:
        ok("a trained model is already here, skipping training")
        return

    print("\n      No model yet, so one is being trained now.")
    print("      This runs once and takes about %s1 to 3 minutes%s." % (B, X))
    print("      Nothing is downloaded; the training data is generated locally.\n")
    started = time.time()
    run(
        [PHISHGUARD, "train", "--n", "9000", "--save"],
        "Training failed and its output is above.\n"
        "  If it mentions memory, try:  .venv/bin/phishguard train --n 4000 --save",
        quiet=False,
    )
    ok("model trained in %d seconds" % int(time.time() - started))


def step_5_serve():
    head(5, "Starting the server")
    url = "http://localhost:8000"
    print("""
      %sOpen this in your browser:%s   %s%s%s

      Paste this key into the box at the top right:

          %sdev-admin-key-change-me%s

      Then pick an example from the dropdown and press "Assess message".

      Press %sCtrl+C%s here when you want to stop the server.
""" % (B, X, B, url, X, B, X, B, X))

    # Give the server a moment to bind, then open a browser if there is one.
    if os.environ.get("PG_NO_BROWSER") != "1":
        try:
            import threading
            import webbrowser

            threading.Timer(3.0, lambda: webbrowser.open(url)).start()
        except Exception:
            pass

    try:
        subprocess.run([str(PHISHGUARD), "serve"], cwd=str(ROOT))
    except KeyboardInterrupt:
        print("\n\nServer stopped. Run 'python start.py' again whenever you need it.\n")


def main():
    print("""
%s================================================================%s
 PhishGuard - Adversarially Robust Phishing Defense
 Capstone BAI-17
%s================================================================%s

 This script does everything for you. It is safe to run again at
 any time; it skips whatever is already done.
""" % (B, X, B, X))

    if not (ROOT / "pyproject.toml").exists():
        die(
            "this script is not in the project folder",
            "Move start.py into the phishguard folder (the one containing\n"
            "  pyproject.toml) and run it from there.",
        )

    step_1_check_python()
    step_2_create_environment()
    step_3_install()
    step_4_check_and_train()
    step_5_serve()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nCancelled. Nothing was broken; run 'python start.py' again.\n")
        sys.exit(130)
