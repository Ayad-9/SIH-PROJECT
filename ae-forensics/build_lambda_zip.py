"""
AE-Forensics: Linux-Pure AWS Lambda ZIP Builder
Builds a production-ready AWS Lambda deployment ZIP on Windows with precompiled Linux x86_64 binaries.
Removes all Windows .pyd binaries and unneeded dev files to prevent Lambda 502/ImportErrors.

Usage:
    python build_lambda_zip.py
"""

import os
import sys
import glob
import shutil
import zipfile
import subprocess

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BUILD_DIR = os.path.join(SCRIPT_DIR, "build_linux_pkg")
WHEELS_DIR = os.path.join(SCRIPT_DIR, "temp_wheels_dir")
ZIP_OUTPUT = os.path.join(SCRIPT_DIR, "lambda_function.zip")

def build_zip():
    print("=" * 65)
    print("   AE-Forensics: Linux-Pure AWS Lambda ZIP Packager   ")
    print("=" * 65)

    # 1. Clean previous build folders
    if os.path.exists(BUILD_DIR):
        shutil.rmtree(BUILD_DIR, ignore_errors=True)
    if os.path.exists(WHEELS_DIR):
        shutil.rmtree(WHEELS_DIR, ignore_errors=True)
    os.makedirs(BUILD_DIR, exist_ok=True)
    os.makedirs(WHEELS_DIR, exist_ok=True)

    # 2. Install base pure-python packages
    print("\n[1/4] Installing pure Python serverless dependencies...")
    pure_reqs = [
        "fastapi", "mangum", "reportlab", "dkimpy", "dnspython", "python-multipart", "jinja2"
    ]
    subprocess.check_call([
        sys.executable, "-m", "pip", "install",
        *pure_reqs,
        "-t", BUILD_DIR,
        "--no-compile"
    ])

    # 3. Download Linux x86_64 binaries for native dependencies
    print("\n[2/4] Downloading Amazon Linux 64-bit native binary wheels...")
    linux_native_pkgs = ["cryptography", "cffi", "pydantic-core", "pycparser"]
    subprocess.check_call([
        sys.executable, "-m", "pip", "download",
        *linux_native_pkgs,
        "--platform", "manylinux2014_x86_64",
        "--implementation", "cp",
        "--python-version", "3.11",
        "--only-binary=:all:",
        "-d", WHEELS_DIR
    ])

    # Extract Linux wheels over the build directory
    for whl in glob.glob(os.path.join(WHEELS_DIR, "*.whl")):
        print(f"  -> Unpacking Linux binary wheel: {os.path.basename(whl)}")
        with zipfile.ZipFile(whl, "r") as z:
            z.extractall(BUILD_DIR)
    shutil.rmtree(WHEELS_DIR, ignore_errors=True)

    # 4. Copy AE-Forensics application source files
    print("\n[3/4] Copying AE-Forensics application source code...")
    for f in ["main.py", "database.py", "lambda_function.py"]:
        src = os.path.join(SCRIPT_DIR, f)
        dst = os.path.join(BUILD_DIR, f)
        if os.path.exists(src):
            shutil.copy2(src, dst)

    for d in ["core", "services", "templates"]:
        src = os.path.join(SCRIPT_DIR, d)
        dst = os.path.join(BUILD_DIR, d)
        if os.path.exists(src):
            shutil.copytree(src, dst, dirs_exist_ok=True)

    # Clean Windows .pyd binaries and unneeded dev files
    print("\n[4/4] Purging Windows .pyd binaries, caches, and unused files...")
    for root, dirs, files in list(os.walk(BUILD_DIR, topdown=False)):
        for f in files:
            if f.endswith(".pyd") or f.endswith(".pyc") or f.endswith(".pyo"):
                try:
                    os.remove(os.path.join(root, f))
                except Exception:
                    pass
        for d in dirs:
            if d.endswith(".dist-info") or d == "__pycache__" or d == "bin" or d == "tests" or d == "PIL":
                shutil.rmtree(os.path.join(root, d), ignore_errors=True)

    # 5. Create the Lambda ZIP package
    print("  -> Creating clean lambda_function.zip archive...")
    if os.path.exists(ZIP_OUTPUT):
        os.remove(ZIP_OUTPUT)

    with zipfile.ZipFile(ZIP_OUTPUT, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for root, dirs, files in os.walk(BUILD_DIR):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, BUILD_DIR)
                zf.write(full_path, rel_path)

    # Clean build directory
    shutil.rmtree(BUILD_DIR, ignore_errors=True)

    # Verify zip integrity
    zf_check = zipfile.ZipFile(ZIP_OUTPUT, "r")
    pyds = [n for n in zf_check.namelist() if n.endswith(".pyd")]
    sos = [n for n in zf_check.namelist() if n.endswith(".so")]
    size_mb = os.path.getsize(ZIP_OUTPUT) / (1024 * 1024)

    print("\n" + "=" * 65)
    print(f" SUCCESS: lambda_function.zip created! ({size_mb:.2f} MB)")
    print(f" File Location: {ZIP_OUTPUT}")
    print(f" - Windows .pyd binaries: {len(pyds)} (Zero Windows conflicts)")
    print(f" - Linux .so binaries:    {len(sos)} (Amazon Linux x86_64 ready)")
    for s in sos:
        print(f"   * {s}")
    print("=" * 65)

if __name__ == "__main__":
    build_zip()
