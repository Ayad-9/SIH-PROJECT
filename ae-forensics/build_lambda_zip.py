"""
AE-Forensics: Lean Zero-Docker AWS Lambda ZIP Builder
Builds an optimized, production-ready AWS Lambda deployment ZIP (~11 MB) on Windows with precompiled Linux x86_64 binaries.

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
BUILD_DIR = os.path.join(SCRIPT_DIR, "build_lambda_temp")
WHEELS_DIR = os.path.join(SCRIPT_DIR, "temp_linux_wheels")
ZIP_OUTPUT = os.path.join(SCRIPT_DIR, "lambda_function.zip")

def build_zip():
    print("=" * 60)
    print("   AE-Forensics: Optimized AWS Lambda ZIP Packager (~11 MB)   ")
    print("=" * 60)

    # 1. Clean previous build folders
    if os.path.exists(BUILD_DIR):
        shutil.rmtree(BUILD_DIR)
    if os.path.exists(WHEELS_DIR):
        shutil.rmtree(WHEELS_DIR)
    os.makedirs(BUILD_DIR, exist_ok=True)
    os.makedirs(WHEELS_DIR, exist_ok=True)

    # 2. Install base pure-python packages (excluding heavy dev tools & unneeded extras)
    print("\n[1/4] Installing core serverless dependencies...")
    core_pkgs = [
        "fastapi", "mangum", "reportlab", "extract-msg",
        "dkimpy", "dnspython", "python-multipart", "jinja2"
    ]
    subprocess.check_call([
        sys.executable, "-m", "pip", "install",
        *core_pkgs,
        "-t", BUILD_DIR,
        "--no-compile", "--no-deps"
    ])

    sub_deps = [
        "starlette", "pydantic", "anyio", "typing-extensions",
        "annotated-types", "idna", "sniffio", "markupsafe",
        "olefile", "ebcdic", "compressed-rtf", "RTFDE",
        "oletools", "msoffcrypto-tool", "pyparsing"
    ]
    subprocess.check_call([
        sys.executable, "-m", "pip", "install",
        *sub_deps,
        "-t", BUILD_DIR,
        "--no-compile", "--no-deps"
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
    shutil.rmtree(WHEELS_DIR)

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

    # Clean unneeded files and metadata
    for root, dirs, files in list(os.walk(BUILD_DIR, topdown=True)):
        for d in list(dirs):
            if d.endswith(".dist-info") or d == "__pycache__" or d == "bin" or d == "tests":
                shutil.rmtree(os.path.join(root, d), ignore_errors=True)
                dirs.remove(d)

    # 5. Create the Lambda ZIP package
    print("\n[4/4] Creating optimized lambda_function.zip archive...")
    if os.path.exists(ZIP_OUTPUT):
        os.remove(ZIP_OUTPUT)

    with zipfile.ZipFile(ZIP_OUTPUT, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for root, dirs, files in os.walk(BUILD_DIR):
            for file in files:
                if file.endswith(".pyc") or file.endswith(".pyo"):
                    continue
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, BUILD_DIR)
                zf.write(full_path, rel_path)

    # Clean build directory
    shutil.rmtree(BUILD_DIR)

    size_mb = os.path.getsize(ZIP_OUTPUT) / (1024 * 1024)
    print("\n" + "=" * 60)
    print(f" SUCCESS: lambda_function.zip created! ({size_mb:.2f} MB)")
    print(f" File Location: {ZIP_OUTPUT}")
    print(" Ready for direct upload or Amazon S3 upload!")
    print("=" * 60)

if __name__ == "__main__":
    build_zip()
