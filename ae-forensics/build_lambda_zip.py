"""
AE-Forensics: Zero-Docker AWS Lambda ZIP Builder
Builds a production-ready AWS Lambda deployment ZIP on Windows with precompiled Linux x86_64 binaries.

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
    print("   AE-Forensics: Zero-Docker AWS Lambda ZIP Packager   ")
    print("=" * 60)

    # 1. Clean previous build folders
    if os.path.exists(BUILD_DIR):
        shutil.rmtree(BUILD_DIR)
    if os.path.exists(WHEELS_DIR):
        shutil.rmtree(WHEELS_DIR)
    os.makedirs(BUILD_DIR, exist_ok=True)
    os.makedirs(WHEELS_DIR, exist_ok=True)

    # 2. Install base pure-python packages
    print("\n[1/4] Installing Python base dependencies...")
    req_file = os.path.join(SCRIPT_DIR, "requirements.txt")
    subprocess.check_call([
        sys.executable, "-m", "pip", "install",
        "-r", req_file,
        "-t", BUILD_DIR,
        "--no-compile"
    ])

    # 3. Download Linux x86_64 binaries for native dependencies
    print("\n[2/4] Downloading Amazon Linux 64-bit native binary wheels...")
    linux_native_pkgs = ["cryptography", "cffi", "pydantic-core", "pillow"]
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

    # 5. Create the Lambda ZIP package
    print("\n[4/4] Creating lambda_function.zip archive...")
    if os.path.exists(ZIP_OUTPUT):
        os.remove(ZIP_OUTPUT)

    with zipfile.ZipFile(ZIP_OUTPUT, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(BUILD_DIR):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, BUILD_DIR)
                if "__pycache__" in rel_path or rel_path.endswith(".pyc"):
                    continue
                zf.write(full_path, rel_path)

    # Clean build directory
    shutil.rmtree(BUILD_DIR)

    size_mb = os.path.getsize(ZIP_OUTPUT) / (1024 * 1024)
    print("\n" + "=" * 60)
    print(f" SUCCESS: lambda_function.zip created! ({size_mb:.2f} MB)")
    print(f" File Location: {ZIP_OUTPUT}")
    print(" Ready to upload directly to the AWS Lambda Console!")
    print("=" * 60)

if __name__ == "__main__":
    build_zip()
