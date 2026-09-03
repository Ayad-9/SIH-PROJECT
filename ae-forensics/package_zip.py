"""
AE-Forensics: AWS Lambda Zip Packager
Creates a clean, production-ready lambda_deploy.zip with source code and dependencies.
Usage:
    python package_zip.py
"""

import os
import sys
import shutil
import zipfile
import subprocess

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BUILD_DIR = os.path.join(SCRIPT_DIR, "build_lambda")
ZIP_OUTPUT = os.path.join(SCRIPT_DIR, "lambda_deploy.zip")

def package():
    print("[1/4] Preparing clean build directory...")
    if os.path.exists(BUILD_DIR):
        shutil.rmtree(BUILD_DIR)
    os.makedirs(BUILD_DIR)

    print("[2/4] Installing dependencies to package target...")
    req_file = os.path.join(SCRIPT_DIR, "requirements.txt")
    cmd = [
        sys.executable, "-m", "pip", "install",
        "-r", req_file,
        "-t", BUILD_DIR,
        "--no-compile"
    ]
    subprocess.check_call(cmd)

    print("[3/4] Copying AE-Forensics application code...")
    for item in ["main.py", "database.py"]:
        src = os.path.join(SCRIPT_DIR, item)
        dst = os.path.join(BUILD_DIR, item)
        if os.path.exists(src):
            shutil.copy2(src, dst)

    for folder in ["core", "services", "templates"]:
        src = os.path.join(SCRIPT_DIR, folder)
        dst = os.path.join(BUILD_DIR, folder)
        if os.path.exists(src):
            shutil.copytree(src, dst, dirs_exist_ok=True)

    print("[4/4] Creating zip archive lambda_deploy.zip...")
    if os.path.exists(ZIP_OUTPUT):
        os.remove(ZIP_OUTPUT)

    with zipfile.ZipFile(ZIP_OUTPUT, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(BUILD_DIR):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, BUILD_DIR)
                # Skip unnecessary caches
                if "__pycache__" in rel_path or rel_path.endswith(".pyc"):
                    continue
                zf.write(full_path, rel_path)

    zip_size_mb = os.path.getsize(ZIP_OUTPUT) / (1024 * 1024)
    print(f"DONE: Package created successfully at: {ZIP_OUTPUT} ({zip_size_mb:.2f} MB)")
    print("Ready to upload to AWS Lambda Console!")

if __name__ == "__main__":
    package()
