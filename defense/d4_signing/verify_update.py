"""
D4 - Signed Update Packages
Step 3: Verify a config file's signature before loading.
Usage: python verify_update.py config.json
"""

import sys
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature

def verify_file(file_path: str, key_path: str = "public_key.pem"):
    with open(file_path, "rb") as f:
        data = f.read()

    sig_path = file_path + ".sig"
    try:
        with open(sig_path, "rb") as f:
            signature = f.read()
    except FileNotFoundError:
        print(f"[FAIL] Signature file '{sig_path}' not found.")
        sys.exit(1)

    with open(key_path, "rb") as f:
        public_key = load_pem_public_key(f.read())

    try:
        public_key.verify(signature, data)
        print(f"[OK] Signature valid. '{file_path}' is authentic.")
        print("[OK] Safe to load configuration.")
    except InvalidSignature:
        print(f"[FAIL] Signature INVALID. '{file_path}' has been tampered with.")
        print("[FAIL] Configuration rejected.")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python verify_update.py <file>")
        sys.exit(1)
    verify_file(sys.argv[1])