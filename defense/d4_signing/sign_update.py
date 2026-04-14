"""
D4 - Signed Update Packages
Step 2: Sign a config file with the private key.
Usage: python sign_update.py config.json
"""

import sys
from cryptography.hazmat.primitives.serialization import load_pem_private_key

def sign_file(file_path: str, key_path: str = "private_key.pem"):
    with open(file_path, "rb") as f:
        data = f.read()

    with open(key_path, "rb") as f:
        private_key = load_pem_private_key(f.read(), password=None)

    signature = private_key.sign(data)

    sig_path = file_path + ".sig"
    with open(sig_path, "wb") as f:
        f.write(signature)

    print(f"[OK] Signed '{file_path}'")
    print(f"[OK] Signature saved to '{sig_path}'")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python sign_update.py <file>")
        sys.exit(1)
    sign_file(sys.argv[1])