"""
D4 - Signed Update Packages
Step 1: Generate Ed25519 key pair.
Run once. Keep private_key.pem secret.
"""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption
)

def generate_keys():
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        ))

    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        ))

    print("[OK] private_key.pem generated.")
    print("[OK] public_key.pem generated.")
    print("[!!] Never commit private_key.pem to GitHub.")

if __name__ == "__main__":
    generate_keys()