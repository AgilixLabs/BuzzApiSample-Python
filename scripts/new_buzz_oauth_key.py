#!/usr/bin/env python3
"""Generate an RSA key pair for Buzz OAuth 2.0 authentication.

Usage:
    python scripts/new_buzz_oauth_key.py [--out DIR] [--bits N]

Outputs:
    private_key.pem  — RSA private key  (keep secret; never commit to source control)
    public_key.pem   — RSA public key   (register with register_buzz_oauth_key.py)

Requires the `cryptography` package (see requirements.txt).  No OpenSSL needed.

SECURITY
    Add private_key.pem to .gitignore immediately.  Store the private key in a
    secrets manager (HashiCorp Vault, AWS/Azure/GCP secret managers) for production.
"""

from __future__ import annotations

import argparse
import os
import stat
import sys
from typing import Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

MIN_BITS = 2048


def generate_key_pair(out_dir: str = ".", bits: int = MIN_BITS,
                      overwrite: bool = False) -> Tuple[str, str]:
    """Generate an RSA key pair; write private_key.pem (0600) and public_key.pem.

    Returns absolute paths ``(private_key_path, public_key_path)``.
    """
    if bits < MIN_BITS:
        raise ValueError(f"Key size must be at least {MIN_BITS} bits (Buzz minimum).")

    os.makedirs(out_dir, exist_ok=True)
    priv_path = os.path.abspath(os.path.join(out_dir, "private_key.pem"))
    pub_path = os.path.abspath(os.path.join(out_dir, "public_key.pem"))

    if not overwrite and (os.path.exists(priv_path) or os.path.exists(pub_path)):
        raise FileExistsError(f"Key file(s) already exist in {out_dir}.")

    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)

    priv_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # SubjectPublicKeyInfo (SPKI) PEM — the format Buzz expects.
    pub_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    _write_private(priv_path, priv_pem)
    with open(pub_path, "wb") as fh:
        fh.write(pub_pem)

    return priv_path, pub_path


def _write_private(path: str, data: bytes) -> None:
    """Write a private key with owner-only permissions from the start."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    try:  # best effort on platforms that honour it
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Generate an RSA key pair for Buzz OAuth 2.0.")
    parser.add_argument("-o", "--out", default=".", help="Output directory (default: current directory)")
    parser.add_argument("-b", "--bits", type=int, default=MIN_BITS,
                        help=f"RSA key size in bits (default/minimum: {MIN_BITS})")
    parser.add_argument("-f", "--force", action="store_true", help="Overwrite existing key files")
    args = parser.parse_args(argv)

    if not args.force and os.path.exists(os.path.join(args.out, "private_key.pem")):
        if input("Key files already exist and will be overwritten.  Continue? [y/N] ").strip().lower()[:1] != "y":
            print("Aborted.")
            return 0
        args.force = True

    try:
        priv_path, pub_path = generate_key_pair(args.out, args.bits, overwrite=args.force)
    except (ValueError, FileExistsError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    print(f"\nRSA key pair generated ({args.bits} bits):")
    print(f"  Private key : {priv_path}")
    print(f"  Public key  : {pub_path}")
    print("\nNext step: register the public key with Buzz.")
    print("  python scripts/register_buzz_oauth_key.py \\")
    print("      -s https://backgroundapi.agilixbuzz.com -u <userid> -k <kid> -p public_key.pem")
    print("\nIMPORTANT: Never commit private_key.pem to source control.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
