"""
Generate a self-signed TLS certificate for pilots / internal use.

    python gen_self_signed_cert.py --host iam-sentinel.internal --out ./certs

Produces certs/server.crt and certs/server.key. Point the app at them:
    TLS_CERT_FILE=./certs/server.crt
    TLS_KEY_FILE=./certs/server.key

For production, use a cert from your internal CA / ACME instead of self-signed.
"""

import argparse
import datetime
import os

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="localhost")
    ap.add_argument("--out", default="./certs")
    ap.add_argument("--days", type=int, default=825)
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, args.host)])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=args.days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(args.host)]), critical=False)
        .sign(key, hashes.SHA256())
    )

    crt_path = os.path.join(args.out, "server.crt")
    key_path = os.path.join(args.out, "server.key")
    with open(crt_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption()))
    os.chmod(key_path, 0o600)
    print(f"Wrote {crt_path}\nWrote {key_path}\nSet TLS_CERT_FILE / TLS_KEY_FILE to these paths.")


if __name__ == "__main__":
    main()
