"""
Generate a self-signed TLS certificate for pilots / internal use.

    python gen_self_signed_cert.py --host 127.0.0.1 --out ./certs

Produces certs/server.crt (and cert.pem) and certs/server.key (and key.pem).
"""

import argparse
import datetime
import ipaddress
import os

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--out", default="./certs")
    ap.add_argument("--days", type=int, default=825)
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, args.host)])
    now = datetime.datetime.now(datetime.timezone.utc)
    
    san_item = x509.IPAddress(ipaddress.ip_address(args.host)) if args.host.replace('.', '').isdigit() else x509.DNSName(args.host)

    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=args.days))
        .add_extension(x509.SubjectAlternativeName([san_item]), critical=False)
        .sign(key, hashes.SHA256())
    )

    cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
    key_bytes = key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption())

    for crt_name in ["server.crt", "cert.pem"]:
        crt_path = os.path.join(args.out, crt_name)
        with open(crt_path, "wb") as f:
            f.write(cert_bytes)
        os.chmod(crt_path, 0o644)

    for key_name in ["server.key", "key.pem"]:
        key_path = os.path.join(args.out, key_name)
        with open(key_path, "wb") as f:
            f.write(key_bytes)
        os.chmod(key_path, 0o644)

    print(f"Generated certificates in {args.out}: cert.pem / key.pem & server.crt / server.key")


if __name__ == "__main__":
    main()
