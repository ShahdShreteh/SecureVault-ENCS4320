from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=3072,
)

name = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "localhost")
])

now = datetime.now(timezone.utc)

certificate = (
    x509.CertificateBuilder()
    .subject_name(name)
    .issuer_name(name)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now)
    .not_valid_after(now + timedelta(days=365))
    .add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ip_address("127.0.0.1")),
        ]),
        critical=False,
    )
    .add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    )
    .sign(key, hashes.SHA256())
)

Path("server.key").write_bytes(
    key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
)

Path("server.crt").write_bytes(
    certificate.public_bytes(serialization.Encoding.PEM)
)

print("Created server.key and server.crt")