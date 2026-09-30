"""
Creates a tiny PKI in ./certs :

    ca            - the trusted Certificate Authority (self-signed root)
    server        - CN=localhost, EKU=serverAuth, signed by ca
    alice, bob    - EKU=clientAuth, signed by ca                 (legit users)
    mallory       - looks like it was issued by our CA, but was signed by an
                    EVIL CA that copied our CA's name          (forged -> must be rejected)
    olduser       - properly signed by ca but already EXPIRED  (must be rejected)
"""
import datetime
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

OUT = "certs"
NOW = datetime.datetime.now(datetime.timezone.utc)


def new_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def name(cn):
    return x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MiniTLS Lab"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def build(subject_cn, pub, issuer_name, issuer_key, *, is_ca=False, eku=None, san=None,
          not_before=None, not_after=None):
    nb = not_before or NOW - datetime.timedelta(minutes=1)
    na = not_after or NOW + datetime.timedelta(days=365)
    b = (x509.CertificateBuilder()
         .subject_name(name(subject_cn)).issuer_name(issuer_name)
         .public_key(pub).serial_number(x509.random_serial_number())
         .not_valid_before(nb).not_valid_after(na)
         .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
         .add_extension(x509.KeyUsage(digital_signature=not is_ca, key_cert_sign=is_ca, crl_sign=is_ca,
                                      content_commitment=False, key_encipherment=False, data_encipherment=False,
                                      key_agreement=False, encipher_only=False, decipher_only=False), critical=True))
    if eku:
        b = b.add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
    if san:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(d) for d in san]), critical=False)
    return b.sign(issuer_key, hashes.SHA256())


def save(basename, key, cert):
    with open(f"{OUT}/{basename}.key", "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    os.chmod(f"{OUT}/{basename}.key", 0o600)
    with open(f"{OUT}/{basename}.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"  created {OUT}/{basename}.crt / .key   subject={cert.subject.rfc4514_string()}")


def main():
    os.makedirs(OUT, exist_ok=True)
    print("Generating RSA-2048 keys and certificates (takes a few seconds)…")

    ca_key = new_key()
    ca_name = name("MiniTLS Root CA")
    ca_cert = build("MiniTLS Root CA", ca_key.public_key(), ca_name, ca_key, is_ca=True,
                    not_after=NOW + datetime.timedelta(days=3650))
    save("ca", ca_key, ca_cert)
    # The CA private key is only needed here, to sign; a real CA would keep it offline.

    k = new_key()
    save("server", k, build("localhost", k.public_key(), ca_name, ca_key,
                            eku=ExtendedKeyUsageOID.SERVER_AUTH, san=["localhost"]))

    for user in ("alice", "bob"):
        k = new_key()
        save(user, k, build(user, k.public_key(), ca_name, ca_key, eku=ExtendedKeyUsageOID.CLIENT_AUTH))

    # expired but genuinely signed
    k = new_key()
    save("olduser", k, build("olduser", k.public_key(), ca_name, ca_key, eku=ExtendedKeyUsageOID.CLIENT_AUTH,
                             not_before=NOW - datetime.timedelta(days=400),
                             not_after=NOW - datetime.timedelta(days=35)))

    # forged: an attacker's CA that uses the SAME distinguished name as ours
    evil_key = new_key()
    k = new_key()
    save("mallory", k, build("mallory", k.public_key(), ca_name, evil_key, eku=ExtendedKeyUsageOID.CLIENT_AUTH))

    print("Done.")


if __name__ == "__main__":
    main()
