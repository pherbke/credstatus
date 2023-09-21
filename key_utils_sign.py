from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


#issuer

with open("private_key_sign_issuer.pem", "rb") as key_file:
    private_key_sign_issuer = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

private_key_bytes_sign_issuer = private_key_sign_issuer.private_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)


# Load the issuer's public key
with open("public_key_sign_issuer.pem", "rb") as key_file:
    public_key_bytes = key_file.read()
    public_key_sign_issuer = serialization.load_pem_public_key(public_key_bytes)


#revocation manager

with open("private_key_sign_rm.pem", "rb") as key_file:
    private_key_sign_rm = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

private_key_bytes_sign_rm = private_key_sign_rm.private_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)


# Load the issuer's public key
with open("public_key_sign_rm.pem", "rb") as key_file:
    public_key_bytes = key_file.read()
    public_key_sign_rm = serialization.load_pem_public_key(public_key_bytes)
