from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


with open("private_key_issuer.pem", "rb") as key_file:
    private_key2 = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

private_key_bytes = private_key2.private_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)


# Load the issuer's public key
with open("public_key_issuer.pem", "rb") as key_file:
    public_key_bytes = key_file.read()
    public_key = serialization.load_pem_public_key(public_key_bytes)

# Use the private key bytes and hash it to get a 32-byte key
digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
digest.update(private_key2.private_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
))
key_32_byte = digest.finalize()
