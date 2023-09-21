from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Load the private key
with open("private_key_rm.pem", "rb") as key_file:
    private_key1 = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

# Hash the private key bytes (unusual but feasible)
digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
digest.update(private_key1.private_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
))
key_32_byte = digest.finalize()

# Load the public key
with open("public_key_rm.pem", "rb") as key_file:
    public_key1 = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )
