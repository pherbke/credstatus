from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# Generate private key
private_key_sign = ed25519.Ed25519PrivateKey.generate()

# Derive public key from private key
public_key_sign = private_key_sign.public_key()

# Serialize private key to PEM format
private_pem = private_key_sign.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Serialize public key to PEM format
public_pem = public_key_sign.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)


# Save the keys to files
with open("private_key_sign_rm.pem", "wb") as f:
    f.write(private_pem)


with open("public_key_sign_rm.pem", "wb") as f:
    f.write(public_pem)