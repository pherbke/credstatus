from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

# Generate private key
private_key = x25519.X25519PrivateKey.generate()

# Derive the public key from the private key
public_key = private_key.public_key()

# Serialize private key to PEM format
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Serialize public key to PEM format
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Save the keys to files
with open("private_key_issuer.pem", "wb") as f:
    f.write(private_pem)


with open("public_key_issuer.pem", "wb") as f:
    f.write(public_pem)


print("Keys generated and saved!")
