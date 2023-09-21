#In this example, the message is first signed with EdDSA digital signature and then encrypted with ECDH-1PU key wrapping algorithm using key with X25519 elliptic curve and A256CBC-HS512 for content encryption of the message.


from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from os import urandom
from cryptography.hazmat.primitives import padding
import base64
import json

def base64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def sign_message(message_dict, private_key_sign):
    # Convert dict to bytes
    message_bytes = json.dumps(message_dict).encode('utf-8')

    eddsa_private_key = ed25519.Ed25519PrivateKey.generate()
    signature = private_key_sign.sign(message_bytes)

    return message_bytes + signature

def encrypt_jwe(message, recipient_public_key2, kid_value, private_key_sign, private_key_sender):
    # Generate a random CEK for AES encryption
    cek = urandom(32)  # 256 bits for AES-256

    # Sign the message first
    signed_message = sign_message(message, private_key_sign)

    # Pad the signed message
    padder = padding.PKCS7(128).padder()  # 128 bit for AES block size
    padded_signed_message = padder.update(signed_message) + padder.finalize()

    # Use the CEK to encrypt the padded signed message
    iv_msg = urandom(16)
    cipher_msg = Cipher(algorithms.AES(cek), modes.CBC(iv_msg), default_backend()).encryptor()
    ciphertext = cipher_msg.update(padded_signed_message) + cipher_msg.finalize()

    # Generate shared secret
    shared_secret = private_key_sender.exchange(recipient_public_key2)

    # Derive the encryption and HMAC keys for wrapping the CEK
    h_enc = hmac.HMAC(shared_secret, hashes.SHA256(), default_backend())
    h_enc.update(b"key_encryption")
    key_encryption_key = h_enc.finalize()

    # Encrypt the CEK
    iv_cek = urandom(16)
    cipher_cek = Cipher(algorithms.AES(key_encryption_key), modes.CBC(iv_cek), default_backend()).encryptor()
    encrypted_cek = cipher_cek.update(cek) + cipher_cek.finalize()
    encrypted_cek_iv_concat = iv_cek + encrypted_cek

    # Authenticate the ciphertext using HMAC-SHA512
    h = hmac.HMAC(shared_secret, hashes.SHA512(), default_backend())
    h.update(ciphertext)
    auth_tag = h.finalize()

    protected_header = {
        "alg": "ECDH-1PU",
        "enc": "A256CBC-HS512"
    }
    protected = base64url_encode(json.dumps(protected_header).encode('utf-8'))

    jwe = {
        "protected": protected,
        "iv": iv_msg.hex(),
        "ciphertext": ciphertext.hex(),
        "tag": auth_tag.hex(),
        "recipient": [
            {
                "encrypted_key": encrypted_cek_iv_concat.hex(),
                "header": {
                    "kid": kid_value  # Placeholder for the recipient's key ID
                }
            }
        ]
    }
    return jwe

def decrypt_jwe(jwe, recipient_private_key1, sender_public_key1):
    # Derive the shared secret
    shared_secret = recipient_private_key1.exchange(sender_public_key1)

    # Derive the encryption and HMAC keys for unwrapping the CEK
    h_enc = hmac.HMAC(shared_secret, hashes.SHA256(), default_backend())
    h_enc.update(b"key_encryption")
    key_encryption_key = h_enc.finalize()
    encrypted_key_bytes = bytes.fromhex(jwe['recipient'][0]['encrypted_key'])
    iv_cek_dec = encrypted_key_bytes[:16]
    decrypted_cek_bytes = encrypted_key_bytes[16:]

    # Decrypt the CEK
    cipher_cek = Cipher(algorithms.AES(key_encryption_key),
                        modes.CBC(iv_cek_dec),
                        default_backend()).decryptor()
    decrypted_cek = cipher_cek.update(decrypted_cek_bytes) + cipher_cek.finalize()

    # Decrypt the ciphertext
    cipher_msg = Cipher(algorithms.AES(decrypted_cek), modes.CBC(bytes.fromhex(jwe['iv'])),
                        default_backend()).decryptor()
    padded_signed_message = cipher_msg.update(bytes.fromhex(jwe['ciphertext'])) + cipher_msg.finalize()

    # Unpad the signed message
    unpadder = padding.PKCS7(128).unpadder()
    signed_message = unpadder.update(padded_signed_message) + unpadder.finalize()

    return signed_message

def verify_signature(signed_message, eddsa_public_key):
    try:
        original_message = signed_message[:-64]  # Ed25519 signatures are 64 bytes long
        signature = signed_message[-64:]

        # Verify the signature
        eddsa_public_key.verify(signature, original_message)
        return True, original_message
    except Exception as e:
        print("Signature verification failed:", str(e))
        return False, None
