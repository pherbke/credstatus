from flask import Flask, request, jsonify
import httpx
import json
import time
from encryption_decryption_mechanism import encrypt_jwe, sign_message, decrypt_jwe, verify_signature
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from key_utils_sign import private_key_sign_issuer, public_key_sign_issuer
from VC_ID_creation import generate_credential
from key_utils_issuer import public_key, private_key2, private_key_bytes



app = Flask(__name__)


async def resolve_did(did_to_resolve):
    AUTH_TOKEN = "Bearer d883dbfc-cb4e-406e-a8c4-b1f97a64a8a7"
    did_doc = f"https://api.godiddy.com/0.1.0/universal-resolver/identifiers/{did_to_resolve}"
    headers = {
        "Authorization": AUTH_TOKEN,
        "Accept": "application/did+ld+json"
    }
    async with httpx.AsyncClient() as client:
        response = await client.get(did_doc, headers=headers)
        if response.status_code == 200:
            return response.status_code, response.json()
        else:
            return response.status_code, None


@app.route('/send-message', methods=['GET', 'POST'])
async def receive_message_get():
    start_time = time.time()
    print('Issuer wants to establish a connection with the Revocation Manager..')
    status_code, did_document = await resolve_did("did:web:did-web.godiddy.com:f06deae6-572f-4af5-bf13-4b5f622c1342")
    with open('did_document.txt', 'w') as file:
        file.write(json.dumps(did_document, indent=4))

    if status_code == 200:
        print(f'Issuer resolves the DID of the Revocation Manager and gets the DID document: {did_document}')
        service_endpoint = did_document['service'][0]['serviceEndpoint']
        print('Service Endpoint of the Revocation Manager:', service_endpoint)
        public_key_revocation_manager = did_document['verificationMethod'][0]['publicKeyJwk']['x']
        public_key_revocation_manager_sign = did_document['verificationMethod'][1]['publicKeyJwk']['x']
        kid_rm = did_document['verificationMethod'][0]['id']
        print('kid of the Revocation Manager is:', kid_rm)
        print('Public Key of the Revocation Manager is:', public_key_revocation_manager)
        print('Ed25519 Public Key of the Revocation Manager is:', public_key_revocation_manager_sign)

        key_value = public_key_revocation_manager
        pem_data = f"-----BEGIN PUBLIC KEY-----\n{key_value}\n-----END PUBLIC KEY-----"
        # Convert PEM to X25519PublicKey object
        public_key = serialization.load_pem_public_key(pem_data.encode())
        # Get raw 32 bytes of public key
        raw_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        recipient_public_key = x25519.X25519PublicKey.from_public_bytes(raw_bytes)
        message = generate_credential()
        print('Message to be sent by the Issuer to the Revocation Manager:', message)
        signed = sign_message(message, private_key_sign_issuer)
        print('Message signed by the Issuer:', signed)
        encrypted = encrypt_jwe(message, recipient_public_key, kid_rm, private_key_sign_issuer, private_key2)
        print('Message encrypted by the Issuer:', encrypted)

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(service_endpoint, data=json.dumps(encrypted),
                                             headers={'Content-Type': 'application/json'}, timeout=30.0)

            if response.status_code == 200 and response.headers.get('Content-Type') == 'application/json':
                end_time = time.time()
                latency = end_time - start_time
                print(f"Latency for sending the message is {latency:.4f} seconds")
                return jsonify({'message': 'Message sent to the Revocation Manager successfully'})

            else:
                print(f"Unexpected status code {response.status_code} or Content-Type {response.headers.get('Content-Type')}.")
        except Exception as e:
            print(f"Error while sending the message: {e}")
            print("Exception type:", type(e).__name__)



    else:
        print(f"Request failed with status code {status_code}")
        return jsonify({'message': 'Error occurred'})

@app.route('/receive-response', methods=['POST'])
async def receive_response():
    start_time1 = time.time()
    data = request.get_json()
    print('Issuer received a response from the Revocation Manager:', data)
    with open('did_document.txt', 'r') as file:
        content = file.read()
    # Parse the content to get a dictionary
    did_data = json.loads(content)
    public_key_revocation_manager = did_data['verificationMethod'][0]['publicKeyJwk']['x']
    public_key_revocation_manager_sign = did_data['verificationMethod'][1]['publicKeyJwk']['x']
    kid_rm = did_data['verificationMethod'][0]['id']
    key_value = public_key_revocation_manager
    pem_data = f"-----BEGIN PUBLIC KEY-----\n{key_value}\n-----END PUBLIC KEY-----"

    # Convert PEM to X25519PublicKey object
    public_key = serialization.load_pem_public_key(pem_data.encode())
    # Get raw 32 bytes of public key
    raw_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    rm_public_key = x25519.X25519PublicKey.from_public_bytes(raw_bytes)

    response = decrypt_jwe(data, private_key2, rm_public_key)
    print("Issuer decrypts the response:", response)
    key_value_sign = public_key_revocation_manager_sign
    pem_data = f"-----BEGIN PUBLIC KEY-----\n{key_value_sign}\n-----END PUBLIC KEY-----"
    public_key_sign = serialization.load_pem_public_key(pem_data.encode())
    is_verified, original_message = verify_signature(response, public_key_sign)
    original_message = json.loads(original_message.decode('utf-8'))
    print("Issuer verifies the signature of the Revocation Manager..")
    if is_verified:
        print("Signature of the Revocation Manager is verified!")
        print('Original response sent by the Revocation Manager is:', original_message)
    end_time1 = time.time()
    latency1 = end_time1 - start_time1
    print(f"Latency for receiving the response is {latency1:.4f} seconds")

    return jsonify({'message': 'Response received by the Issuer successfully'})

if __name__ == '__main__':
    app.run(debug=True, port=3001)
