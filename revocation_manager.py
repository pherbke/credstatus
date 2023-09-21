import traceback
from flask import Flask, request, jsonify
import json
from encryption_decryption_mechanism import encrypt_jwe, sign_message, decrypt_jwe, verify_signature
from cryptography.hazmat.primitives import serialization
from key_utils_rm import private_key1 as rm_private_key
from key_utils_sign import private_key_sign_issuer, public_key_sign_issuer, private_key_sign_rm
from cryptography.hazmat.primitives.asymmetric import x25519
import time
import aiohttp
import logging
import asyncio
import aiofiles
import socket

app = Flask(__name__)

# Setup Logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def send_socket_command(command, key, value=None):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("127.0.0.1", 65432))
        if value:
            s.sendall(f"{command},{key},{value}".encode())
        else:
            s.sendall(f"{command},{key}".encode())
        return s.recv(1024).decode()

async def resolve_did(did_to_resolve):

    AUTH_TOKEN = "Bearer d883dbfc-cb4e-406e-a8c4-b1f97a64a8a7"
    async with aiohttp.ClientSession() as session:
        did_doc = f"https://api.godiddy.com/0.1.0/universal-resolver/identifiers/{did_to_resolve}"
        headers = {
            "Authorization": AUTH_TOKEN,
            "Accept": "application/did+ld+json"
        }
        async with session.get(did_doc, headers=headers) as response:
            if response.status == 200:
                return response.status, await response.json()
            else:
                return response.status, None
async def load_authorized_dids():
    async with aiofiles.open('authorized_dids.txt', mode='r') as f:
        lines = await f.readlines()
    return [line.strip() for line in lines]

@app.route('/receive-message', methods=['POST', 'GET'])
async def receive_message():
    try:
        start_time1 = time.time()
        data = request.get_json()
        logging.info("Received request on /receive-message endpoint")
        logging.info('Revocation Manager received an encrypted message from the Issuer:', data)
        did_to_resolve = "did:web:did-web.godiddy.com:4615929e-c71d-4b2c-b2b3-8e3f6d233ce1"

        status_code, did_document = await resolve_did(did_to_resolve)

        if status_code == 200:
            logging.info(f'Revocation Manager resolves the DID of the Issuer and gets DID document: {did_document}')
            authorized_dids = await load_authorized_dids()
            if did_document.get("id") not in authorized_dids:
                return jsonify({'error': 'Unauthorized DID'}), 403
            logging.info(f'Authorization successful : Issuer is allowed to send a message to the Revocation Manager ')
            service_endpoint = did_document['service'][0]['serviceEndpoint']
            public_key_issuer = did_document['verificationMethod'][0]['publicKeyJwk']['x']
            public_key_issuer_sign = did_document['verificationMethod'][1]['publicKeyJwk']['x']
            kid_rm = did_document['verificationMethod'][0]['id']
            logging.info('Public Key of the Issuer is: {}'.format(public_key_issuer))
            logging.info('Ed25519 Public Key of the Issuer is: {}'.format(public_key_issuer_sign))
            logging.info('Service Endpoint of the Revocation Manager:{}'.format(service_endpoint))

            # decryption using x25519 public key
            key_value = public_key_issuer
            pem_data = f"-----BEGIN PUBLIC KEY-----\n{key_value}\n-----END PUBLIC KEY-----"

            # Convert PEM to X25519PublicKey object
            public_key = serialization.load_pem_public_key(pem_data.encode())
            # Get raw 32 bytes of public key
            raw_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )

            sender_public_key = x25519.X25519PublicKey.from_public_bytes(raw_bytes)

            received_message = decrypt_jwe(data, rm_private_key, sender_public_key)
            logging.info("Revocation Manager decrypts the message:{}".format(received_message))
            key_value_sign = public_key_issuer_sign
            pem_data = f"-----BEGIN PUBLIC KEY-----\n{key_value_sign}\n-----END PUBLIC KEY-----"

            public_key_sign = serialization.load_pem_public_key(pem_data.encode())
            is_verified, original_message = verify_signature(received_message, public_key_sign)
            original_message = json.loads(original_message.decode('utf-8'))
            logging.info("Revocation Manager verifies the signature of the Issuer..")

            if is_verified:
                logging.info("Signature of the Issuer is verified!")
                logging.info('Original message sent by the Issuer is:{}'.format(original_message))
                logging.info('Revocation Manager connects with the DHT and prepares a response ..')

                #connects with kademlia

                original_message1 = json.loads(original_message)
                action = original_message1.get("action", "store")

                if action == "store":
                    key = original_message1["Verifiable Credential id"]
                    value = original_message1["Status of the Credential"]
                    response_content = send_socket_command("set", key, value)

                elif action == "revoke":
                    key = original_message1["Verifiable Credential id"]
                    value = original_message1["Status of the Credential"]
                    response_content = send_socket_command("revoke", key, value)

                elif action == "query_status":

                    key = original_message1["Verifiable Credential id"]

                    response_content = send_socket_command("get", key)

                # Respond to Issuer
                try:

                    logging.info('Response to be sent to the Issuer:{}'.format(response_content))

                    signed_response = sign_message(response_content, private_key_sign_rm)
                    logging.info('Response signed by the Revocation Manager:{}'.format(signed_response))
                    encrypted_response = encrypt_jwe(response_content, sender_public_key, kid_rm, private_key_sign_rm,
                                                     rm_private_key)
                    logging.info('Response encrypted by the Issuer:{}'.format(encrypted_response))

                    async with aiohttp.ClientSession() as session:
                        response = await session.post(service_endpoint,
                                                      data=json.dumps(encrypted_response),
                                                      headers={'Content-Type': 'application/json'})

                    if response.status == 200:
                        logging.debug('Response sent to the Issuer successfully')
                        end_time1 = time.time()
                        latency1 = end_time1 - start_time1
                        logging.info(
                            f"Latency for receiving the message and sending the response to the Issuer is {latency1:.4f} seconds")

                    else:
                        logging.error(f"Failed to send response. Status code: {response.status}")
                except Exception as e:
                    logging.error(f"Error while sending response: {e}")

                return jsonify(response_content), 200


        else:
            return jsonify({'error': 'Invalid data'}), 400

    except Exception as e:
        app.logger.error(f"Exception in /receive-message: {str(e)}")
        traceback.print_exc()  # this will print the stack trace
        return jsonify(error=str(e)), 500


if __name__ == '__main__':
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    app.run(debug=False, port=5000)
