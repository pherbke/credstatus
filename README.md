# DIDCommV2-in-credential-revocation
## Introduction
This repository contains an implementation of DIDComm V2 messaging protocol between an Issuer and an Off-Chain Revocation Manager. The revocation Manager is connected with a Kademlia DHT and the Issuer sends verifiable credential(VC) information to the Revocation Manager following DIDComm V2 messaging protocol. After that, the Revocation Manager stores the VC information into the Kademlia DHT. The issuer also interacts with the Revocation Manager for revoking a VC or checking a status of an existing VC.

## Installation
To install this project, please install Python 3.10, Flask 2.3.3  or higher on your machine. Follow these steps in order to run the project.

1. Clone this repository to your local machine using Git:
git@github.com:Tanzi005/DIDCommV2-in-credential-revocation.git
2. Navigate to the root directory of the cloned repository.
3. Install all of its dependencies and run the following commands:
```
kademliaDHT.py
```
```
revocation_manager.py
```
```
issuer.py
```
4. After you have all these three up and running, make a simple get request.
```
curl http://127.0.0.1:3001/send-message
```
#### Note: Please make sure to run the kademliaDHT.py first before running the flask servers. Also, make sure to have an empty file of credentialsraw.txt when you start the implementation.

## Components

### issuer_key_gen.py
Issuer geneartes x25519 public and private key pair and stores locally as .pem file. After resolving the DID document of the Revocation Manager, Issuer uses the x25519 public key of the Revocation Manager(rm) for encrypting a message. And the Revocation Manager uses it's x25519 private key to decrypt the message.
### rm_key_gen.py
Revocation Manager geneartes x25519 public and private key pair and stores locally as .pem file. After resolving the DID document of the Issuer, Revocation Manager uses the x25519 public key of the Issuer for encrypting a message. And the Issuer uses it's x25519 private key to decrypt the message.
### EdDSA_key_creation_issuer.py
Issuer geneartes EdDSA public and private key pair and stores them locally as .pem file. Issuer uses the EdDSA private key for signing a message digitally. After resolving the DID document of the Revocation Manager, the Issuer uses the EdDSA public key of the Revocation Manager to verify the signature.
### EdDSA_key_creation_rm.py
Revocation Manager geneartes EdDSA public and private key pair and stores locally as .pem file. Revocation Manager uses the EdDSA private key for signing a message digitally. After resolving the DID document of the Issuer, the Revocation Manager uses the EdDSA public key of the Issuer to verify the signature.
### VC_ID_creation.py
This file contains a function for generating random Verifiable Credential ID and status which is further used in the 'issuer.py'  file as message input.
### kademliaDHT.py

#### Description:
This integrates a Kademlia Distributed Hash Table (DHT) with a simple socket server, allowing for distributed key-value storage and retrieval. This is especially useful for decentralized systems that require efficient and fault-tolerant data storage and access mechanisms.

#### Key Features:
1. Kademlia DHT Initialization: The DHT is set up and bootstrapped for data storage and retrieval.
2. Socket Server:
- Listens for incoming connections to interact with the DHT.
- Supports commands:
- set: To store a key-value pair in the DHT.
- revoke: Another way to set a key-value pair, but with a more specific intent to revoke a credential.
- get: To retrieve a value associated with a given key from the DHT.
3. Async Programming: Uses the asyncio library to efficiently manage asynchronous tasks and network I/O operations.
  
#### Setup and Installation:
1. Dependencies: Ensure the following modules and packages are installed:
- kademlia (for the DHT functionalities)
- Python's built-in asyncio and socket libraries for asynchronous operations and socket server setup, respectively.
2. Running the Application:
`python kademliaDHT.py`

This will initialize the Kademlia server and the socket server, waiting for incoming connections.

### issuer.py

#### Description:
This is a Flask application that focuses on establishing a connection with a Revocation Manager using DID (Decentralized Identifier) resolution. The application sends encrypted and signed messages and also processes the responses received.

#### Key Features:
1. DID Resolver: Using an asynchronous function, the app resolves a DID with the help of an external service (e.g., api.godiddy.com). 
2. Send Message Endpoint (/send-message):
- Resolves the DID of the Revocation Manager. The DID documents contains the Public key pairs and the service end point of the Revocation Manager.
- Encrypts and signs a generated message using cryptography primitives.
- Sends the encrypted message to the Revocation Manager's service endpoint.  
3. Receive Response Endpoint (/receive-response):
- Decrypts the response received from the Revocation Manager.
- Verifies the signature of the response.
- Outputs the original message after verification.
  
#### Setup and Installation:
1. Dependencies: Ensure the following modules and packages are installed:
- 'flask'
- 'httpx'
- 'cryptography'
Any other dependencies from the code, such as encryption_decryption_mechanism, key_utils_sign, and VC_ID_creation.

#### Running the Application:
`python issuer.py`

This will start the Flask server on port 3001.

### revocation_manager.py

#### Description:
This Flask-based service handles encrypted messages received from an issuer. It decrypts the messages, verifies their signatures, interacts with a Distributed Hash Table (DHT) based on the action specified, and sends an encrypted response back to the issuer.

#### Key Features:
1. Message Decryption: Uses the x25519 elliptic curve to decrypt JSON Web Encryption (JWE) encrypted messages.
2. Signature Verification: Utilizes EdDSA for message signature verification.
3. DHT Integration: Connects with a Kademlia-based DHT to store, revoke, or query the status of credentials.
4. DID Resolution: Uses the universal resolver to fetch DID documents.
5. Authorization: Checks if the sender's DID is authorized to send messages.
6. Socket Integration: Interacts with another service using sockets for DHT-related operations.
   
#### Dependencies:
1. 'flask': The micro web framework to run the service.
2. 'cryptography': For cryptographic operations, like elliptic curve-based encryption/decryption.
3. 'aiohttp': Asynchronous HTTP client/server framework.
4. 'aiofiles': Asynchronous file reading.
5. Python's built-in libraries like 'json', 'socket', 'asyncio', and 'traceback'.

#### Setup and Usage:
1. Installing Dependencies:
`
pip install flask cryptography aiohttp aiofiles
`
3. Running the Service:
`
python revocation_manager.py
`
This will start the Flask service, listening on port 5000.
4. Endpoint:
- 'POST /receive-message': Send an encrypted message to this endpoint to get it decrypted, verified, and acted upon.

#### Expected Payload:
For the '/receive-message' endpoint, send a 'POST' request with the JSON payload containing the encrypted message.

### encryption_decryption_mechanism.py

This provides a set of cryptographic utilities for secure message handling and protection. Here's a breakdown of the functionalities:

#### Libraries and Dependencies:
- Uses various cryptographic primitives from the cryptography.hazmat library.
- Relies on os.urandom for cryptographically secure random number generation.
- Utilizes base64 for encoding purposes and json for data serialization.

#### Functions:
1. base64url_encode(data):
- Encodes data in a URL-safe base64 format without padding.
2. sign_message(message_dict, private_key_sign):
- Accepts a message in dictionary format and a private key.
- Converts the message to bytes and signs it using the Ed25519 digital signature algorithm.
- Returns the concatenated bytes of the message and its signature.
3. encrypt_jwe(message, recipient_public_key2, kid_value, private_key_sign, private_key_sender):
- Encrypts a JSON Web Encryption (JWE) format message.
- Uses Elliptic Curve Diffie-Hellman (ECDH) for key agreement.
- Encrypts the message using AES in CBC mode with a random Content Encryption Key (CEK).
- Uses HMAC for message authentication.
- Returns a dictionary containing the JWE components.
4. decrypt_jwe(jwe, recipient_private_key1, sender_public_key1):
- Decrypts a given JWE format message.
- Derives the shared secret using ECDH.
- Decrypts the CEK and then uses it to decrypt the actual message content.
- Returns the decrypted message.
5. verify_signature(signed_message, eddsa_public_key):
- Accepts a signed message and an Ed25519 public key.
- Extracts the signature from the message and verifies it using the public key.
- If the verification succeeds, it returns the original message; otherwise, it signals an error.
