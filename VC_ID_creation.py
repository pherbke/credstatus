import json
import random
import time
from hashlib import sha3_256
import datetime
import os
CREDENTIAL_COUNT = 0
CREDENTIALS_FILE = "credentialsraw.txt"

def store_credential_id(credential_id):
    with open(CREDENTIALS_FILE, "a") as file:
        file.write(credential_id + "\n")

def read_credential_ids():
    if not os.path.exists(CREDENTIALS_FILE):
        return []
    with open(CREDENTIALS_FILE, "r") as file:
        return [line.strip() for line in file.readlines()]

def generate_credential():
    global CREDENTIAL_COUNT
    CREDENTIAL_COUNT = (CREDENTIAL_COUNT % 5) + 1

    # First 2 times: Generate and store credentials
    if CREDENTIAL_COUNT <= 2:
        credential_id = str(int(time.time() * 1000))
        hashed_credential_id = sha3_256(credential_id.encode()).hexdigest()

        status = 'valid'
        current_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())

        current_datetime = datetime.datetime.now()
        try:
            five_years_later = current_datetime.replace(year=current_datetime.year + 5)
        except ValueError:
            five_years_later = current_datetime.replace(year=current_datetime.year + 5, day=current_datetime.day - 1)
        expiry_time = five_years_later.strftime('%Y-%m-%d %H:%M:%S')

        credential_data = {
            'Verifiable Credential id': hashed_credential_id,
            'Status of the Credential': status
        }

        store_credential_id(hashed_credential_id)
        return json.dumps(credential_data)

    # 3rd time: Query the status of the first credential
    elif CREDENTIAL_COUNT == 3:
        existing_credential_ids = read_credential_ids()
        if not existing_credential_ids:
            return json.dumps({"error": "No existing credential IDs found"})
        return json.dumps({
            "action": "query_status",
            "Verifiable Credential id": existing_credential_ids[0]
        })

    # 4th time: Revoke the first credential
    elif CREDENTIAL_COUNT == 4:
        existing_credential_ids = read_credential_ids()
        if not existing_credential_ids:
            return json.dumps({"error": "No existing credential IDs found"})
        return json.dumps({
            "action": "revoke",
            "Verifiable Credential id": existing_credential_ids[0],
            'Status of the Credential': 'invalid'
        })

    # 5th time: Check status of the revoked credential
    elif CREDENTIAL_COUNT == 5:
        existing_credential_ids = read_credential_ids()
        if not existing_credential_ids:
            return json.dumps({"error": "No existing credential IDs found"})
        return json.dumps({
            "action": "query_status",
            "Verifiable Credential id": existing_credential_ids[0]
        })
