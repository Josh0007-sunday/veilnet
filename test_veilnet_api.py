import sys
import os
import requests
from cryptography.hazmat.primitives import serialization
import json # Import json for JSONDecodeError

# Add the project root to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))

from core.identity import PublicKey
from core.seal import Seal
from core.signature import SignatureManager
from core.transaction import Transaction # Import Transaction for model_dump()

BASE_URL = "https://veilnet.vercel.app/api"

def generate_identity_and_seal():
    """Generates a new PublicKey identity and an associated Seal."""
    identity = PublicKey.generate("ed25519")
    seal = Seal.generate()
    
    print(f"Generated Identity Fingerprint: {identity.fingerprint}")
    print(f"Generated Seal Fingerprint: {seal.get_fingerprint()})")
    
    return identity, seal

def register_identity(identity: PublicKey, seal: Seal):
    """Registers the generated identity and seal with the API."""
    register_data = {
        "public_key_pem": identity.key_bytes.decode('utf-8'),
        "public_key_fingerprint": identity.fingerprint,
        "seal_public_key_pem": seal.get_public_key_bytes().decode('utf-8'),
        "seal_fingerprint": seal.get_fingerprint()
    }
    
    print(f"\nAttempting to register identity...")
    response = requests.post(f"{BASE_URL}/register-identity", json=register_data)
    
    print(f"Register Identity Status: {response.status_code}")
    try:
        print(f"Register Identity Response: {response.json()}")
    except json.JSONDecodeError:
        print(f"Register Identity Raw Response (not JSON): {response.text}")
    response.raise_for_status()
    return response.json()

def submit_transaction(identity: PublicKey, seal: Seal, nonce: int, payload_data: dict):
    """Creates and submits a transaction to the API."""
    transaction = SignatureManager.create_signed_transaction(
        public_key_fingerprint=identity.fingerprint,
        seal=seal,
        payload_type="data",
        payload_data=payload_data,
        nonce=nonce
    )
    
    print(f"\nAttempting to submit transaction {transaction.transaction_id} with nonce {nonce}...")
    response = requests.post(f"{BASE_URL}/submit", json=transaction.model_dump())
    
    print(f"Submit Transaction Status: {response.status_code}")
    try:
        print(f"Submit Transaction Response: {response.json()}")
    except json.JSONDecodeError:
        print(f"Submit Transaction Raw Response (not JSON): {response.text}")
    response.raise_for_status()
    return response.json(), transaction.transaction_id

def get_identity_state(identity_fingerprint: str):
    """Retrieves the state of an identity from the API."""
    print(f"\nAttempting to get state for {identity_fingerprint}...")
    response = requests.get(f"{BASE_URL}/state/{identity_fingerprint}")
    
    print(f"Get Identity State Status: {response.status_code}")
    try:
        print(f"Get Identity State Response: {response.json()}")
    except json.JSONDecodeError:
        print(f"Get Identity State Raw Response (not JSON): {response.text}")
    response.raise_for_status()
    return response.json()

def get_transaction_status(transaction_id: str):
    """Retrieves the status of a transaction from the API."""
    print(f"\nAttempting to get status for transaction {transaction_id}...")
    response = requests.get(f"{BASE_URL}/transaction/{transaction_id}")
    
    print(f"Get Transaction Status: {response.status_code}")
    try:
        print(f"Get Transaction Status Response: {response.json()}")
    except json.JSONDecodeError:
        print(f"Get Transaction Status Raw Response (not JSON): {response.text}")
    response.raise_for_status()
    return response.json()

if __name__ == "__main__":
    try:
        # Step 1: Generate Identity and Seal
        identity, seal = generate_identity_and_seal()

        # Step 2: Register Identity
        register_identity(identity, seal)

        # Step 3: Submit a transaction (nonce 0)
        submit_tx_response_0, tx_id_0 = submit_transaction(
            identity, seal, 0, {"message": "Hello VeilNet from Python script!"}
        )
        
        # Step 4: Submit another transaction (nonce 1)
        submit_tx_response_1, tx_id_1 = submit_transaction(
            identity, seal, 1, {"message": "Second message from script!"}
        )

        # Step 5: Get Identity State
        identity_state = get_identity_state(identity.fingerprint)
        assert identity_state["nonce"] == 2 # Expect nonce to be 2 after two transactions

        # Step 6: Get Transaction Status for the first transaction
        tx_status_0 = get_transaction_status(tx_id_0)
        assert tx_status_0["transaction_id"] == tx_id_0
        
        # Step 7: Get Transaction Status for the second transaction
        tx_status_1 = get_transaction_status(tx_id_1)
        assert tx_status_1["transaction_id"] == tx_id_1

        print("\nAll API calls successful!")

    except requests.exceptions.RequestException as e:
        print(f"API request failed: {e}")
        if e.response:
            print(f"Response content: {e.response.text}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")