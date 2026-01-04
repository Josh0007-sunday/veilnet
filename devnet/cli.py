"""
CLI tool for interacting with the VeilNet DevNet.
"""
import argparse
import json
import base64
import os
import sys
import requests

# Add project root to Python path to allow absolute imports
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from core.identity import PublicKey
from core.seal import Seal
from core.signature import SignatureManager
from core.transaction import Transaction, TransactionPayload, TransactionType
from core.encryption import PayloadEncryptor

API_BASE_URL = "http://127.0.0.1:8000/api"

def _read_file_content(filepath: str, binary: bool = False) -> str | bytes:
    """Helper to read content from a file."""
    mode = 'rb' if binary else 'r'
    try:
        with open(filepath, mode) as f:
            return f.read()
    except FileNotFoundError:
        print(f"Error: File not found at {filepath}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file {filepath}: {e}", file=sys.stderr)
        sys.exit(1)

def generate_identity_and_seal(args):
    """Generates a new PublicKey and an associated Seal."""
    identity = PublicKey.generate(key_type=args.key_type)
    seal = Seal.generate()

    print("--- New Identity and Seal Generated ---")
    print(f"Public Key Fingerprint: {identity.fingerprint}")
    print(f"Public Key (PEM):")
    print(identity.key_bytes.decode())
    print(f"Seal Fingerprint: {seal.get_fingerprint()}")
    print(f"Seal Public Key (PEM):")
    print(seal.get_public_key_bytes().decode())
    print("\nIMPORTANT: Store the private key for this Seal securely if you wish to reuse it:")
    print(f"Seal Private Key (Base64): {base64.b64encode(seal.export_private()).decode()}")

def register_identity(args):
    """Registers a PublicKey and its initial Seal with the VeilNet node."""
    public_key_pem_content = _read_file_content(args.public_key_pem_file)
    seal_public_key_pem_content = _read_file_content(args.seal_public_key_pem_file)

    payload = {
        "public_key_pem": public_key_pem_content,
        "public_key_fingerprint": args.public_key_fingerprint,
        "seal_public_key_pem": seal_public_key_pem_content,
        "seal_fingerprint": args.seal_fingerprint
    }
    
    try:
        response = requests.post(f"{API_BASE_URL}/register-identity", json=payload)
        response.raise_for_status()
        print("--- Registration Successful ---")
        print(json.dumps(response.json(), indent=2))
    except requests.exceptions.RequestException as e:
        print(f"Error registering identity: {e}", file=sys.stderr)
        if hasattr(e, 'response') and e.response is not None:
            print(f"Server response: {e.response.text}", file=sys.stderr)

def create_transaction(args):
    """Creates a signed transaction."""
    try:
        seal_private_bytes = base64.b64decode(args.seal_private_key_b64)
        seal = Seal.import_private(seal_private_bytes)
    except Exception as e:
        print(f"Error: Invalid Seal Private Key. {e}", file=sys.stderr)
        return

    try:
        payload_data = json.loads(args.payload_data)
    except json.JSONDecodeError:
        print("Error: Invalid JSON for payload-data.", file=sys.stderr)
        return

    payload_type = TransactionType(args.payload_type)

    transaction = SignatureManager.create_signed_transaction(
        public_key_fingerprint=args.public_key_fingerprint,
        seal=seal,
        payload_type=payload_type.value,
        payload_data=payload_data,
        nonce=args.nonce,
        encrypt_payload=args.encrypt
    )
    
    # Custom JSON serialization for bytes in payload
    tx_dump = transaction.model_dump()
    if tx_dump["payload"].get("encrypted_data"):
        tx_dump["payload"]["encrypted_data"] = base64.b64encode(tx_dump["payload"]["encrypted_data"]).decode()

    print("--- Signed Transaction Created ---")
    print(json.dumps(tx_dump, indent=2))
    print("\nTo submit this transaction, save the above JSON to a file (e.g., tx.json) and use curl:")
    print(f"curl -X POST {API_BASE_URL}/submit -H 'Content-Type: application/json' -d @tx.json")

def decode_transaction(args):
    """Decrypts and displays the payload of a transaction."""
    try:
        tx_json = json.loads(_read_file_content(args.transaction_file))
        encrypted_data_b64 = tx_json.get("payload", {}).get("encrypted_data")

        if not encrypted_data_b64:
            print("Error: Transaction does not contain an encrypted payload.", file=sys.stderr)
            # If there's a clear-text 'data' field, show it as a fallback.
            if tx_json.get("payload", {}).get("data"):
                 print("Payload (plaintext):", json.dumps(tx_json["payload"]["data"]))
            return

        encrypted_data = base64.b64decode(encrypted_data_b64)
        
        seal_private_bytes = base64.b64decode(args.seal_private_key_b64)
        
        # Derive the same key that was used for encryption
        encryption_key = PayloadEncryptor.derive_key_from_seal(seal_private_bytes)
        
        decrypted_payload_bytes = PayloadEncryptor.decrypt(encrypted_data, encryption_key)
        
        # Attempt to decode as JSON for pretty printing
        try:
            decrypted_payload = json.loads(decrypted_payload_bytes.decode())
            print("--- Decrypted Payload ---")
            print(json.dumps(decrypted_payload, indent=2))
        except (json.JSONDecodeError, UnicodeDecodeError):
            print("--- Decrypted Payload (raw) ---")
            print(decrypted_payload_bytes)

    except json.JSONDecodeError:
        print("Error: Invalid JSON in transaction file.", file=sys.stderr)
    except (ValueError, TypeError) as e:
        print(f"Error during decryption: {e}", file=sys.stderr)


def create_seal_rotation_transaction(args):
    """Creates a signed seal rotation transaction."""
    try:
        old_seal_private_bytes = base64.b64decode(args.old_seal_private_key_b64)
        old_seal = Seal.import_private(old_seal_private_bytes)
    except Exception as e:
        print(f"Error: Invalid Old Seal Private Key. {e}", file=sys.stderr)
        return
    
    new_seal = Seal.generate()
    rotation_tx = Transaction.create_seal_rotation(
        public_key_fingerprint=args.public_key_fingerprint,
        old_seal=old_seal,
        new_seal=new_seal,
        nonce=args.nonce
    )

    print("--- Signed Seal Rotation Transaction Created ---")
    print(json.dumps(rotation_tx.model_dump(), indent=2))
    print(f"\nNew Seal Fingerprint: {new_seal.get_fingerprint()}")
    print(f"New Seal Public Key (PEM):")
    print(new_seal.get_public_key_bytes().decode())
    print(f"New Seal Private Key (Base64): {base64.b64encode(new_seal.export_private()).decode()}")
    print("\nTo submit this transaction, save the above JSON to a file (e.g., rotation_tx.json) and use curl:")
    print(f"curl -X POST {API_BASE_URL}/submit -H 'Content-Type: application/json' -d @rotation_tx.json")


def main():
    parser = argparse.ArgumentParser(description="VeilNet DevNet CLI tool.")
    subparsers = parser.add_subparsers(dest="command", help="Available commands", required=True)

    parser_gen = subparsers.add_parser("generate", help="Generate a new PublicKey and associated Seal.")
    parser_gen.add_argument("--key-type", type=str, default="ed25519", choices=["ed25519", "rsa"],
                            help="Type of Public Key to generate.")
    parser_gen.set_defaults(func=generate_identity_and_seal)

    parser_register = subparsers.add_parser("register-identity", help="Register a PublicKey and initial Seal with the node.")
    parser_register.add_argument("--public-key-fingerprint", required=True)
    parser_register.add_argument("--public-key-pem-file", required=True)
    parser_register.add_argument("--seal-fingerprint", required=True)
    parser_register.add_argument("--seal-public-key-pem-file", required=True)
    parser_register.set_defaults(func=register_identity)

    parser_create_tx = subparsers.add_parser("create-tx", help="Create a signed transaction.")
    parser_create_tx.add_argument("--public-key-fingerprint", required=True)
    parser_create_tx.add_argument("--seal-private-key-b64", required=True)
    parser_create_tx.add_argument("--payload-type", required=True, choices=[t.value for t in TransactionType])
    parser_create_tx.add_argument("--payload-data", default="{}", help="JSON string of payload data.")
    parser_create_tx.add_argument("--nonce", type=int, required=True)
    parser_create_tx.add_argument("--encrypt", action='store_true', help="Encrypt the payload (only for 'data' type).")
    parser_create_tx.set_defaults(func=create_transaction)

    parser_decode_tx = subparsers.add_parser("decode-tx", help="Decrypt and view a transaction's payload.")
    parser_decode_tx.add_argument("--transaction-file", required=True, help="Path to the transaction JSON file.")
    parser_decode_tx.add_argument("--seal-private-key-b64", required=True, help="Base64 encoded private key of the Seal.")
    parser_decode_tx.set_defaults(func=decode_transaction)

    parser_rotate_seal = subparsers.add_parser("rotate-seal", help="Create a signed seal rotation transaction.")
    parser_rotate_seal.add_argument("--public-key-fingerprint", required=True)
    parser_rotate_seal.add_argument("--old-seal-private-key-b64", required=True)
    parser_rotate_seal.add_argument("--nonce", type=int, required=True)
    parser_rotate_seal.set_defaults(func=create_seal_rotation_transaction)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
