"""
API Routes for VeilNet Node
"""
from fastapi import APIRouter, HTTPException, Body, Depends
from typing import Dict, Any
from pydantic import BaseModel, Field

from core.transaction import Transaction
from storage.db import Database, get_database
from node.validator import Validator
from node.mempool import mempool
from core.identity import PublicKey # Import PublicKey to recreate it from PEM

router = APIRouter()

# Pydantic model for identity registration request
class IdentityRegistrationRequest(BaseModel):
    public_key_pem: str = Field(..., description="PEM encoded public key of the identity")
    public_key_fingerprint: str = Field(..., description="Fingerprint of the public key")
    seal_public_key_pem: str = Field(..., description="PEM encoded public key of the initial seal")
    seal_fingerprint: str = Field(..., description="Fingerprint of the initial seal")


@router.post("/register-identity", status_code=201)
async def register_identity(
    request: IdentityRegistrationRequest,
    db: Database = Depends(get_database)
):
    """
    Registers a new Public Key identity and its initial Seal with the node.
    """
    # 1. Reconstruct PublicKey object and save it
    # Assuming key_type is ed25519 for now, as per design
    # A more robust system would derive key_type from PEM or require it in request
    identity = PublicKey.from_bytes(
        key_bytes=request.public_key_pem.encode(),
        key_type="ed25519" 
    )
    if identity.fingerprint != request.public_key_fingerprint:
        raise HTTPException(
            status_code=400,
            detail="Public key fingerprint mismatch."
        )

    pk_id = db.save_identity(identity)
    if not pk_id:
        raise HTTPException(
            status_code=400,
            detail="Identity already exists or could not be saved."
        )

    # 2. Authorize the initial Seal
    # For now, we trust the provided seal_public_key_pem and fingerprint.
    # In a real system, more checks would be needed (e.g., verifying seal_fingerprint derived from PEM)
    auth_success = db.authorize_seal(
        identity_fingerprint=request.public_key_fingerprint,
        seal_fingerprint=request.seal_fingerprint,
        seal_public_key_bytes=request.seal_public_key_pem.encode()
    )

    if not auth_success:
        raise HTTPException(
            status_code=400,
            detail="Initial seal could not be authorized. It might already exist or identity is invalid."
        )
    
    return {
        "message": "Identity and initial seal registered successfully.",
        "public_key_fingerprint": request.public_key_fingerprint,
        "seal_fingerprint": request.seal_fingerprint
    }


@router.post("/submit", status_code=202)
async def submit_transaction(
    transaction: Transaction,
    db: Database = Depends(get_database)
):
    """
    Accepts, validates, and processes a new transaction, then adds it to the mempool.
    """
    validator = Validator(db)
    if not validator.process_transaction(transaction):
        raise HTTPException(
            status_code=400,
            detail="Transaction processing failed."
        )

    # Add to mempool
    if not mempool.add_transaction(transaction):
        raise HTTPException(
            status_code=409, # Conflict
            detail="Transaction already in mempool."
        )

    # For now, save to DB to keep tests passing.
    success = db.save_transaction(transaction, status="pending")
    if not success:
        raise HTTPException(
            status_code=500,
            detail="Transaction could not be saved to database."
        )
        
    return {
        "message": "Transaction accepted",
        "transaction_id": transaction.transaction_id
    }

@router.get("/state/{identity_fingerprint}")
async def get_identity_state(
    identity_fingerprint: str,
    db: Database = Depends(get_database)
) -> Dict[str, Any]:
    """
    Retrieves the current state for a given public key identity.
    """
    state = db.get_identity_state(identity_fingerprint)
    
    if state is None:
        raise HTTPException(
            status_code=404,
            detail=f"State for identity '{identity_fingerprint}' not found."
        )
        
    return state

@router.get("/transaction/{transaction_id}")
async def get_transaction_status(
    transaction_id: str,
    db: Database = Depends(get_database)
) -> Dict[str, Any]:
    """
    Retrieves the details and status of a specific transaction,
    checking the mempool first, then the database.
    """
    # Check mempool first
    tx = mempool.get_transaction(transaction_id)
    if tx:
        return tx.model_dump()

    # If not in mempool, check database
    tx_data = db.get_transaction(transaction_id)
    if tx_data is None:
        raise HTTPException(
            status_code=404,
            detail=f"Transaction '{transaction_id}' not found."
        )
        
    return tx_data
