# VeilNet Foundation

> Identity is public. Authority is hidden. Transactions are sealed vessels.

## Overview
VeilNet is a transaction-based protocol where transactions are sealed vessels carrying structured data, tokens, metadata, and instructions.

## Core Concepts

### Public Key (Identity Anchor)
- Stable public identifier
- Owns tokens and transaction history
- Defines identity namespace
- **Does not** authorize transactions

### Seal (Authority Object)
- Private authority object
- Rotatable
- Used to sign transactions
- Never revealed to the network
- Produces deterministic Seal Fingerprint

### Transaction (Sealed Vessel)
- Contains PublicKey reference
- Carries payload (data/tokens/instructions)
- Includes Seal Fingerprint
- Verified by network nodes

## Architecture
