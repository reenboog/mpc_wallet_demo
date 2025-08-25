![Rust Build Status](https://github.com/reenboog/mpc_wallet_demo/workflows/Rust/badge.svg)

## Overview

- **Server**: An Axum-based HTTP service that participates in distributed key generation (DKG) and threshold signing.  
- **Client**: A CLI wallet for interacting with the server.  
- **Crypto**:  
  - Feldman’s DKG is used to distribute secret shares securely.  
  - FROST-style threshold signatures are used to collaboratively produce Ed25519 signatures.  
  - The client’s private share is encrypted locally using Argon2id key derivation and AEAD.  

## Running the Server

```bash
cargo run -p api
```

The server listens on `0.0.0.0:8081` and exposes:

- `POST /signup` – generate a new key via a DKG ceremony  
- `POST /sign/commit` – start a signing flow  
- `POST /sign/final` – finalize the signing flow  
- `DELETE /delete/{key_id}` – delete a stored share  

## Usage

### 1. Initialize a new key

```bash
cargo run -p cli -- -p mypass init
```

- Runs DKG with the server.  
- Stores the local private share encrypted with Argon2 (using `mypass`).  
- Prints the generated key ID (base64).  

### 2. Sign a message (using the `key_id` from step 1)

```bash
cargo run -p cli -- -p mypass sign -k <key_id> -m "hello world"
```

- Generates nonces and exchanges commitments with the server.  
- Combines client and server partials into a valid Ed25519 signature.  
- Verifies and prints the signature.  

### 3. Delete a key

```bash
cargo run -p cli -- -p mypass delete -k <key_id>
```

- Deletes the local encrypted bundle.  
- Removes the corresponding key share from the server.

## Notes

The underlying math is universal enough to support any t-of-n scheme (see tests). The only difference would be a more complex distribution flow, which is not the purpose of this demo: shares should be end-to-end encrypted (encrypting each one to the recipient's public key would suffice), and a WebSocket connection might be the preferred way to handle transport.

The client-side CLI always initiates and finalizes the signing process. In practice, you might want to store participants’ transaction history on the backend. Moreover, since you still need to broadcast the transactions to the main net, whether it’s 1-of-1 or a generic t-of-n scheme, it may be preferable for the server to finalize the flow.

Re-sharing is not implemented, nor is inviting new peers, though the building blocks already exist in the math module, so adding this functionality would not be much work.

In a real-world scenario, anything that touches the server should obviously be authenticated with at least MFA (I introduced a deletion token just to highlight that I am aware of the context).