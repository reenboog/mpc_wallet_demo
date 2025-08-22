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