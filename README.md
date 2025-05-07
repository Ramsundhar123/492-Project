# 🔐 Secure Peer-to-Peer Chat Application (492-Project)

## 📖 Overview

This project implements a secure peer-to-peer (P2P) communication system in Java. It demonstrates:

- A full **TCP-like handshake simulation**
- **RSA public-key authentication**
- **Authenticated Diffie-Hellman key exchange**
- **AES-like encryption in CBC mode** (via XOR for simplicity)
- **SHA-256 hashing** for message integrity
- **Replay attack prevention** using timestamps

Developed as part of a computer security course, this project simulates real-world secure communication protocols without relying on third-party libraries.

---

## 🔧 Features

- 🔑 **RSA Authentication**  
  Mutual authentication with digital signatures.

- 🔐 **Diffie-Hellman Key Exchange**  
  Session keys with RSA-bound authentication tokens.

- 🔄 **Symmetric Encryption (CBC)**  
  Custom XOR-based AES simulation with IVs.

- ✅ **Message Integrity**  
  Verified using SHA-256 hashes.

- ⏱️ **Replay Protection**  
  Timestamps guard against message replays.

- 🔁 **Bi-Directional Messaging**  
  Simultaneous send/receive via threads.

---

## 📁 File Structure

| File                  | Description                                                             |
|-----------------------|-------------------------------------------------------------------------|
| `PeerServer.java`     | Server-side peer that waits for connections.                            |
| `PeerClient.java`     | Client-side peer that initiates connection to the server.               |
| `RSA.java`            | Custom RSA algorithm (keygen, encrypt/decrypt, sign/verify).            |
| `AuthenticatedDH.java`| RSA-authenticated Diffie-Hellman key exchange implementation.           |
| `SimpleEncryptor.java`| AES-inspired CBC-mode encryption/decryption and custom SHA-256 hash.    |
| `run_peers.sh`        | Shell script to compile and launch both server and client terminals.    |

---

## 🚀 Running the Application

### ✅ Prerequisites

- Java 8 or later
- Bash-compatible shell (macOS/Linux/WSL/Git Bash)
- Terminal

### ▶️ Quick Start (Script)

```bash
chmod +x run_peers.sh
./run_peers.sh


