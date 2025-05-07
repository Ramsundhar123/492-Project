# 🔐 Secure Peer-to-Peer Chat Application

## Overview

This Java-based project implements a secure peer-to-peer (P2P) chat application. It features:

- **Simulated TCP handshake**
- **RSA-based mutual authentication**
- **Authenticated Diffie-Hellman key exchange**
- **Custom AES-like CBC encryption**
- **SHA-256 for message integrity**
- **Replay attack detection using timestamps**

The application models real-world secure communication protocols and cryptography principles, making it ideal for learning and demonstrating secure messaging over untrusted networks.

---

## 🔧 Features

- **RSA Authentication**: Exchange and verify public keys with digital signatures.
- **Diffie-Hellman Key Exchange**: Secure session key agreement with authentication tokens.
- **Custom CBC Encryption**: AES-inspired symmetric encryption using XOR.
- **SHA-256 Integrity**: Ensures messages have not been altered.
- **Replay Protection**: Uses timestamps to detect and block replayed messages.
- **Full-duplex Communication**: Bi-directional encrypted chat.

---

## 📁 File Structure

| File                  | Description                                                             |
|-----------------------|-------------------------------------------------------------------------|
| `PeerServer.java`     | Listens for incoming connections, acts as the server peer.              |
| `PeerClient.java`     | Connects to the server peer and initiates the handshake.                |
| `RSA.java`            | RSA key generation, encryption, decryption, and signature verification. |
| `AuthenticatedDH.java`| Authenticated Diffie-Hellman implementation with RSA-based tokens.      |
| `SimpleEncryptor.java`| CBC-mode encryption and decryption using XOR and SHA-256.               |
| `run_peers.sh`        | Bash script to launch both server and client.                           |

---

## 🚀 Getting Started

### Prerequisites

- Java 8 or higher
- Terminal or command line
- Git (optional)

### Compilation

```bash
javac FinalProject/*.java
