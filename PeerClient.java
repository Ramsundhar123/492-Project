package FinalProject;

import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.util.Arrays;
import java.util.Date;
import java.util.Scanner;

public class PeerClient { // Client Class

    public static void main(String[] args) throws Exception { // Main method

        var scanner = new Scanner(System.in); // User input
        System.out.print("Enter server IP: ");
        var ip = scanner.nextLine(); // IP address to server

        // Simulate TCP SYN packet
        var seqA = (int) (Math.random() * Integer.MAX_VALUE); // Random sequence number
        System.out.println("[TCP] SYN: SEQ a = " + seqA);

        var socket = new Socket(ip, 5001); // Establish TCP connection to the server
        System.out.println("[TCP] Received SYN-ACK from server.");
        System.out.println("[TCP] Sent final ACK. TCP handshake completed.");

        // Create output and input streams for object-based communication
        var out = new ObjectOutputStream(socket.getOutputStream()); // Output stream
        var in = new ObjectInputStream(socket.getInputStream()); // Input stream

        var localRSA = new RSA(59, 67, true); // RSA key pair
        var localDH = new AuthenticatedDH(); // Diffie-Hellman key pair

        // Receive and store Server RSA public key and modulus
        System.out.println("[RSA] Waiting for server's public key and modulus...");
        var peerPubKey = Long.parseLong((String) in.readObject());
        var peerMod = Long.parseLong((String) in.readObject());
        var peerRSA = new RSA(peerPubKey, peerMod);
        System.out.println("[RSA] Server Public Key: " + peerPubKey + ", Modulus: " + peerMod);

        // Send client's RSA public key and modulus
        System.out.println("[RSA] Sending my public key and modulus...");
        out.writeObject(Long.toString(localRSA.getPublicKey()));
        out.writeObject(Long.toString(localRSA.getModulus()));
        out.flush();

        // Receive server's challenge and signature
        String peerChallenge = (String) in.readObject();
        var peerSignature = Long.parseLong((String) in.readObject()); // Signature
        var peerHash = Math.abs(peerChallenge.hashCode()) % peerRSA.getModulus(); // Hash

        System.out.println("[RSA] Received challenge: \"" + peerChallenge + "\"");
        System.out.println("[RSA] Signature received: " + peerSignature);
        System.out.println("[RSA] Computed hash: " + peerHash);

        var valid = RSA.verification(peerSignature, peerHash, peerRSA.getPublicKey(), peerRSA.getModulus()); // Verify server signature
        System.out.println("[RSA] Authentication " + (valid ? "✅ SUCCESS" : "❌ FAILED"));
        if (!valid) { // Check validity
            socket.close();
            return;
        }

        // Send client challenge and signature
        var challenge = "I am client";
        var hash = Math.abs(challenge.hashCode()) % localRSA.getModulus();
        var signature = localRSA.signature(hash);
        out.writeObject(challenge);
        out.writeObject(Long.toString(signature));
        out.flush();
        System.out.println("[RSA] Sent challenge: \"" + challenge + "\", hash: " + hash + ", signature: " + signature);

        // Receive server Diffie-Hellman public key
        System.out.println("[DH] Waiting for server's DH public key...");
        var peerDHPub = (BigInteger) in.readObject();
        System.out.println("[DH] Server DH Public Key: " + peerDHPub);

        // Send client's DH public key
        var myDHPub = localDH.getPublicKey();
        System.out.println("[DH] Sending my DH public key: " + myDHPub);
        out.writeObject(myDHPub);
        out.flush();

        var sessionKey = localDH.computeSharedSecret(peerDHPub); // Compute shared session key from server’s DH public key
        System.out.println("[DH] \uD83D\uDD10 Shared Secret Key Established: " + sessionKey);

        System.out.println("[DH] Waiting for server's authentication token...");
        var peerAuthToken = (byte[]) in.readObject(); // Receive server’s authentication token (signed DH data)

        System.out.println("[DH] Sending my authentication token...");
        var authToken = localDH.generateAuthToken(sessionKey, localRSA); // Send client authentication token
        out.writeObject(authToken);
        out.flush();

        var verified = localDH.verifyAuthToken(peerAuthToken, peerDHPub, sessionKey, peerRSA); // Verify server’s DH authentication token
        System.out.println("[DH] Token Verification: " + (verified ? "✅ SUCCESS" : "❌ FAILED"));
        if (!verified) { // Check validity
            socket.close();
            return;
        }
        System.out.println("[🔐] Secure session fully established!");

        final long[] lastTimestamp = {0}; // Store last message timestamp to detect replays

        new Thread(() -> { // Sender thread
            try {
                while (true) {

                    var message = scanner.nextLine(); // Read message from user input

                    // Encrypt message using AES-like CBC with shared session key
                    var encrypted = SimpleEncryptor.encrypt(message, sessionKey);
                    System.out.println("[Encrypt] Message: \"" + message + "\"");
                    System.out.println("[Encrypt] Encrypted (hex): " + encrypted);


                    var hashBytes = SHA256.computeHash(message.getBytes()); // Compute SHA-256 hash for message integrity
                    var timestamp = System.currentTimeMillis(); // Get current timestamp for replay protection

                    // Send encrypted message, hash, and timestamp
                    out.writeObject(encrypted);
                    out.writeObject(hashBytes);
                    out.writeObject(timestamp);
                    out.flush();
                    System.out.println("[You] Sent at " + new Date(timestamp));
                }

            } catch (Exception e) {
                System.out.println("Sender error: " + e.getMessage());
            }
        }).start();

        new Thread(() -> { // Receiver thread
            try {
                while (true) {

                    var encrypted = (String) in.readObject();// Read incoming encrypted message
                    var receivedHash = (byte[]) in.readObject(); // Read incoming encrypted hash
                    var timestamp = (Long) in.readObject(); // Read incoming timestamp

                    if (timestamp <= lastTimestamp[0]) { // Check for replay attacks
                        System.out.println("⚠️ Replay attack detected. Discarded message.");
                        continue;
                    }

                    System.out.println("[Decrypt] Received Encrypted (hex): " + encrypted);

                    // Decrypt message using session key
                    var decrypted = SimpleEncryptor.decrypt(encrypted, sessionKey);
                    System.out.println("[Decrypt] Decrypted Message: \"" + decrypted + "\"");

                    var computedHash = SHA256.computeHash(decrypted.getBytes()); // Verify integrity by recomputing SHA-256 hash

                    if (!Arrays.equals(receivedHash, computedHash)) { // Compare received hash with computed one
                        System.out.println("⚠️ Integrity check failed. Message tampered.");
                        continue;
                    }

                    lastTimestamp[0] = timestamp; // Update timestamp and display message
                    System.out.println("[Peer] " + decrypted + " (Received at " + new Date(timestamp) + ")");
                }

            } catch (Exception e) {
                System.out.println("Receiver error: " + e.getMessage());
            }
        }).start();
    }
}


