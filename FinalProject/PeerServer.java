package FinalProject;

// Libraries to be imported
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.util.Arrays;
import java.util.Date;
import java.util.Scanner;

public class PeerServer { // Entry point of the server side encryption

    public static void main(String[] args) throws Exception { // Main method

        // Simulate Server Sequence number in a TCP handshake
        var seqB = (int) (Math.random() * Integer.MAX_VALUE); // Generate a random sequence number
        System.out.println("[TCP] SYN-ACK: SEQ b = " + seqB);

        var serverSocket = new ServerSocket(5001); // Listening on port 5001
        System.out.println("[TCP] Waiting for incoming connection (SYN)...");
        Socket socket = serverSocket.accept(); // Accept an incoming TCP connection
        System.out.println("[TCP] Connection accepted. ACK received from client. Handshake complete.");

        // Set up object I/O streams for data exchange for user input
        var out = new ObjectOutputStream(socket.getOutputStream());
        var in = new ObjectInputStream(socket.getInputStream());

        Scanner scanner = new Scanner(System.in); // User input via scanner

        var localRSA = new RSA(61, 53, true); // Create a new RSA key pair
        AuthenticatedDH localDH = new AuthenticatedDH(); // Initialize DH key exchange

        // RSA Key Exchange (Public key and Modulus to Peer)
        System.out.println("[RSA] Sending my public key and modulus...");
        out.writeObject(Long.toString(localRSA.getPublicKey()));
        out.writeObject(Long.toString(localRSA.getModulus()));
        out.flush();

        // Receive and store peer RSA public key and Modulus
        System.out.println("[RSA] Receiving peer's public key and modulus...");
        var peerPubKey = Long.parseLong((String) in.readObject());
        var peerMod = Long.parseLong((String) in.readObject());
        var peerRSA = new RSA(peerPubKey, peerMod);
        System.out.println("[RSA] Peer Public Key: " + peerPubKey + ", Modulus: " + peerMod);

        // Send challenge and signature
        String challenge = "I am server";
        var hash = Math.abs(challenge.hashCode()) % localRSA.getModulus(); // Hash the key
        var signature = localRSA.signature(hash); // Sign with server private key

        // Send challenge and signature to the client
        out.writeObject(challenge);
        out.writeObject(Long.toString(signature));
        out.flush();
        System.out.println("[RSA] Sent challenge: \"" + challenge + "\", hash: " + hash + ", signature: " + signature);

        // Receive challenge and re-hashes client challenge message
        var peerChallenge = (String) in.readObject();
        var peerSignature = Long.parseLong((String) in.readObject());
        var peerHash = Math.abs(peerChallenge.hashCode()) % peerRSA.getModulus();
        System.out.println("[RSA] Received challenge: \"" + peerChallenge + "\"");
        System.out.println("[RSA] Signature received: " + peerSignature);
        System.out.println("[RSA] Computed hash: " + peerHash);

        var valid = RSA.verification(peerSignature, peerHash, peerRSA.getPublicKey(), peerRSA.getModulus()); // Varify client-signature using their RSA public key
        System.out.println("[RSA] Authentication " + (valid ? "✅ SUCCESS" : "❌ FAILED"));

        if (!valid) { // Terminate connection if authentication fails
            socket.close(); // Close socket
            return;
        }

        // Send Server's DH public key
        var myDHPub = localDH.getPublicKey();
        System.out.println("[DH] My DH Public Key: " + myDHPub);
        out.writeObject(myDHPub);
        out.flush();

        // Receive Client's DH public key
        System.out.println("[DH] Waiting for peer's DH public key...");
        var peerDHPub = (BigInteger) in.readObject();
        System.out.println("[DH] Peer DH Public Key: " + peerDHPub);

        // Compute Shared Secret key using Server's private DH key and Client's public DH key
        var sessionKey = localDH.computeSharedSecret(peerDHPub);
        System.out.println("[DH] \uD83D\uDD10 Shared Secret Key Established: " + sessionKey);

        // Send a signed DH authentication token (DH public key + shared secret)
        System.out.println("[DH] Sending my authentication token...");
        var authToken = localDH.generateAuthToken(sessionKey, localRSA);
        out.writeObject(authToken);
        out.flush();

        // Receive client-authentication token using their RSA key
        System.out.println("[DH] Waiting for peer authentication token...");
        var peerAuthToken = (byte[]) in.readObject();

        var verified = localDH.verifyAuthToken(peerAuthToken, peerDHPub, sessionKey, peerRSA); // Verify client authentication token
        System.out.println("[DH] Token Verification: " + (verified ? "✅ SUCCESS" : "❌ FAILED"));
        if (!verified) { // Terminate if authentication fails
            socket.close();
            return;
        }

        // Confirm session setup and initializes last timestamp for replay protection
        System.out.println("[🔐] Secure session fully established!");
        final long[] lastTimestamp = {0};

        new Thread(() -> { // Sender thread
            try {
                while (true) {

                    String message = scanner.nextLine(); // User input

                    String encrypted = SimpleEncryptor.encrypt(message, sessionKey); // Encrypt the shared key
                    System.out.println("[Encrypt] Message: \"" + message + "\"");
                    System.out.println("[Encrypt] Encrypted (hex): " + encrypted);

                    var hashBytes = SHA256.computeHash(message.getBytes()); // Compute SHA-256 hash for integrity
                    var timestamp = System.currentTimeMillis(); // Current timestamp

                    // Send encrypted message, hash and timestamp to peer
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

        new Thread(() -> { // Receiver Thread
            try {
                while (true) {

                    String encrypted = (String) in.readObject(); // Read incoming encrypted message
                    var receivedHash = (byte[]) in.readObject(); // Read hash
                    var timestamp = (Long) in.readObject(); // Read timestamp

                    if (timestamp <= lastTimestamp[0]) { // Check for replay attacks
                        System.out.println("⚠️ Replay attack detected. Discarded message.");
                        continue;
                    }

                    System.out.println("[Decrypt] Received Encrypted (hex): " + encrypted);
                    var decrypted = SimpleEncryptor.decrypt(encrypted, sessionKey); // Decrypt message
                    System.out.println("[Decrypt] Decrypted Message: \"" + decrypted + "\"");
                    var computedHash = SHA256.computeHash(decrypted.getBytes()); // Recompute hash

                    if (!Arrays.equals(receivedHash, computedHash)) { // Check validity of hash
                        System.out.println("⚠️ Integrity check failed. Message tampered.");
                        continue;
                    }

                    lastTimestamp[0] = timestamp; // Store timestamp
                    System.out.println("[Peer] " + decrypted + " (Received at " + new Date(timestamp) + ")");
                }

            } catch (Exception e) {
                System.out.println("Receiver error: " + e.getMessage());
            }
        }).start();
    }
}


