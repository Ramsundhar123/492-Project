package FinalProject;
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.util.Scanner;
import java.util.Arrays;
import java.util.Date;

/**
 * AuthenticatedPeer represents two peers communicating securely using:
 * - TCP handshake
 * - RSA mutual authentication
 * - Diffie-Hellman for session key generation
 * - Shared session key for encrypted chat with SHA-256 message integrity and replay prevention using timestamps
 */
public class AuthenticatedPeer {

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);

        System.out.println("Choose mode: (1) Listen  (2) Connect");
        int mode = Integer.parseInt(scanner.nextLine());

        Socket socket;

        if (mode == 1) {
            ServerSocket serverSocket = new ServerSocket(5001);
            System.out.println("[Peer 1] Listening on port 5001...");
            socket = serverSocket.accept();
            System.out.println("[Peer 1] Connection accepted.");
        } else {
            System.out.print("Enter IP address to connect: ");
            String ip = scanner.nextLine();
            socket = new Socket(ip, 5001);
            System.out.println("[Peer 2] Connected to " + ip);
        }

        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

        RSA localRSA = new RSA(61, 53, true);
        AuthenticatedDH localDH = new AuthenticatedDH();

        // Send and receive RSA keys
        out.writeObject(Long.toString(localRSA.getPublicKey()));
        out.writeObject(Long.toString(localRSA.getModulus()));
        out.flush();

        long peerPubKey = Long.parseLong((String) in.readObject());
        long peerMod = Long.parseLong((String) in.readObject());
        RSA peerRSA = new RSA(peerPubKey, peerMod);

        // Mutual RSA Authentication
        String challenge = "I am peer";
        long hash = Math.abs(challenge.hashCode()) % localRSA.getModulus();
        long signature = localRSA.signature(hash);
        out.writeObject(challenge);
        out.writeObject(Long.toString(signature));
        out.flush();

        String peerChallenge = (String) in.readObject();
        long peerSignature = Long.parseLong((String) in.readObject());
        long peerHash = Math.abs(peerChallenge.hashCode()) % peerRSA.getModulus();
        boolean peerValid = RSA.verification(peerSignature, peerHash, peerRSA.getPublicKey(), peerRSA.getModulus());

        if (!peerValid) {
            System.out.println("❌ Peer RSA authentication failed. Terminating session.");
            socket.close();
            return;
        }

        System.out.println("✅ Peer RSA authenticated successfully.");

        // Diffie-Hellman key exchange
        out.writeObject(localDH.getPublicKey());
        out.flush();
        BigInteger peerDHPub = (BigInteger) in.readObject();
        BigInteger sessionKey = localDH.computeSharedSecret(peerDHPub);

        // Verify DH exchange with RSA signature
        byte[] authToken = localDH.generateAuthToken(sessionKey, localRSA);
        out.writeObject(authToken);
        out.flush();

        byte[] peerAuthToken = (byte[]) in.readObject();
        boolean verified = localDH.verifyAuthToken(peerAuthToken, peerDHPub, sessionKey, peerRSA);

        if (!verified) {
            System.out.println("❌ DH Authentication failed. Terminating session.");
            socket.close();
            return;
        }

        System.out.println("🔐 Secure session established with shared key.");

        // Store last timestamp to detect replay attacks
        final long[] lastReceivedTimestamp = {0};

        Thread sender = new Thread(() -> {
            try {
                while (true) {
                    String message = scanner.nextLine();
                    String encrypted = SimpleEncryptor.encrypt(message, sessionKey);
                    byte[] hashBytes = SHA256.hash(message.getBytes());
                    long timestamp = System.currentTimeMillis();
                    out.writeObject(encrypted);
                    out.writeObject(hashBytes);
                    out.writeObject(timestamp);
                    out.flush();
                    System.out.println("[You] Sent at " + new Date(timestamp));
                }
            } catch (Exception e) {
                System.out.println("Sender error: " + e.getMessage());
            }
        });

        Thread receiver = new Thread(() -> {
            try {
                while (true) {
                    String encrypted = (String) in.readObject();
                    byte[] receivedHash = (byte[]) in.readObject();
                    long receivedTimestamp = (Long) in.readObject();

                    if (receivedTimestamp <= lastReceivedTimestamp[0]) {
                        System.out.println("⚠️ Replay attack detected. Message rejected.");
                        continue;
                    }

                    String decrypted = SimpleEncryptor.decrypt(encrypted, sessionKey);
                    byte[] computedHash = SHA256.hash(decrypted.getBytes());
                    if (!Arrays.equals(receivedHash, computedHash)) {
                        System.out.println("⚠️ Message integrity check failed. Possible tampering.");
                        continue;
                    }

                    lastReceivedTimestamp[0] = receivedTimestamp;
                    System.out.println("[Peer] " + decrypted + " (Received at " + new Date(receivedTimestamp) + ")");
                }
            } catch (Exception e) {
                System.out.println("Receiver error: " + e.getMessage());
            }
        });

        sender.start();
        receiver.start();

        sender.join();
        receiver.join();

        socket.close();
    }
}





