package FinalProject;

import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.util.Arrays;
import java.util.Date;
import java.util.Scanner;

public class PeerClient {
    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter server IP: ");
        String ip = scanner.nextLine();
        Socket socket = new Socket(ip, 5001);
        System.out.println("[TCP] Three-way handshake completed with server.");

        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

        RSA localRSA = new RSA(59, 67, true);
        AuthenticatedDH localDH = new AuthenticatedDH();

        long peerPubKey = Long.parseLong((String) in.readObject());
        long peerMod = Long.parseLong((String) in.readObject());
        RSA peerRSA = new RSA(peerPubKey, peerMod);

        out.writeObject(Long.toString(localRSA.getPublicKey()));
        out.writeObject(Long.toString(localRSA.getModulus()));
        out.flush();

        String peerChallenge = (String) in.readObject();
        long peerSignature = Long.parseLong((String) in.readObject());
        long peerHash = Math.abs(peerChallenge.hashCode()) % peerRSA.getModulus();

        System.out.println("[RSA] Received challenge: \"" + peerChallenge + "\"");
        System.out.println("[RSA] Signature received: " + peerSignature);
        System.out.println("[RSA] Computed hash: " + peerHash);

        if (!RSA.verification(peerSignature, peerHash, peerRSA.getPublicKey(), peerRSA.getModulus())) {
            System.out.println("[RSA] ❌ RSA authentication failed.");
            socket.close();
            return;
        }

        String challenge = "I am client";
        long hash = Math.abs(challenge.hashCode()) % localRSA.getModulus();
        long signature = localRSA.signature(hash);
        out.writeObject(challenge);
        out.writeObject(Long.toString(signature));
        out.flush();
        System.out.println("[RSA] Sent challenge: \"" + challenge + "\", hash: " + hash + ", signature: " + signature);

        BigInteger peerDHPub = (BigInteger) in.readObject();
        System.out.println("[DH] Received DH public key: " + peerDHPub);
        out.writeObject(localDH.getPublicKey());
        out.flush();
        System.out.println("[DH] Sent my DH public key: " + localDH.getPublicKey());

        BigInteger sessionKey = localDH.computeSharedSecret(peerDHPub);
        System.out.println("[DH] Computed shared secret: " + sessionKey);

        byte[] peerAuthToken = (byte[]) in.readObject();
        byte[] authToken = localDH.generateAuthToken(sessionKey, localRSA);
        out.writeObject(authToken);
        out.flush();

        if (!localDH.verifyAuthToken(peerAuthToken, peerDHPub, sessionKey, peerRSA)) {
            System.out.println("❌ DH auth failed.");
            socket.close();
            return;
        }

        System.out.println("[DH] Authentication token exchanged and verified ✅");
        System.out.println("[🔐] Secure session established!");
        final long[] lastTimestamp = {0};

        new Thread(() -> {
            try {
                while (true) {
                    String message = scanner.nextLine();
                    String encrypted = SimpleEncryptor.encrypt(message, sessionKey);
                    System.out.println("[Encrypt] Message: \"" + message + "\"");
                    System.out.println("[Encrypt] Encrypted (hex): " + encrypted);
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
        }).start();

        new Thread(() -> {
            try {
                while (true) {
                    String encrypted = (String) in.readObject();
                    byte[] receivedHash = (byte[]) in.readObject();
                    long timestamp = (Long) in.readObject();

                    if (timestamp <= lastTimestamp[0]) {
                        System.out.println("⚠️ Replay attack detected.");
                        continue;
                    }

                    System.out.println("[Decrypt] Received Encrypted (hex): " + encrypted);
                    String decrypted = SimpleEncryptor.decrypt(encrypted, sessionKey);
                    System.out.println("[Decrypt] Decrypted Message: \"" + decrypted + "\"");
                    byte[] computedHash = SHA256.hash(decrypted.getBytes());

                    if (!Arrays.equals(receivedHash, computedHash)) {
                        System.out.println("⚠️ Integrity check failed.");
                        continue;
                    }

                    lastTimestamp[0] = timestamp;
                    System.out.println("[Peer] " + decrypted + " (Received at " + new Date(timestamp) + ")");
                }
            } catch (Exception e) {
                System.out.println("Receiver error: " + e.getMessage());
            }
        }).start();
    }
}


