package FinalProject;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * AuthenticatedDH class implements Diffie-Hellman key exchange
 * combined with RSA-based authentication to verify peer identity.
 */
public class AuthenticatedDH {

    private final BigInteger privateKey;   // Secret exponent (random)
    private final BigInteger publicKey;    // g^a mod p
    private final BigInteger modulus;      // Prime modulus p
    private final BigInteger generator;    // Generator g

    // Default 2048-bit safe prime modulus (RFC 3526 Group 14)
    private static final BigInteger DEFAULT_PRIME = new BigInteger(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
                    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
                    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
                    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
                    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381" +
                    "FFFFFFFFFFFFFFFF", 16);

    private static final BigInteger DEFAULT_GENERATOR = BigInteger.valueOf(2);

    /**
     * Constructs a DH instance with default modulus and generator.
     */
    public AuthenticatedDH() {
        this(DEFAULT_PRIME, DEFAULT_GENERATOR);
    }

    /**
     * Constructs a DH instance with custom modulus and generator.
     * Generates random private key and computes the corresponding public key.
     */
    public AuthenticatedDH(BigInteger modulus, BigInteger generator) {
        this.modulus = modulus;
        this.generator = generator;

        SecureRandom random = new SecureRandom();

        // Private key must be less than modulus
        this.privateKey = new BigInteger(modulus.bitLength() - 2, random).add(BigInteger.ONE);
        this.publicKey = generator.modPow(privateKey, modulus); // g^a mod p
    }

    /**
     * Returns the public key (g^a mod p).
     */
    public BigInteger getPublicKey() {
        return publicKey;
    }

    /**
     * Computes the shared secret: (g^b)^a mod p = g^(ab) mod p
     */
    public BigInteger computeSharedSecret(BigInteger otherPublicKey) {
        return otherPublicKey.modPow(privateKey, modulus);
    }

    /**
     * Generates a signed token combining the DH public key and shared secret.
     * This is used to authenticate the exchange using RSA.
     */
    public byte[] generateAuthToken(BigInteger sharedSecret, RSA rsa) {
        try {
            // Create a message combining the DH public key and shared secret
            String authMessage = publicKey.toString() + sharedSecret.toString();

            // Compute a bounded message hash (ensure it's within modulus)
            long messageHash = Math.abs(authMessage.hashCode()) % rsa.getModulus();

            // Sign the hash with RSA private key
            long signature = rsa.signature(messageHash);

            // Serialize the public key and the signature into a single byte array
            byte[] publicKeyBytes = publicKey.toByteArray();
            byte[] signatureBytes = BigInteger.valueOf(signature).toByteArray();

            byte[] token = new byte[publicKeyBytes.length + signatureBytes.length];
            System.arraycopy(publicKeyBytes, 0, token, 0, publicKeyBytes.length);
            System.arraycopy(signatureBytes, 0, token, publicKeyBytes.length, signatureBytes.length);

            return token;
        } catch (Exception e) {
            throw new RuntimeException("Authentication token generation failed", e);
        }
    }

    /**
     * Verifies the received authentication token:
     * - Confirms the public key matches
     * - Confirms RSA signature is valid
     */
    public boolean verifyAuthToken(byte[] token, BigInteger theirPublicKey,
                                   BigInteger sharedSecret, RSA theirRSA) {
        try {
            // Reconstruct the sent public key and RSA signature from the token
            byte[] theirPubKeyBytes = theirPublicKey.toByteArray();
            int pubLen = theirPubKeyBytes.length;

            byte[] sentPubKeyBytes = Arrays.copyOfRange(token, 0, pubLen);
            byte[] signatureBytes = Arrays.copyOfRange(token, pubLen, token.length);

            BigInteger sentPubKey = new BigInteger(sentPubKeyBytes);
            long signature = new BigInteger(signatureBytes).longValue();

            // Debug print
            System.out.println("[DEBUG] Expected Public Key: " + theirPublicKey);
            System.out.println("[DEBUG] Received Public Key: " + sentPubKey);
            System.out.println("[DEBUG] Signature: " + signature);

            // Validate public key match
            if (!sentPubKey.equals(theirPublicKey)) {
                System.out.println("[ERROR] Public key mismatch");
                return false;
            }

            // Recreate hash from received data
            String authMessage = theirPublicKey.toString() + sharedSecret.toString();
            long messageHash = Math.abs(authMessage.hashCode()) % theirRSA.getModulus();
            System.out.println("[DEBUG] Recomputed Hash: " + messageHash);

            // Verify RSA signature
            boolean valid = RSA.verification(signature, messageHash, theirRSA.getPublicKey(), theirRSA.getModulus());

            if (!valid) {
                System.out.println("[ERROR] Signature verification failed");
            }
            return valid;

        } catch (Exception e) {
            System.out.println("[ERROR] Token verification failed: " + e.getMessage());
            return false;
        }
    }
}

