package FinalProject;

// Libraries to be imported
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;


public class AuthenticatedDH { // Implementation of Diffie-Hellman key-exchange

    private final BigInteger privateKey;   // Randomly generated secret random exponent (A)
    private final BigInteger publicKey;    // Public key to share (G^A mod P)
    private final BigInteger modulus;      // Prime modulus for the DH group (P)
    private final BigInteger generator;    // Generator for the group (G)

    private static final BigInteger DEFAULT_PRIME = new BigInteger(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
                    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
                    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
                    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
                    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381" +
                    "FFFFFFFFFFFFFFFF", 16); // Default 2048-bit safe prime numbers (RFC 3526 Group 14)

    private static final BigInteger DEFAULT_GENERATOR = BigInteger.valueOf(2); // Common generate G = 2


    public AuthenticatedDH() { // Constructs a DH instance with default 2048-bit modulus and generator
        this(AuthenticatedDH.DEFAULT_PRIME, AuthenticatedDH.DEFAULT_GENERATOR); // Constructor chaining passing values to the other constructor
    }

    public AuthenticatedDH(BigInteger modulus, BigInteger generator) { // Constructs a DH instance with a custom modulus and generator

        this.modulus = modulus; // Set the modulus
        this.generator = generator; // Set the generator

        var random = new SecureRandom(); // Random instance created

        // Private key must be less than modulus
        this.privateKey = new BigInteger(modulus.bitLength() - 2, random).add(BigInteger.ONE); // Generate a random private-key (A)
        this.publicKey = generator.modPow(privateKey, modulus); // Compute the corresponding public key (G^A mod P)
    }

    public BigInteger getPublicKey() { // Getter for public key
        return this.publicKey; // Return the public key (G^A mod P)
    }

    public BigInteger computeSharedSecret(final BigInteger otherPublicKey) { // Compute the shared secret using the other party public key
        return otherPublicKey.modPow(this.privateKey, this.modulus); // Shared Secret = G^(AB) mod P
    }

    public byte[] generateAuthToken(final BigInteger sharedSecret, final RSA rsa) { // Generate an RSA-authenticated token used to authenticate the exchange using RSA.

        try {
            var authMessage = this.publicKey.toString() + sharedSecret.toString(); // Create a message combining the DH public key and shared secret

            var messageHash = Math.abs(authMessage.hashCode()) % rsa.getModulus();  // Compute a simple bounded message hash

            var signature = rsa.signature(messageHash); // Digitally sign the hash with RSA private-key

            // Serialize: Convert the public key and the signature into byte arrays
            var publicKeyBytes = this.publicKey.toByteArray(); // Public key into byte-array
            var signatureBytes = BigInteger.valueOf(signature).toByteArray(); // Signature into byte-array

            var token = new byte[publicKeyBytes.length + signatureBytes.length]; // Combine both into one byte array
            System.arraycopy(publicKeyBytes, 0, token, 0, publicKeyBytes.length); // Public Key Bytes
            System.arraycopy(signatureBytes, 0, token, publicKeyBytes.length, signatureBytes.length); // Signature Bytes

            return token; // Return the signed authentication token

        } catch (Exception e) {
            throw new RuntimeException("Authentication token generation failed", e);
        }
    }

    public boolean verifyAuthToken(final byte[] token, final BigInteger theirPublicKey,
                                   final BigInteger sharedSecret, final RSA theirRSA) { // Verify authenticity of the received token
        try {

            // Reconstruct the sent public key and RSA signature from the token
            var theirPubKeyBytes = theirPublicKey.toByteArray(); // Extract the original public key bytes from received input
            var publicKeyLength = theirPubKeyBytes.length; // Length of the other party public key

            // Split the token
            var sentPubKeyBytes = Arrays.copyOfRange(token, 0, publicKeyLength); // First part is public-key
            var signatureBytes = Arrays.copyOfRange(token, publicKeyLength, token.length); // Rest is the signature

            // Reconstruct values from byte arrays
            var sentPubKey = new BigInteger(sentPubKeyBytes);
            var signature = new BigInteger(signatureBytes).longValue();

            // Debug print
            System.out.println("[DEBUG] Expected Public Key: " + theirPublicKey);
            System.out.println("[DEBUG] Received Public Key: " + sentPubKey);
            System.out.println("[DEBUG] Signature: " + signature);

            // Validate public key match
            if (!sentPubKey.equals(theirPublicKey)) {
                System.out.println("[ERROR] Public key mismatch");
                return false;
            }

            // Recompute hash from received data
            var authMessage = theirPublicKey.toString() + sharedSecret.toString();
            var messageHash = Math.abs(authMessage.hashCode()) % theirRSA.getModulus();
            System.out.println("[DEBUG] Recomputed Hash: " + messageHash);


            var valid = RSA.verification(signature,
                    messageHash, theirRSA.getPublicKey(), theirRSA.getModulus()); // Verify digital signature with sender public RSA key

            if (!valid) { // Return false
                System.out.println("[ERROR] Signature verification failed");
            }
            return valid; // Return true if everything checks out

        } catch (Exception e) {
            System.out.println("[ERROR] Token verification failed: " + e.getMessage());
            return false;
        }
    }
}

