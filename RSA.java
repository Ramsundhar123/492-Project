package FinalProject;
import java.util.*;
import java.math.*;

/**
 * Interface defining basic RSA operations.
 */
interface Operations {
    long encrypt(long plaintext);
    long decrypt(long ciphertext);
    long signature(long plaintext);
}

/**
 * RSA encryption, decryption, and digital signature utility.
 * Supports both key generation (via primes) and usage with remote public keys.
 */
public class RSA implements Operations {

    private final long publicKey;
    private final long privateKey;
    private final long modulus;

    /**
     * Constructor for generating RSA key pairs using two distinct prime numbers.
     *
     * @param primeP        First prime number
     * @param primeQ        Second prime number
     * @param isPrimeInput  Must be true to proceed with key generation
     */
    public RSA(long primeP, long primeQ, boolean isPrimeInput) {
        if (isPrimeInput) {
            if (primeP == primeQ) {
                throw new IllegalArgumentException("Primes must be distinct");
            }

            // Compute Euler's totient (φ) = (p-1)*(q-1)
            long phi = (primeP - 1) * (primeQ - 1);
            this.modulus = primeP * primeQ;

            // Choose public key e such that 1 < e < phi and gcd(e, phi) = 1
            this.publicKey = selectPublicKey(phi);

            // Compute private key d as modular inverse of e mod φ
            this.privateKey = RSAHelper.modInverse(this.publicKey, phi);
        } else {
            throw new IllegalArgumentException("Invalid constructor usage");
        }
    }

    /**
     * Constructor used for peer public key initialization (without private key).
     *
     * @param publicKey Peer’s public exponent
     * @param modulus   Shared modulus
     */
    public RSA(final long publicKey, final long modulus) {
        this.publicKey = publicKey;
        this.modulus = modulus;
        this.privateKey = 0; // Not known in this case
    }

    /**
     * Encrypt a message using the public key: c = m^e mod n
     */
    @Override
    public long encrypt(long plaintext) {
        if (plaintext < 0 || plaintext >= this.modulus) {
            throw new IllegalArgumentException("Message must be less than modulus");
        }
        return RSAHelper.power(plaintext, this.publicKey, this.modulus);
    }

    /**
     * Decrypt a message using the private key: m = c^d mod n
     */
    @Override
    public long decrypt(long ciphertext) {
        if (ciphertext < 0 || ciphertext >= modulus) {
            throw new IllegalArgumentException("Ciphertext must be less than modulus");
        }
        long result = RSAHelper.power(ciphertext, this.privateKey, this.modulus);
        if (result < 0 || result >= this.modulus) {
            throw new IllegalArgumentException("Decryption produced invalid result");
        }
        return result;
    }

    /**
     * Sign a message (typically its hash) using the private key: s = m^d mod n
     */
    @Override
    public long signature(long plaintext) {
        return RSAHelper.power(plaintext, this.privateKey, this.modulus);
    }

    /**
     * Verifies a signature: Checks that s^e mod n == hash
     *
     * @param signature         The signature to verify
     * @param messageHash       The original message hash
     * @param senderPublicKey   Public key of the sender
     * @param senderModulus     Modulus used by the sender
     * @return true if valid, false otherwise
     */
    public static boolean verification(long signature, long messageHash, long senderPublicKey, long senderModulus) {
        long verifiedHash = RSAHelper.power(signature, senderPublicKey, senderModulus);
        return verifiedHash == messageHash;
    }

    /**
     * Select a random public exponent e such that gcd(e, phi) == 1.
     */
    private static long selectPublicKey(long phi) {
        List<Long> candidates = new ArrayList<>();
        for (long e = 3; e < phi; e++) {
            if (RSAHelper.gcd(e, phi) == 1) {
                candidates.add(e);
            }
        }
        return candidates.get(new Random().nextInt(candidates.size()));
    }

    // Accessors
    public long getPublicKey() {
        return this.publicKey;
    }

    public long getPrivateKey() {
        return this.privateKey;
    }

    public long getModulus() {
        return this.modulus;
    }

    /**
     * Utility class containing static methods for RSA math operations.
     */
    static class RSAHelper {

        /**
         * Compute greatest common divisor using brute force.
         */
        public static long gcd(long a, long b) {
            long gcd = 1;
            for (long i = 1; i <= Math.min(a, b); i++) {
                if (a % i == 0 && b % i == 0) {
                    gcd = i;
                }
            }
            return gcd;
        }

        /**
         * Modular exponentiation: (base^exponent) % mod
         * Uses binary exponentiation (efficient).
         */
        public static long power(long base, long exponent, long mod) {
            if (mod == 1) return 0;
            long result = 1;
            base = base % mod;
            while (exponent > 0) {
                if ((exponent & 1) == 1) {
                    result = (result * base) % mod;
                }
                exponent >>= 1;
                base = (base * base) % mod;
            }
            return result;
        }

        /**
         * Compute modular inverse using Java's BigInteger.
         */
        public static long modInverse(long a, long m) {
            return BigInteger.valueOf(a).modInverse(BigInteger.valueOf(m)).longValue();
        }

        /**
         * Check for primality using trial division.
         */
        public static boolean isPrime(long number) {
            if (number <= 1) return false;
            if (number <= 3) return true;
            if (number % 2 == 0 || number % 3 == 0) return false;
            for (long i = 5; i * i <= number; i += 6) {
                if (number % i == 0 || number % (i + 2) == 0) return false;
            }
            return true;
        }
    }
}


