package FinalProject;

// Libraries to be imported
import java.util.*;
import java.math.*;


interface Operations { // Interface defining basic RSA operations
    long encrypt(long plaintext); // Public-key encryption
    long decrypt(long ciphertext); // Private-key decryption
    long signature(long plaintext); // Digital signature generation
}


public class RSA implements Operations { // RSA encryption, decryption, and digital signature Utility

    private final long publicKey; // Public exponent (E)
    private final long privateKey; // Public exponent (D)
    private final long modulus; // RSA Modulus (N = P * Q)

    public RSA(long primeP, long primeQ, boolean isPrimeInput) { // Generates RSA key pair given two distinct primes

        if (isPrimeInput) { // Check for prime
            if (primeP == primeQ) { // Check if primes are equal
                throw new IllegalArgumentException("Primes must be distinct"); // Throw exception
            }


            var totient = (primeP - 1) * (primeQ - 1); // Totient = (P - 1) * (Q - 1)
            this.modulus = primeP * primeQ; // Modulus

            this.publicKey = RSA.selectPublicKey(totient); // Choose public key e such that 1 < E < phi and gcd(e, phi) = 1

            this.privateKey = RSAHelper.modInverse(this.publicKey, totient); // Compute private key (D) as modular inverse of (E) mod totient

        } else {
            throw new IllegalArgumentException("Invalid constructor usage");
        }
    }


    public RSA(final long publicKey, final long modulus) { // Constructs an RSA object with only public-key component

        this.publicKey = publicKey; // Set the public key
        this.modulus = modulus; // Set the private key
        this.privateKey = 0; // Not known in this case
    }

    @Override
    public long encrypt(final long plaintext) { // Encrypt a plaintext using the public key (C = M^E mod N)

        if (plaintext < 0 || plaintext >= this.modulus) { // Check if message is less than 0 or bigger than modulus
            throw new IllegalArgumentException("Message must be less than modulus");
        }

        return RSAHelper.power(plaintext, this.publicKey, this.modulus); // Return the encrypted message
    }

    @Override
    public long decrypt(final long ciphertext) { // Decrypts a ciphertext using the private key (M = C^D mod N)

        if (ciphertext < 0 || ciphertext >= this.modulus) { // Check if the cipher text is valid
            throw new IllegalArgumentException("Ciphertext must be less than modulus");
        }

        var result = RSAHelper.power(ciphertext, this.privateKey, this.modulus); // Result = C^D mod N

        if (result < 0 || result >= this.modulus) { // Check after decryption
            throw new IllegalArgumentException("Decryption produced invalid result");
        }

        return result; // Long plaintext
    }

    @Override
    public long signature(final long plaintext) { // Sign a message using the private key (S = M^D mod N)
        return RSAHelper.power(plaintext, this.privateKey, this.modulus);  // S = M^D mod N
    }

    public static boolean verification(final long signature, final long messageHash, final long senderPublicKey, final long senderModulus) { // Verify the signature

        var verifiedHash = RSAHelper.power(signature, senderPublicKey, senderModulus); // S^E mod N
        return verifiedHash == messageHash; // True if value else false
    }

    /**
     * Select a random public exponent e such that gcd(e, phi) == 1.
     */
    private static long selectPublicKey(long relativePrime) { // Select a random public exponent

        List<Long> candidates = new ArrayList<>(); // New array-list to hold relative primes

        for (long index = 3; index < relativePrime; index++) { // Go through each prime
            if (RSAHelper.gcd(index, relativePrime) == 1) { // See if GCD(E, N) is prime
                candidates.add(index); // Add to the candidates
            }
        }
        return candidates.get(new Random().nextInt(candidates.size())); // Get random prime
    }

    // Accessors
    public long getPublicKey() { // Getter public key
        return this.publicKey; // Return public key
    }

    public long getModulus() { // Getter modulus
        return this.modulus; // Return modulus
    }

    static class RSAHelper { // Utility class containing static methods for RSA math operations.


        public static long gcd(long a, long b) { // Compute greatest common divisor using brute force.

            var gcd = 1L; // Set initial GCD

            for (long i = 1; i <= Math.min(a, b); i++) { // Loop from 1 to a smaller number of A and B
                if (a % i == 0 && b % i == 0) { // Testing if it divides both A and B
                    gcd = i; // If it divides both A and B exactly
                }
            }
            return gcd; // Return the largest value that was a common divisor
        }

        public static long power(long base, long exponent, long mod) { // Modular Exponentiation (Base^Exponent) % Mod

            if (mod == 1){ // If mod is 1
                return 0; // Return 0
            }

            var result = 1L; // Initialize result as 1
            base = base % mod; // Reduce base modulo to prevent overflow and simplify calculation

            while (exponent > 0) { // Loop until all the bits of exponent are processed
                if ((exponent & 1) == 1) { // If the current bit of exponent is 1
                    result = (result * base) % mod; // Multiple result with current base and take modulo
                }
                exponent >>= 1; // Right shift the exponent by 1 bit
                base = (base * base) % mod; // Square the base for the next itertion and take modulo
            }
            return result; // Final modular exponentiation result
        }

        public static long modInverse(long a, long m) { // Compute modular inverse using Java's BigInteger.
            return BigInteger.valueOf(a).modInverse(BigInteger.valueOf(m)).longValue(); // Convert result to long
        }
    }
}


