package FinalProject;

// Libraries imported
import java.math.BigInteger;
import java.security.SecureRandom;

public class SimpleEncryptor { // Simple implementation of AES simulated with XOR in CBC mode and SHA-256

    private static long deriveKey(final BigInteger sharedSecret) { // Derives a pseudo-AES 64-bit key from a shared secret using SHA-256

        var hash = SHA256.computeHash(sharedSecret.toByteArray());  // Hash the shared secret using SHA-256
        return CBC.bytesToLong(new byte[] {
                hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7]
        }); // Use the first 8 bits of the hash (64 bits) as the key
    }

    public static String encrypt(final String message, final BigInteger sharedSecret) throws Exception { // Encrypts the plaintext-message using XOR-based CBC mode and SHA-256.

        var key = SimpleEncryptor.deriveKey(sharedSecret); // Derive the key from the shared secret
        var aes = new CBC(key); // Creat the CBC cipher instance using the derived key

        var padded = CBC.padding(message.getBytes()); // Pas the message using PKCS so it is a multiple of 8 bytes

        var ivBytes = new byte[8]; // New byte array to hold the initialization-vector (IV) for CBC mode
        new SecureRandom().nextBytes(ivBytes); // Generate a random initialization-vector (IV) for CBC mode

        var messageBlocks = CBC.toLongArray(padded); // Convert the padded message to 64-bit blocks
        var cipherBlocks = aes.encrypt(messageBlocks, ivBytes); // Encrypt the blocks using CBC mode

        var cipherBytes = CBC.toByteArray(cipherBlocks); // Convert the encrypted long blocks back to bytes
        var finalBytes = new byte[ivBytes.length + cipherBytes.length]; // Allocate a new byte array to hold the final message bytes

        // Concatenate IV + ciphertext into a single byte array
        System.arraycopy(ivBytes, 0, finalBytes, 0, ivBytes.length);
        System.arraycopy(cipherBytes, 0, finalBytes, ivBytes.length, cipherBytes.length);

        return HexOperations.bytesToHex(finalBytes); // Return the result as a hex-encoded string
    }


    public static String decrypt(final String hexMessage, final BigInteger sharedSecret) throws Exception { // Decrypt the hex-encoded cipher-text using CBC mode and shared secret.

        var allBytes = HexOperations.hexToBytes(hexMessage); // Convert the hex string back to byte array

        var ivBytes = new byte[8]; // Extract the first 8 bits as the initialization-vector (IV)
        var cipherBytes = new byte[allBytes.length - 8]; // Rest is the actual cipher-text bytes

        // Split IV and cipher-text bytes into separate byte arrays
        System.arraycopy(allBytes, 0, ivBytes, 0, 8);
        System.arraycopy(allBytes, 8, cipherBytes, 0, cipherBytes.length);

        var key = SimpleEncryptor.deriveKey(sharedSecret); // Derive the key using the same shared secret
        var aes = new CBC(key); // Initialize the CBC cipher

        var cipherBlocks = CBC.toLongArray(cipherBytes); // Convert cipher-text to long blocks using CBC mode
        var plainBlocks = aes.decrypt(cipherBlocks, ivBytes); // Decrypt the blocks using CBC mode
        var paddedPlain = CBC.toByteArray(plainBlocks); // Convert decrypted long blocks back to padded bytes
        var unpadded = CBC.unpad(paddedPlain); // Remove PKCS padding form the padded bytes

        return new String(unpadded); // Convert the final byte array to string (original message)
    }

    static class HexOperations { // Class for Hex operations

        private static String bytesToHex(final byte[] bytes) { // Convert the byte array to a hex string

            var sb = new StringBuilder(); // New StringBuilder to hold the hex string

            for (byte singleByte : bytes) { // Convert each byte to a 2-digit hex string
                sb.append(String.format("%02x", singleByte)); // Append to stringBuilder instance
            }
            return sb.toString(); // Convert StringBuilder to string and return the result
        }

        private static byte[] hexToBytes(final String hex) { // Convert a hex string to a byte array
            var result = new byte[hex.length() / 2]; // Each 2 hex digits form one byte

            for (int index = 0; index < hex.length(); index += 2) { // Loop through teh hex string, two characters at a time
                /*
                    Extract two hex characters can concert them to byte
                    Parse-Int converts the hex string to an integer value
                    Cast the integer to a byte
                 */

                result[index / 2] = (byte) Integer.parseInt(hex.substring(index, index + 2), 16);
            }
            return result; // Return the final byte array representing original binary data
        }
    }
}

class SHA256 { // Custom SHA-256 algorithm implementation

    private static final int[] ROUND_CONSTANTS = { // Round constants defined by the SHA-256 standard (FIPS PUB 180-4) used in each of the 64 rounds
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    static class BitWiseOperations { // Utility class

        // Bitwise functions
        private static int rotateRight(int x, int n) { // Performs a right rotation (circular shift) of a 32-bit integer
            return (x >>> n) | (x << (32 - n)); // Bits shifted out on the right and reinserted on the left
        }

        private static int shiftRight(int x, int n) { // Performs a logical (zero-fill) right shift of a 32-bit integer by n bits
            return x >>> n; // Shifted bits are discarded and zero-filled in from the left
        }

        // Logical mixing functions
        private static int choice(int x, int y, int z) { // Used during the compression step to mix working variables
            return (x & y) ^ (~x & z); // Select bits from Y or Z based on the value of X
        }

        private static int majority(int x, int y, int z) { // Select majority-bit from X, Y, and Z
            return (x & y) ^ (x & z) ^ (y & z); // Returns a bit that occurs in at least two of the inputs
        }

        // Compression mixing functions
        private static int rotateMixA(int x) { // Used in SHA-256 compression step on the 'A' working variable
            return BitWiseOperations.rotateRight(x, 2) ^ BitWiseOperations.rotateRight(x, 13) ^ BitWiseOperations.rotateRight(x, 22); // Performs a combination of bit-wise right rotations (2, 13, 22) and XOR
        }

        private static int rotateMixE(int x) { // Used in SHA-256 compression step on the 'E' working variable
            return BitWiseOperations.rotateRight(x, 6) ^ BitWiseOperations.rotateRight(x, 11) ^ BitWiseOperations.rotateRight(x, 25); // Performs a combination of bit-wise right rotations (6, 11, 25) and XOR
        }

        // Expansion Mixing functions
        private static int expandWordMix1(int x) { // Used during message-schedule expansion step
            return BitWiseOperations.rotateRight(x, 7) ^ BitWiseOperations.rotateRight(x, 18) ^ BitWiseOperations.shiftRight(x, 3); // Performs a rotate right (7, 18), logical shift right (3), and then XORs the results.
        }

        private static int expandWordMix2(int x) { // Used during message-schedule expansion step
            return BitWiseOperations.rotateRight(x, 17) ^ BitWiseOperations.rotateRight(x, 19) ^ BitWiseOperations.shiftRight(x, 10); // Performs a rotate right (17, 19), logical shift right (10), and then XORs the results.
        }
    }

    public static byte[] computeHash(final byte[] message) { // Computes SHA-256 hash of a given input message

        int[] hashState = { // Initial hash values
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };


        var padded = padMessage(message); // Pad the message
        var blocks = padded.length / 64; // Number of 512-bit blocks in the padded message


        for (int idx = 0; idx < blocks; idx++) { // Process each of the 512-bit block

            var messageSchedule = new int[64]; // Initialize a message-schedule array for this 512-bit block

            for (int idx2 = 0; idx2 < 16; idx2++) { // Fill the first 16 words of the schedule with the original message block
                int index = idx * 64 + idx2 * 4;
                messageSchedule[idx2] = ((padded[index] & 0xFF) << 24) | ((padded[index + 1] & 0xFF) << 16)
                        | ((padded[index + 2] & 0xFF) << 8) | (padded[index + 3] & 0xFF);
            }

            for (int j = 16; j < 64; j++) { // Extend the message schedule using bitwise mixing functions
                messageSchedule[j] = BitWiseOperations.expandWordMix2(messageSchedule[j - 2]) + messageSchedule[j - 7] + BitWiseOperations.expandWordMix1(messageSchedule[j - 15]) + messageSchedule[j - 16];
            }

            // Initialize working variables from current hash state
            int workVariableA = hashState[0], workVariableB = hashState[1], workVariableC = hashState[2], workVariableD = hashState[3];
            int workVariableE = hashState[4], workVariableF = hashState[5], workVariableG = hashState[6], workVariableH = hashState[7];

            for (int index = 0; index < 64; index++) { // Perform the main SHA-256 compression loop for 64 rounds

                var tempOne = workVariableH + BitWiseOperations.rotateMixE(workVariableE) + // Combine H and transformed E
                        BitWiseOperations.choice(workVariableE, workVariableF, workVariableG) + // Choice(E, F, G)
                        SHA256.ROUND_CONSTANTS[index] + // Current round constant at index value
                        messageSchedule[index]; // Message-schedule word at index

                var tempTwo = BitWiseOperations.rotateMixA(workVariableA) + // Transform A using rotation mix function
                        BitWiseOperations.majority(workVariableA, workVariableB, workVariableC); // Logical majority of A, B, and C

                // Update working variables by shifting them as specifying by SHA-256
                workVariableH = workVariableG; // Shift H -> G
                workVariableG = workVariableF; // Shift G -> F
                workVariableF = workVariableE;  // Shift F -> E
                workVariableE = workVariableD + tempOne; // New E = D + tempOne
                workVariableD = workVariableC; // Shift D -> C
                workVariableC = workVariableB; // Shift C -> B
                workVariableB = workVariableA; // Shift B -> A
                workVariableA = tempOne + tempTwo; // New A = tempOne + tempTwo
            }

            // Once processing is done on this 512-bit block, update the current hash state with working variables.
            hashState[0] += workVariableA; // Update H0 with final A
            hashState[1] += workVariableB; // Update H1 with final B
            hashState[2] += workVariableC; // Update H2 with final C
            hashState[3] += workVariableD; // Update H3 with final D
            hashState[4] += workVariableE; // Update H4 with final E
            hashState[5] += workVariableF; // Update H5 with final F
            hashState[6] += workVariableG; // Update H6 with final G
            hashState[7] += workVariableH; // Update H7 with final G
        }

        var digest = new byte[32]; // Allocate 32 bits to hold the final SHA-256 hash

        for (int index = 0; index < hashState.length; index++) {

            // Break each 32-bit integer into 4 bytes
            digest[index * 4] = (byte) (hashState[index] >>> 24); // Most significant byte
            digest[index * 4 + 1] = (byte) (hashState[index] >>> 16);
            digest[index * 4 + 2] = (byte) (hashState[index] >>> 8);
            digest[index * 4 + 3] = (byte) (hashState[index]); // Least significant byte
        }
        return digest; // Return final-hash as a 32-byte array
    }

    private static byte[] padMessage(byte[] message) { // Pads the input message according to SHA-256 specification
        var length = message.length; // Original message length in bytes
        var bitLength = (long) length * 8; // Convert byte length to bit length

        var padLength = 64 - ((length + 9) % 64); // 1 byte for marker and 8 bytes for length (total of 9) and ensure padded length is multiple of 64
        var padded = new byte[length + 1 + padLength + 8]; // Create a new byte array: original length + 1 byte + pad-length + 8 bytes

        System.arraycopy(message, 0, padded, 0, length); // Copy original message into the beginning of the padded array

        padded[length] = (byte) 0x80; // Append a single-bit (0x80)

        for (int index = 0; index < 8; index++) { // Append original message length as a 64-bit integer at the end
            padded[padded.length - 1 - index] = (byte) ((bitLength >>> (8 * index)) & 0xFF);
        }
        return padded; // Return the padded message ready for processing in 512-bit blocks
    }
}
class CBC { // CBC mode class

    private final long key;  // Symmetric key used for XOR-based encryption/decryption

    public CBC(long key) { // Construct a CBC instance with the given key
        this.key = key; // A 64-bit key used for XOR-based encryption
    }

    private long encryptBlock(long block) { // Encrypt a 64-bit block using XOR (placeholder for real block)
        return block ^ this.key; // Simple XOR encryption (symmetric)
    }

    private long decryptBlock(long block) { // Decrypt a 64-bit block using XOR
        return block ^ this.key; // XOR decryption (symmetric)
    }


    public long[] encrypt(final long[] plaintext, final byte[] ivBytes) { // Encrypt a message using CBC mode with XOR-based block cipher

        if (ivBytes == null || ivBytes.length != 8) // 8-byte initialization-vector required for CBC mode
            throw new IllegalArgumentException("IV must be 8 bytes"); // Exception

        var ciphertext = new long[plaintext.length]; // New array to hold the ciphertext blocks
        var iv = bytesToLong(ivBytes); // Convert IV to 64-bit long value
        var prevCipher = iv; // First previous cipher-block is IV

        for (int index = 0; index < plaintext.length; index++) { // Each block is XORed with the previous ciphertext (or IV).
            var XORED = plaintext[index] ^ prevCipher; // CBC chaining: XOR with previous
            var encrypted = encryptBlock(XORED); // Encrypt block
            ciphertext[index] = encrypted;
            prevCipher = encrypted; // Update previous cipher block
        }

        return ciphertext; // Return the ciphertext blocks
    }

    public long[] decrypt(final long[] ciphertext, final byte[] ivBytes) { // Decrypts a message using CBC mode with a XOR-based block cipher

        if (ivBytes == null || ivBytes.length != 8) // 8-byte initialization-vector required for CBC mode
            throw new IllegalArgumentException("IV must be 8 bytes"); // Exception

        var plaintext = new long[ciphertext.length]; // New array to hold the plaintext blocks
        var iv = bytesToLong(ivBytes); // Convert IV to 64-bit long value
        var prevCipher = iv; // First previous cipher-block is IV

        for (int index = 0; index < ciphertext.length; index++) { // Each decrypted block is XORed with the previous ciphertext (or IV).
            var decrypted = decryptBlock(ciphertext[index]);       // Decrypt block
            plaintext[index] = decrypted ^ prevCipher;              // CBC chaining
            prevCipher = ciphertext[index];                         // Update previous cipher block
        }

        return plaintext; // Return the plaintext blocks
    }

    public static long[] toLongArray(final byte[] byteArray) { // Convert byte-array to long-array

        if (byteArray.length % 8 != 0) { // Byte array length must be multiple of 8
            throw new IllegalArgumentException("Byte array length must be a multiple of 8.");
        }

        var len = byteArray.length / 8; // Number of 64-bit blocks the input contains
        var result = new long[len]; // Create a new long array to hold the converted values

        for (int index = 0; index < byteArray.length; index++) { // Iterate over each byte in the input array
            result[index / 8] |= ((long) byteArray[index] & 0xFF) << ((index % 8) * 8); // Little-endian
        }
        return result; // Return the fully constructed array of 64-bit values
    }

    public static byte[] toByteArray(final long[] longArray) { // Convert long-array to a byte-array

        var result = new byte[longArray.length * 8]; // Corresponding byte array

        for (int index = 0; index < longArray.length; index++) { // Iterate through each long in the input array
            for (int idx = 0; idx < 8; idx++) { // Break down each 64-bit long into 8 bytes
                result[index * 8 + idx] = (byte) ((longArray[index] >> (idx * 8)) & 0xFF); // Store bytes at the correct position in the output array
            }
        }
        return result; // Return the complete byte array
    }

    public static byte[] padding(final byte[] input) { // PKCS-style padding to multiple of 8 bytes

        var padLength = 8 - (input.length % 8); // Calculate the number of padding bytes needed to reach a multiple of 8
        var padded = new byte[input.length + padLength]; // Create a new byte array to hold input and padding bytes
        System.arraycopy(input, 0, padded, 0, input.length); // Copy the original input into the beginning of the new array

        for (int index = input.length; index < padded.length; index++) { // Fill remaining padding bytes with the pad length (PKCS-style)
            padded[index] = (byte) padLength; // Pad length is a single byte
        }
        return padded; // A new padded byte array with a length multiple of 8
    }

    public static byte[] unpad(final byte[] input) throws Exception { // Remove PKCS-style padding from a padded byte array

        var padLength = input[input.length - 1] & 0xFF; // Read the value of last-byte that indicate how many padding bytes were added (0xFF to avoid negative values)

        if (padLength <= 0 || padLength > 8) { // Validate the padding length is between 1 and 8 (inclusive)
            throw new Exception("Invalid padding length"); // Padding of 0 or greater than block size is invalid
        }

        for (int index = input.length - padLength; index < input.length; index++) { // Prevent incorrect un-padding and protecting against padding attacks
            if (input[index] != (byte) padLength) { // Check all the last pad-length bytes are equal to the expected padding value.
                throw new Exception("Invalid padding bytes."); // If not, throw an exception.
            }
        }

        var result = new byte[input.length - padLength]; // Create a new byte array excluding the padding bytes
        System.arraycopy(input, 0, result, 0, result.length); // Copy the original unpadded portion of the input into the result
        return result; // Return the clean and unpadded byte array
    }

    public static long bytesToLong(final byte[] bytes) { // Converts 8-byte array into a 64-bit long value

        if (bytes == null || bytes.length != 8) { // Check for null input or invalid length
            throw new IllegalArgumentException("Input must be 8 bytes"); // Throw an exception if invalid length
        }

        long result = 0; // Resulting long value variable

        for (int index = 0; index < 8; index++) { // Iterate over each byte in the input array
            /*
                Step 1: Converts byte to unsigned value (& 0xFF)
                Step 2: Shift it left by 8 * index bits to position it correctly in the long value
                Step 3: Index = 0 put it in the least significant position
                Step 4: Index = 7 put it in the most significant position
             */
            result |= ((long) bytes[index] & 0xFF) << (8 * index); // Assign to result
        }
        return result; // Return the reconstructed 64-bit long value
    }
}




