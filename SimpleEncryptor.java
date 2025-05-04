package FinalProject;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * A SimpleEncryptor implementation using custom AES (simulated with XOR in CBC mode) and SHA-256.
 */
public class SimpleEncryptor {

    /**
     * Derives a pseudo AES key from the shared secret using the custom SHA-256.
     */
    private static long deriveKey(BigInteger sharedSecret) {
        byte[] hash = SHA256.hash(sharedSecret.toByteArray());
        // Take first 8 bytes of hash and convert to long (little-endian)
        return AES.bytesToLong(new byte[] {
                hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7]
        });
    }

    /**
     * Encrypts the message using custom AES in CBC mode with PKCS#7 padding.
     */
    public static String encrypt(String message, BigInteger sharedSecret) throws Exception {
        long key = deriveKey(sharedSecret);
        AES aes = new AES(key);

        byte[] padded = AES.pad(message.getBytes());
        byte[] ivBytes = new byte[8];
        new SecureRandom().nextBytes(ivBytes);

        long[] messageBlocks = AES.toLongArray(padded);
        long[] cipherBlocks = aes.encrypt(messageBlocks, ivBytes);

        byte[] cipherBytes = AES.toByteArray(cipherBlocks);
        byte[] finalBytes = new byte[ivBytes.length + cipherBytes.length];
        System.arraycopy(ivBytes, 0, finalBytes, 0, ivBytes.length);
        System.arraycopy(cipherBytes, 0, finalBytes, ivBytes.length, cipherBytes.length);

        return bytesToHex(finalBytes);
    }

    /**
     * Decrypts the hex-encoded message using custom AES in CBC mode.
     */
    public static String decrypt(String hexMessage, BigInteger sharedSecret) throws Exception {
        byte[] allBytes = hexToBytes(hexMessage);

        byte[] ivBytes = new byte[8];
        byte[] cipherBytes = new byte[allBytes.length - 8];
        System.arraycopy(allBytes, 0, ivBytes, 0, 8);
        System.arraycopy(allBytes, 8, cipherBytes, 0, cipherBytes.length);

        long key = deriveKey(sharedSecret);
        AES aes = new AES(key);

        long[] cipherBlocks = AES.toLongArray(cipherBytes);
        long[] plainBlocks = aes.decrypt(cipherBlocks, ivBytes);
        byte[] paddedPlain = AES.toByteArray(plainBlocks);
        byte[] unpadded = AES.unpad(paddedPlain);

        return new String(unpadded);
    }

    /** Converts a byte array to a hex string. */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /** Converts a hex string to a byte array. */
    private static byte[] hexToBytes(String hex) {
        byte[] result = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length(); i += 2) {
            result[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        }
        return result;
    }
}

/**
 * Custom SHA-256 implementation.
 * Outputs a 32-byte digest for any input byte array.
 */
class SHA256 {
    private static final int[] K = { /* round constants */
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    private static int ROTR(int x, int n) { return (x >>> n) | (x << (32 - n)); }
    private static int SHR(int x, int n) { return x >>> n; }
    private static int Ch(int x, int y, int z) { return (x & y) ^ (~x & z); }
    private static int Maj(int x, int y, int z) { return (x & y) ^ (x & z) ^ (y & z); }
    private static int Sigma0(int x) { return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22); }
    private static int Sigma1(int x) { return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25); }
    private static int sigma0(int x) { return ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3); }
    private static int sigma1(int x) { return ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10); }

    public static byte[] hash(byte[] message) {
        int[] H = {
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };

        byte[] padded = padMessage(message);
        int blocks = padded.length / 64;

        for (int i = 0; i < blocks; i++) {
            int[] w = new int[64];
            for (int j = 0; j < 16; j++) {
                int index = i * 64 + j * 4;
                w[j] = ((padded[index] & 0xFF) << 24) | ((padded[index + 1] & 0xFF) << 16)
                        | ((padded[index + 2] & 0xFF) << 8) | (padded[index + 3] & 0xFF);
            }
            for (int j = 16; j < 64; j++) {
                w[j] = sigma1(w[j - 2]) + w[j - 7] + sigma0(w[j - 15]) + w[j - 16];
            }

            int a = H[0], b = H[1], c = H[2], d = H[3];
            int e = H[4], f = H[5], g = H[6], h = H[7];

            for (int j = 0; j < 64; j++) {
                int temp1 = h + Sigma1(e) + Ch(e, f, g) + K[j] + w[j];
                int temp2 = Sigma0(a) + Maj(a, b, c);
                h = g; g = f; f = e; e = d + temp1;
                d = c; c = b; b = a; a = temp1 + temp2;
            }

            H[0] += a; H[1] += b; H[2] += c; H[3] += d;
            H[4] += e; H[5] += f; H[6] += g; H[7] += h;
        }

        byte[] digest = new byte[32];
        for (int i = 0; i < H.length; i++) {
            digest[i * 4] = (byte) (H[i] >>> 24);
            digest[i * 4 + 1] = (byte) (H[i] >>> 16);
            digest[i * 4 + 2] = (byte) (H[i] >>> 8);
            digest[i * 4 + 3] = (byte) (H[i]);
        }
        return digest;
    }

    /**
     * Pads the message according to SHA-256 specification.
     */
    private static byte[] padMessage(byte[] message) {
        int len = message.length;
        long bitLen = (long) len * 8;
        int padLen = 64 - ((len + 9) % 64);
        byte[] padded = new byte[len + 1 + padLen + 8];
        System.arraycopy(message, 0, padded, 0, len);
        padded[len] = (byte) 0x80;
        for (int i = 0; i < 8; i++) {
            padded[padded.length - 1 - i] = (byte) ((bitLen >>> (8 * i)) & 0xFF);
        }
        return padded;
    }
}
class AES {
    private long key;  // Simulated AES key

    public AES(long key) {
        this.key = key;
    }

    // Encrypt one 64-bit block with XOR-based logic
    private long encryptBlock(long block) {
        return block ^ key;
    }

    private long decryptBlock(long block) {
        return block ^ key;
    }

    /** Encrypts array of 64-bit blocks using CBC mode. */
    public long[] encrypt(long[] message, byte[] ivBytes) {
        if (ivBytes == null || ivBytes.length != 8)
            throw new IllegalArgumentException("IV must be 8 bytes");

        long[] result = new long[message.length];
        long iv = bytesToLong(ivBytes);
        long prev = iv;

        for (int i = 0; i < message.length; i++) {
            long xored = message[i] ^ prev;
            long encrypted = encryptBlock(xored);
            result[i] = encrypted;
            prev = encrypted;
        }
        return result;
    }

    /** Decrypts array of 64-bit blocks using CBC mode. */
    public long[] decrypt(long[] cipher, byte[] ivBytes) {
        if (ivBytes == null || ivBytes.length != 8)
            throw new IllegalArgumentException("IV must be 8 bytes");

        long[] result = new long[cipher.length];
        long iv = bytesToLong(ivBytes);
        long prev = iv;

        for (int i = 0; i < cipher.length; i++) {
            long decrypted = decryptBlock(cipher[i]);
            result[i] = decrypted ^ prev;
            prev = cipher[i];
        }
        return result;
    }

    /** Converts byte[] to long[] assuming little-endian block layout. */
    public static long[] toLongArray(byte[] byteArray) {
        if (byteArray.length % 8 != 0)
            throw new IllegalArgumentException("Byte array length must be a multiple of 8.");

        int len = byteArray.length / 8;
        long[] result = new long[len];
        for (int i = 0; i < byteArray.length; i++) {
            result[i / 8] |= ((long) byteArray[i] & 0xFF) << ((i % 8) * 8);
        }
        return result;
    }

    /** Converts long[] to byte[] assuming little-endian block layout. */
    public static byte[] toByteArray(long[] longArray) {
        byte[] result = new byte[longArray.length * 8];
        for (int i = 0; i < longArray.length; i++) {
            for (int j = 0; j < 8; j++) {
                result[i * 8 + j] = (byte) ((longArray[i] >> (j * 8)) & 0xFF);
            }
        }
        return result;
    }

    /** Pads input to a multiple of 8 bytes using PKCS#5/7 style padding. */
    public static byte[] pad(byte[] input) {
        int padLength = 8 - (input.length % 8);
        byte[] padded = new byte[input.length + padLength];
        System.arraycopy(input, 0, padded, 0, input.length);
        for (int i = input.length; i < padded.length; i++) {
            padded[i] = (byte) padLength;
        }
        return padded;
    }

    /** Removes PKCS#5/7 style padding. */
    public static byte[] unpad(byte[] input) throws Exception {
        int padLength = input[input.length - 1] & 0xFF;
        if (padLength <= 0 || padLength > 8)
            throw new Exception("Invalid padding length: " + padLength);

        for (int i = input.length - padLength; i < input.length; i++) {
            if (input[i] != (byte) padLength)
                throw new Exception("Invalid padding bytes.");
        }

        byte[] result = new byte[input.length - padLength];
        System.arraycopy(input, 0, result, 0, result.length);
        return result;
    }

    /** Converts 8-byte array to a single long value (little-endian). */
    public static long bytesToLong(byte[] bytes) {
        if (bytes == null || bytes.length != 8)
            throw new IllegalArgumentException("Input must be 8 bytes.");

        long result = 0;
        for (int i = 0; i < 8; i++) {
            result |= ((long) bytes[i] & 0xFF) << (8 * i);
        }
        return result;
    }

    /** Converts a long to 8-byte array (little-endian). */
    public static byte[] longToBytes(long value) {
        byte[] result = new byte[8];
        for (int i = 0; i < 8; i++) {
            result[i] = (byte) ((value >> (8 * i)) & 0xFF);
        }
        return result;
    }
}



