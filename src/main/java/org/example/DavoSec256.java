package org.example;

import java.security.SecureRandom;
import java.util.Arrays;

public class DavoSec256 {
    private static final int KEY_SIZE = 32; // 256 bits
    private static final int BLOCK_SIZE = 16; // 128 bits
    private static final int ROUNDS = 14; // Similar to AES

    private byte[] key;

    public DavoSec256() {
        key = new byte[KEY_SIZE];
        SecureRandom random = new SecureRandom();
        random.nextBytes(key);
    }

    public byte[] encrypt(byte[] plaintext) {
        byte[] block = Arrays.copyOf(plaintext, BLOCK_SIZE);

        for (int round = 0; round < ROUNDS; round++) {
            addRoundKey(block, round);
            substituteBytes(block);
            shiftRows(block);
            mixColumns(block);
        }
        addRoundKey(block, ROUNDS); // Final round key addition
        return block;
    }

    public byte[] decrypt(byte[] ciphertext) {
        byte[] block = Arrays.copyOf(ciphertext, BLOCK_SIZE);

        addRoundKey(block, ROUNDS); // Initial key addition for decryption
        for (int round = ROUNDS - 1; round >= 0; round--) {
            inverseMixColumns(block);
            inverseShiftRows(block);
            inverseSubstituteBytes(block);
            addRoundKey(block, round);
        }
        return block;
    }

    public String encryptText(String plaintext) {
        byte[] plaintextBytes = plaintext.getBytes();
        byte[] encryptedBytes = encrypt(plaintextBytes);
        return bytesToHex(encryptedBytes);
    }

    public String decryptText(String hexCiphertext) {
        byte[] ciphertextBytes = hexToBytes(hexCiphertext);
        byte[] decryptedBytes = decrypt(ciphertextBytes);
        return new String(decryptedBytes).trim(); // Trimming any padding
    }

    private void addRoundKey(byte[] block, int round) {
        for (int i = 0; i < block.length; i++) {
            block[i] ^= key[(i + round) % key.length];
        }
    }

    private void substituteBytes(byte[] block) {
        for (int i = 0; i < block.length; i++) {
            block[i] = (byte) ((block[i] * 31) ^ 101); // Simple non-linear transformation
        }
    }

    private void shiftRows(byte[] block) {
        byte temp = block[1];
        block[1] = block[5];
        block[5] = block[9];
        block[9] = block[13];
        block[13] = temp;
    }

    private void mixColumns(byte[] block) {
        for (int i = 0; i < 4; i++) {
            int a = block[i];
            int b = block[i + 4];
            int c = block[i + 8];
            int d = block[i + 12];

            block[i] = (byte) (a ^ b ^ c ^ d);
            block[i + 4] = (byte) (b ^ c ^ d ^ a);
            block[i + 8] = (byte) (c ^ d ^ a ^ b);
            block[i + 12] = (byte) (d ^ a ^ b ^ c);
        }
    }

    private void inverseSubstituteBytes(byte[] block) {
        for (int i = 0; i < block.length; i++) {
            block[i] = (byte) ((block[i] ^ 101) / 31);
        }
    }

    private void inverseShiftRows(byte[] block) {
        byte temp = block[13];
        block[13] = block[9];
        block[9] = block[5];
        block[5] = block[1];
        block[1] = temp;
    }

    private void inverseMixColumns(byte[] block) {
        for (int i = 0; i < 4; i++) {
            int a = block[i];
            int b = block[i + 4];
            int c = block[i + 8];
            int d = block[i + 12];

            block[i] = (byte) (a ^ d);
            block[i + 4] = (byte) (b ^ c);
            block[i + 8] = (byte) (c ^ b);
            block[i + 12] = (byte) (d ^ a);
        }
    }

    // Method to convert byte array to hex string
    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder(2 * bytes.length);
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    // Method to convert hex string to byte array
    public static byte[] hexToBytes(String hexString) {
        int len = hexString.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                    + Character.digit(hexString.charAt(i+1), 16));
        }
        return data;
    }
}
