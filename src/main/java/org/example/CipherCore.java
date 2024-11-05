package org.example;

public class CipherCore {
    private static final int BLOCK_SIZE = 16; // 128 bits
    private static final int ROUNDS = 14; // Ähnlich wie AES
    private byte[] key;

    public CipherCore(byte[] key) {
        this.key = key;
    }

    public byte[] encrypt(byte[] plaintext) {
        byte[] block = new byte[BLOCK_SIZE];
        System.arraycopy(plaintext, 0, block, 0, Math.min(plaintext.length, BLOCK_SIZE));

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
        byte[] block = new byte[BLOCK_SIZE];
        System.arraycopy(ciphertext, 0, block, 0, Math.min(ciphertext.length, BLOCK_SIZE));

        addRoundKey(block, ROUNDS); // Initial key addition for decryption
        for (int round = ROUNDS - 1; round >= 0; round--) {
            inverseMixColumns(block);
            inverseShiftRows(block);
            inverseSubstituteBytes(block);
            addRoundKey(block, round);
        }
        return block;
    }

    private void addRoundKey(byte[] block, int round) {
        for (int i = 0; i < block.length; i++) {
            block[i] ^= key[(i + round) % key.length];
        }
    }

    private void substituteBytes(byte[] block) {
        for (int i = 0; i < block.length; i++) {
            block[i] = (byte) ((block[i] * 31) ^ 101); // Beispielhafte, nicht-lineare Transformation
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
            block[i] = (byte) ((block[i] ^ 101) / 31); // Inverse der Substitution
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
}
