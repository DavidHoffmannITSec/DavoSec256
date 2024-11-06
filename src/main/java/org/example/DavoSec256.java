package org.example;

import java.io.*;
import java.util.Arrays;
import java.util.Random;
import java.util.stream.IntStream;

public class DavoSec256 {
    private static final int KEY_SIZE = 32; // 256 bits
    private static final int BLOCK_SIZE = 16; // 128 bits
    private int baseRounds;

    private byte[] key; // Schlüssel
    private byte[] iv;  // Initialisierungsvektor

    private byte[] S_BOX;
    private byte[] INVERSE_S_BOX;
    private int[] PERMUTATION;

    CustomKeyGenerator ckg;

    private static final byte[][] MIX_COLUMNS_MATRIX = {
            {2, 3, 1, 1},
            {1, 2, 3, 1},
            {1, 1, 2, 3},
            {3, 1, 1, 2}
    };

    private static final byte[][] INV_MIX_COLUMNS_MATRIX = {
            {14, 11, 13, 9},
            {9, 14, 11, 13},
            {13, 9, 14, 11},
            {11, 13, 9, 14}
    };

    public DavoSec256() {
        this.ckg = new CustomKeyGenerator();
    }

    public DavoSec256(int delay) {
        this.ckg = new CustomKeyGenerator(delay);
    }

    public void generateKey() {
        this.key = ckg.getKey();
        this.iv = generateDynamicIV();
        int dataLength = this.key.length; // Automatische Berechnung der Datenlänge
        this.baseRounds = 18 + (key.length % 5) + (dataLength / BLOCK_SIZE);
        this.S_BOX = generateDynamicSBox(this.key, this.iv);
        this.INVERSE_S_BOX = generateInverseSBox(this.S_BOX);
        this.PERMUTATION = generateDynamicPermutation(this.key, this.iv);

        testSBoxForCollisions(this.S_BOX);
        testPermutationForCollisions(this.PERMUTATION);
    }

    private byte[] generateDynamicIV() {
        byte[] iv = new byte[BLOCK_SIZE];
        Random random = new Random(Arrays.hashCode(key) ^ System.nanoTime() ^ Runtime.getRuntime().freeMemory());
        random.nextBytes(iv);
        return iv;
    }

    public void saveKeyAndIV(String filePath) throws IOException {
        try (DataOutputStream dos = new DataOutputStream(new FileOutputStream(filePath))) {
            dos.write(key);
            dos.write(iv);
        }
    }

    public void loadKeyAndIV(String filePath) throws IOException {
        byte[] keyBytes = new byte[KEY_SIZE];
        byte[] ivBytes = new byte[BLOCK_SIZE];
        try (DataInputStream dis = new DataInputStream(new FileInputStream(filePath))) {
            dis.readFully(keyBytes);
            dis.readFully(ivBytes);
        }
        this.key = keyBytes;
        this.iv = ivBytes;
    }

    public byte[] encrypt(byte[] plaintext) {
        if (plaintext.length == 0) {
            throw new IllegalArgumentException("Eingabetext darf nicht leer sein.");
        }

        byte[] paddedPlaintext = pad(plaintext);
        byte[] ciphertext = new byte[paddedPlaintext.length];
        byte[] currentIV = Arrays.copyOf(iv, BLOCK_SIZE);

        for (int i = 0; i < paddedPlaintext.length; i += BLOCK_SIZE) {
            byte[] plaintextBlock = Arrays.copyOfRange(paddedPlaintext, i, i + BLOCK_SIZE);
            xorWithIV(plaintextBlock, currentIV);
            byte[] encryptedBlock = encryptBlock(plaintextBlock);
            System.arraycopy(encryptedBlock, 0, ciphertext, i, BLOCK_SIZE);
            currentIV = encryptedBlock;
        }

        return ciphertext;
    }

    public byte[] decrypt(byte[] ciphertext) {
        if (ciphertext.length % BLOCK_SIZE != 0) {
            throw new IllegalArgumentException("Ungültige Länge des verschlüsselten Textes.");
        }

        byte[] decryptedText = new byte[ciphertext.length];
        byte[] currentIV = Arrays.copyOf(iv, BLOCK_SIZE);

        for (int i = 0; i < ciphertext.length; i += BLOCK_SIZE) {
            byte[] ciphertextBlock = Arrays.copyOfRange(ciphertext, i, i + BLOCK_SIZE);
            byte[] decryptedBlock = decryptBlock(ciphertextBlock);
            xorWithIV(decryptedBlock, currentIV);
            System.arraycopy(decryptedBlock, 0, decryptedText, i, BLOCK_SIZE);
            currentIV = ciphertextBlock;
        }

        return removePadding(decryptedText);
    }

    private byte[] pad(byte[] data) {
        int paddingLength = BLOCK_SIZE - (data.length % BLOCK_SIZE);
        byte[] padded = Arrays.copyOf(data, data.length + paddingLength);
        Arrays.fill(padded, data.length, padded.length, (byte) paddingLength);
        return padded;
    }

    private byte[] removePadding(byte[] data) {
        int paddingLength = data[data.length - 1] & 0xFF;

        if (paddingLength < 1 || paddingLength > BLOCK_SIZE) {
            throw new IllegalArgumentException("Ungültiges Padding: Padding-Length außerhalb der gültigen Grenzen");
        }

        for (int i = data.length - paddingLength; i < data.length; i++) {
            if (data[i] != (byte) paddingLength) {
                throw new IllegalArgumentException("Ungültiges Padding: inkonsistentes Padding");
            }
        }

        return Arrays.copyOf(data, data.length - paddingLength);
    }

    private byte[] encryptBlock(byte[] block) {
        byte[] workingBlock = Arrays.copyOf(block, block.length);
        for (int round = 0; round < baseRounds; round++) {
            addRoundKey(workingBlock, round);
            substituteBytes(workingBlock);
            permuteBytes(workingBlock);
            mixColumns(workingBlock);
        }
        return workingBlock;
    }

    private byte[] decryptBlock(byte[] block) {
        byte[] workingBlock = Arrays.copyOf(block, block.length);
        for (int round = baseRounds - 1; round >= 0; round--) {
            reverseMixColumns(workingBlock);
            reversePermuteBytes(workingBlock);
            reverseSubstituteBytes(workingBlock);
            reverseAddRoundKey(workingBlock, round);
        }
        return workingBlock;
    }

    private void addRoundKey(byte[] block, int round) {
        IntStream.range(0, BLOCK_SIZE).parallel().forEach(i -> block[i] ^= key[(i + round) % KEY_SIZE]);
    }

    private void reverseAddRoundKey(byte[] block, int round) {
        addRoundKey(block, round);
    }

    private void substituteBytes(byte[] block) {
        for (int i = 0; i < block.length; i++) {
            block[i] = S_BOX[block[i] & 0xFF];
        }
    }

    private void reverseSubstituteBytes(byte[] block) {
        for (int i = 0; i < block.length; i++) {
            block[i] = INVERSE_S_BOX[block[i] & 0xFF];
        }
    }

    private void permuteBytes(byte[] block) {
        byte[] permuted = new byte[BLOCK_SIZE];
        for (int i = 0; i < BLOCK_SIZE; i++) {
            permuted[i] = block[PERMUTATION[i]];
        }
        System.arraycopy(permuted, 0, block, 0, BLOCK_SIZE);
    }

    private void reversePermuteBytes(byte[] block) {
        byte[] reversed = new byte[BLOCK_SIZE];
        for (int i = 0; i < BLOCK_SIZE; i++) {
            reversed[PERMUTATION[i]] = block[i];
        }
        System.arraycopy(reversed, 0, block, 0, BLOCK_SIZE);
    }

    private void mixColumns(byte[] block) {
        mixColumnsWithMatrix(block, MIX_COLUMNS_MATRIX);
    }

    private void reverseMixColumns(byte[] block) {
        mixColumnsWithMatrix(block, INV_MIX_COLUMNS_MATRIX);
    }

    private void mixColumnsWithMatrix(byte[] block, byte[][] matrix) {
        byte[] mixed = new byte[BLOCK_SIZE];
        for (int i = 0; i < BLOCK_SIZE; i += 4) {
            for (int j = 0; j < 4; j++) {
                mixed[i + j] = 0;
                for (int k = 0; k < 4; k++) {
                    mixed[i + j] ^= galoisMultiply(block[i + k], matrix[j][k]);
                }
            }
        }
        System.arraycopy(mixed, 0, block, 0, BLOCK_SIZE);
    }

    private static byte galoisMultiply(byte a, byte b) {
        int product = 0;
        for (int i = 0; i < 8; i++) {
            if ((b & 1) != 0) {
                product ^= a;
            }
            boolean highBitSet = (a & 0x80) != 0;
            a <<= 1;
            if (highBitSet) {
                a ^= 0x1b; // Modulo x^8 + x^4 + x^3 + x + 1
            }
            b >>= 1;
        }
        return (byte) product;
    }

    private void xorWithIV(byte[] block, byte[] iv) {
        for (int i = 0; i < block.length; i++) {
            block[i] ^= iv[i];
            iv[i] = (byte) ((iv[i] + block[i]) % 256); // Dynamische Anpassung des IV
        }
    }

    private void testSBoxForCollisions(byte[] sBox) {
        boolean[] seen = new boolean[256];
        for (byte value : sBox) {
            int idx = value & 0xFF;
            if (seen[idx]) {
                throw new IllegalStateException("Kollision in der S-Box festgestellt!");
            }
            seen[idx] = true;
        }
    }

    private void testPermutationForCollisions(int[] permutation) {
        boolean[] seen = new boolean[BLOCK_SIZE];
        for (int value : permutation) {
            if (value < 0 || value >= BLOCK_SIZE || seen[value]) {
                throw new IllegalStateException("Kollision in der Permutationsmatrix festgestellt!");
            }
            seen[value] = true;
        }
    }

    private byte[] generateDynamicSBox(byte[] key, byte[] iv) {
        byte[] sBox = new byte[256];
        boolean[] used = new boolean[256];
        Random random = new Random(Arrays.hashCode(key) ^ Arrays.hashCode(iv));

        for (int i = 0; i < 256; i++) {
            sBox[i] = (byte) i;
        }

        for (int i = 0; i < 256; i++) {
            int j = Math.abs(i * i + 11 + key[i % key.length]) % 256;
            byte temp = sBox[i];
            sBox[i] = sBox[j];
            sBox[j] = temp;
        }

        for (int i = 0; i < 256; i++) {
            sBox[i] = (byte) (sBox[i] ^ (sBox[Math.floorMod(i + 1, 256)] * 31) ^ (sBox[Math.floorMod(i + 3, 256)] >> 2));
            sBox[i] = (byte) ((sBox[i] * 197) ^ (sBox[i] >>> 5) ^ (sBox[i] * 37));
        }

        for (int i = 0; i < 256; i++) {
            int newValue;
            do {
                newValue = Math.floorMod(random.nextInt(256) ^ sBox[i], 256);
            } while (used[newValue]);
            sBox[i] = (byte) newValue;
            used[newValue] = true;
        }

        return sBox;
    }

    private byte[] generateInverseSBox(byte[] sBox) {
        byte[] inverseSBox = new byte[256];
        for (int i = 0; i < 256; i++) {
            inverseSBox[sBox[i] & 0xFF] = (byte) i;
        }
        return inverseSBox;
    }

    private int[] generateDynamicPermutation(byte[] key, byte[] iv) {
        int[] permutation = new int[BLOCK_SIZE];
        Random random = new Random(Arrays.hashCode(key) ^ Arrays.hashCode(iv));

        for (int i = 0; i < BLOCK_SIZE; i++) {
            permutation[i] = i;
        }

        for (int i = BLOCK_SIZE - 1; i > 0; i--) {
            int j = random.nextInt(i + 1);
            int temp = permutation[i];
            permutation[i] = permutation[j];
            permutation[j] = temp;
        }

        return permutation;
    }

    public String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

}
