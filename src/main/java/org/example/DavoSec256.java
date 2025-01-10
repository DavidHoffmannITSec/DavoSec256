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
        this.ckg = new CustomKeyGenerator();
        this.key = ckg.getKey();
        this.iv = generateDynamicIV();
        int dataLength = this.key.length;
        this.baseRounds = 18 + (key.length % 5) + (dataLength / BLOCK_SIZE);
        this.S_BOX = generateDynamicSBox(this.key, this.iv);
        this.INVERSE_S_BOX = generateInverseSBox(this.S_BOX);
        this.PERMUTATION = generateDynamicPermutation(this.key, this.iv);
    }

    private byte[] generateDynamicIV() {
        byte[] iv = new byte[BLOCK_SIZE];
        long seed = Arrays.hashCode(key) ^ System.nanoTime() ^ Runtime.getRuntime().freeMemory();
        seed ^= (seed << 21) ^ (seed >> 17) ^ System.currentTimeMillis();

        Random random = new Random(seed);
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

        this.S_BOX = generateDynamicSBox(this.key, this.iv);
        this.INVERSE_S_BOX = generateInverseSBox(this.S_BOX);
        this.PERMUTATION = generateDynamicPermutation(this.key, this.iv);
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
            fixedTimeBlockProcessing(plaintextBlock);
            byte[] encryptedBlock = encryptBlock(plaintextBlock);
            System.arraycopy(encryptedBlock, 0, ciphertext, i, BLOCK_SIZE);
            currentIV = encryptedBlock;

            // Dummy-Operationen für Stabilität
            performTimingConsistentNOP();
        }

        ensureTimingConsistency();
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

            // Konsistente Blockverarbeitungszeit in der Entschlüsselungsschleife
            fixedTimeBlockProcessing(ciphertextBlock);

            byte[] decryptedBlock = decryptBlock(ciphertextBlock);
            xorWithIV(decryptedBlock, currentIV);
            System.arraycopy(decryptedBlock, 0, decryptedText, i, BLOCK_SIZE);
            currentIV = ciphertextBlock;

            // Dummy-Operationen für Timing-Konsistenz in der Entschlüsselungsschleife
            performTimingConsistentNOP();
        }

        ensureTimingConsistency();
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
        int adjustedRounds = baseRounds + 5;

        for (int round = 0; round < adjustedRounds; round++) {
            addRoundKey(workingBlock, round);
            substituteBytes(workingBlock);
            permuteBytes(workingBlock);
            mixColumns(workingBlock);
        }
        return workingBlock;
    }


    private byte[] decryptBlock(byte[] block) {
        byte[] workingBlock = Arrays.copyOf(block, block.length);
        int adjustedRounds = baseRounds + 5; // Konsistente Rundenzahl wie bei `encryptBlock`

        for (int round = adjustedRounds - 1; round >= 0; round--) {
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

    private void performTimingConsistentNOP() {
        int dummySum = 0;
        for (int i = 0; i < 1000; i++) {
            dummySum += i * 37;
            dummySum ^= (dummySum << 5) ^ (dummySum >> 3);
        }

        if (dummySum == Integer.MAX_VALUE) {
            System.out.println("Timing consistency check");
        }
    }

    private void reverseAddRoundKey(byte[] block, int round) {
        addRoundKey(block, round);
    }

    private void fixedTimeBlockProcessing(byte[] block) {
        long targetTimeNs = 1_200_000; // Zielzeit in Nanosekunden

        long startTime = System.nanoTime();
        encryptBlock(block); // Die eigentliche Blockverschlüsselung

        while (System.nanoTime() - startTime < targetTimeNs) {
            dummyOperation();
        }
    }

    private void dummyOperation() {
        for (int i = 0; i < 1000; i++) {
            int dummySum = (i * 31) ^ (i << 3);
        }
    }


    private void substituteBytes(byte[] block) {
        int dummySum = 0; // Dummy-Wert zur Konsistenz
        for (int i = 0; i < block.length; i++) {
            block[i] = S_BOX[block[i] & 0xFF];
            dummySum += block[i]; // Dummy-Berechnung für Konsistenz
        }

        if (dummySum == Integer.MAX_VALUE) {
            System.out.println("Dummy operation in substituteBytes");
        }
    }


    private void reverseSubstituteBytes(byte[] block) {
        for (int i = 0; i < block.length; i++) {
            block[i] = INVERSE_S_BOX[block[i] & 0xFF];
        }
    }

    private void permuteBytes(byte[] block) {
        byte[] permuted = new byte[BLOCK_SIZE];
        int dummySum = 0; // Dummy-Wert zur Konsistenz
        for (int i = 0; i < BLOCK_SIZE; i++) {
            permuted[i] = block[PERMUTATION[i]];
            dummySum += permuted[i]; // Dummy-Berechnung für Konsistenz
        }
        System.arraycopy(permuted, 0, block, 0, BLOCK_SIZE);

        if (dummySum == Integer.MAX_VALUE) {
            System.out.println("Dummy operation in permuteBytes");
        }
    }

    private void ensureTimingConsistency() {
        int dummyResult = 0;
        for (int i = 0; i < 1000; i++) {
            dummyResult += (i * i) ^ (i << 3);
        }

        if (dummyResult == Integer.MAX_VALUE) {
            System.out.println("Timing consistency check");
        }
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


    public byte[] getS_BOX()
    {
        return S_BOX;
    }

    public byte[] getKey()
    {
        return key;
    }


    public int[] getPERMUTATION()
    {
        return PERMUTATION;
    }

    public byte[] getSalt(){
        return ckg.getSalt();
    }

    public String getSeed(){
        return ckg.getSeed();
    }
}
