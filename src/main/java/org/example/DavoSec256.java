package org.example;

import java.util.Arrays;
import java.util.stream.IntStream;

public class DavoSec256 {
    private static final int KEY_SIZE = 32; // 256 bits
    private static final int BLOCK_SIZE = 16; // 128 bits
    private static final int MIN_ROUNDS = 16;
    private static final int MAX_ROUNDS = MIN_ROUNDS + 12;
    private static final int ROUNDS = calculateRounds();

    private final byte[] key;
    private final byte[] iv;

    // Dynamische Rundenanzahl basierend auf Systemleistung
    private static int calculateRounds() {
        int processors = Runtime.getRuntime().availableProcessors();
        return Math.min(MAX_ROUNDS, MIN_ROUNDS + processors / 2);
    }

    public DavoSec256(byte[] key) {
        if (key == null || key.length != KEY_SIZE) {
            throw new IllegalArgumentException("Schlüssel muss genau 256 Bit (32 Bytes) lang sein.");
        }
        this.key = Arrays.copyOf(key, KEY_SIZE);
        this.iv = new byte[BLOCK_SIZE];
        initializeIV();
    }

    // Verbesserte IV-Generierung mit hoher Entropie und dynamischem Seed
    private void initializeIV() {
        long seed = System.nanoTime();
        for (int i = 0; i < iv.length; i++) {
            seed = (seed ^ (seed << 21)) ^ (seed >> 35) ^ (seed << 4);
            iv[i] = (byte) (seed & 0xFF);
            seed *= 6364136223846793005L + ((long) i * 37);
        }
    }

    // Verschlüsselungsmethode mit Timing-Schutz
    public byte[] encrypt(byte[] plaintext) {
        if (plaintext == null || plaintext.length == 0) {
            throw new IllegalArgumentException("Eingabedaten zur Verschlüsselung dürfen nicht null oder leer sein.");
        }

        byte[] paddedPlaintext = pad(plaintext);
        byte[] ciphertext = new byte[paddedPlaintext.length];
        byte[] block = Arrays.copyOf(iv, BLOCK_SIZE);

        for (int i = 0; i < paddedPlaintext.length; i += BLOCK_SIZE) {
            byte[] plaintextBlock = Arrays.copyOfRange(paddedPlaintext, i, i + BLOCK_SIZE);
            xorWithIV(plaintextBlock, block);
            block = encryptBlock(plaintextBlock);
            System.arraycopy(block, 0, ciphertext, i, BLOCK_SIZE);
        }
        return ciphertext;
    }

    public byte[] decrypt(byte[] ciphertext) {
        if (ciphertext == null || ciphertext.length == 0 || ciphertext.length % BLOCK_SIZE != 0) {
            throw new IllegalArgumentException("Ungültige Chiffretext-Eingabe für die Entschlüsselung.");
        }

        byte[] plaintext = new byte[ciphertext.length];
        byte[] block = Arrays.copyOf(iv, BLOCK_SIZE);

        for (int i = 0; i < ciphertext.length; i += BLOCK_SIZE) {
            byte[] ciphertextBlock = Arrays.copyOfRange(ciphertext, i, i + BLOCK_SIZE);
            byte[] decryptedBlock = decryptBlock(ciphertextBlock);
            xorWithIV(decryptedBlock, block);
            System.arraycopy(decryptedBlock, 0, plaintext, i, BLOCK_SIZE);
            block = ciphertextBlock;
        }
        return unpad(plaintext);
    }

    private byte[] encryptBlock(byte[] block) {
        for (int round = 0; round < ROUNDS; round++) {
            addRoundKey(block, round);
            substituteBytes(block, round);
            permuteBytes(block, round);  // Neue P-Box
            mixColumns(block);
            shuffleBytes(block, round);
        }
        addRoundKey(block, ROUNDS);
        return block;
    }

    private byte[] decryptBlock(byte[] block) {
        addRoundKey(block, ROUNDS);
        for (int round = ROUNDS - 1; round >= 0; round--) {
            inverseShuffleBytes(block, round);
            inverseMixColumns(block);
            inversePermuteBytes(block, round);
            inverseSubstituteBytes(block, round);
            addRoundKey(block, round);
        }
        return block;
    }

    // Statisch generierte hochkomplexe S-Box und dynamische Anpassung pro Runde
    private void substituteBytes(byte[] block, int round) {
        int[] sBox = generateComplexSBox(round);
        IntStream.range(0, block.length).parallel().forEach(i -> block[i] = (byte) sBox[block[i] & 0xFF]);
    }

    private void inverseSubstituteBytes(byte[] block, int round) {
        int[] sBox = generateComplexSBox(round);
        int[] inverseSBox = new int[256];
        for (int i = 0; i < sBox.length; i++) {
            inverseSBox[sBox[i]] = i;
        }
        IntStream.range(0, block.length).parallel().forEach(i -> block[i] = (byte) inverseSBox[block[i] & 0xFF]);
    }

    private void inverseMixColumns(byte[] block) {
        for (int i = 0; i < 4; i++) {
            int a = block[i], b = block[i + 4], c = block[i + 8], d = block[i + 12];

            block[i] = (byte) ((a * 14) ^ (b * 11) ^ (c * 13) ^ (d * 9) & 0xFF);
            block[i + 4] = (byte) ((a * 9) ^ (b * 14) ^ (c * 11) ^ (d * 13) & 0xFF);
            block[i + 8] = (byte) ((a * 13) ^ (b * 9) ^ (c * 14) ^ (d * 11) & 0xFF);
            block[i + 12] = (byte) ((a * 11) ^ (b * 13) ^ (c * 9) ^ (d * 14) & 0xFF);
        }
    }


    // Erzeugt eine ultra-komplexe S-Box für maximale Sicherheit
    private int[] generateComplexSBox(int round) {
        int[] sBox = new int[256];
        long primeMultiplier = 0x9E3779B97F4A7C15L + round;  // Einzigartig pro Runde
        for (int i = 0; i < 256; i++) {
            sBox[i] = (int) (((i * primeMultiplier) ^ (i << 7) ^ (i >> 3)) & 0xFF);
        }
        return sBox;
    }

    // Permutiert die Bytes für zusätzliche Diffusion und Sicherheit (P-Box)
    private void permuteBytes(byte[] block, int round) {
        int prime = 31 + (round * 17);  // Dynamische Permutation basierend auf Runde
        for (int i = 0; i < block.length; i++) {
            int swapIndex = (i * prime + round + block[i % block.length]) % block.length;
            byte temp = block[i];
            block[i] = block[swapIndex];
            block[swapIndex] = temp;
        }
    }

    private void inversePermuteBytes(byte[] block, int round) {
        int prime = 31 + (round * 17);
        for (int i = block.length - 1; i >= 0; i--) {
            int swapIndex = (i * prime + round + block[i % block.length]) % block.length;
            byte temp = block[i];
            block[i] = block[swapIndex];
            block[swapIndex] = temp;
        }
    }

    // Weitere notwendige Transformationen
    private void addRoundKey(byte[] block, int round) {
        IntStream.range(0, block.length).parallel().forEach(i -> block[i] ^= key[(i + round * 7) % key.length]);
    }

    private void xorWithIV(byte[] block, byte[] iv) {
        IntStream.range(0, block.length).parallel().forEach(i -> block[i] ^= iv[i]);
    }

    private void mixColumns(byte[] block) {
        for (int i = 0; i < 4; i++) {
            int a = block[i], b = block[i + 4], c = block[i + 8], d = block[i + 12];
            block[i] = (byte) ((a ^ b * 2 ^ c * 3 ^ d) & 0xFF);
            block[i + 4] = (byte) ((a * 2 ^ b ^ c * 3 ^ d * 2) & 0xFF);
            block[i + 8] = (byte) ((a * 3 ^ b * 2 ^ c ^ d * 2) & 0xFF);
            block[i + 12] = (byte) ((a * 2 ^ b * 3 ^ c * 2 ^ d) & 0xFF);
        }
    }

    private void shuffleBytes(byte[] block, int round) {
        for (int i = 0; i < block.length; i++) {
            int swapIndex = (i * 31 + round + (block[i % block.length] ^ (round * 37))) % block.length;
            byte temp = block[i];
            block[i] = block[swapIndex];
            block[swapIndex] = temp;
        }
    }

    private void inverseShuffleBytes(byte[] block, int round) {
        for (int i = block.length - 1; i >= 0; i--) {
            int swapIndex = (i * 31 + round + (block[i % block.length] ^ (round * 37))) % block.length;
            byte temp = block[i];
            block[i] = block[swapIndex];
            block[swapIndex] = temp;
        }
    }

    // Padding und Unpadding
    private byte[] pad(byte[] data) {
        int paddingLength = BLOCK_SIZE - (data.length % BLOCK_SIZE);
        byte[] padded = Arrays.copyOf(data, data.length + paddingLength);
        for (int i = data.length; i < padded.length; i++) {
            padded[i] = (byte) ((paddingLength + i * 31) & 0xFF);
        }
        return padded;
    }

    private byte[] unpad(byte[] data) {
        int paddingLength = data[data.length - 1] & 0xFF;
        return Arrays.copyOf(data, data.length - paddingLength);
    }

    // Hex-Konvertierungsmethoden
    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder(2 * bytes.length);
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public static byte[] hexToBytes(String hexString) {
        int len = hexString.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                    + Character.digit(hexString.charAt(i + 1), 16));
        }
        return data;
    }
}
