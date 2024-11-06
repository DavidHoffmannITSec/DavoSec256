package org.example;

import java.util.Arrays;

public class DavoSec256 {
    private static final int KEY_SIZE = 32; // 256 bits
    private static final int BLOCK_SIZE = 16; // 128 bits
    private static final int DEFAULT_BASE_ROUNDS = 24; // Default rounds
    private int baseRounds; // Anzahl der Runden
    private int reserveRounds; // Reservierte Runden

    private final byte[] key;
    private final byte[] iv;

    public DavoSec256() {
        CustomKeyGenerator keyGenerator = new CustomKeyGenerator();
        this.key = keyGenerator.getKey(); // Dynamisch generierter Schlüssel
        this.iv = generateDynamicIV(); // Dynamisch generierter Initialisierungsvektor
        this.baseRounds = DEFAULT_BASE_ROUNDS; // Setze die Basisrunden auf den Standardwert
        this.reserveRounds = 5; // Beispiel für reservierte Runden (kann angepasst werden)
    }

    // Methode zur Generierung eines dynamischen und komplexeren IVs
    private byte[] generateDynamicIV() {
        byte[] iv = new byte[BLOCK_SIZE];
        long seed = System.currentTimeMillis() ^ System.nanoTime() ^ Thread.currentThread().hashCode();

        for (int i = 0; i < iv.length; i++) {
            seed ^= (seed << 13) ^ (seed >> 7) ^ i;
            iv[i] = (byte) ((seed & 0xFF) ^ (rotateLeft((byte) seed, i % 8) & 0xFF));
            seed = (seed * 6364136223846793005L + 1442695040888963407L) ^ (seed >> 17);
        }
        return iv;
    }

    // Linksdrehung zur Transformation von Bits
    private byte rotateLeft(byte b, int bits) {
        return (byte) ((b << bits) | ((b & 0xFF) >>> (8 - bits)));
    }

    public static String byteArrayToHexString(byte[] bytes) {
        StringBuilder hexString = new StringBuilder(2 * bytes.length);
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xFF & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    // Verschlüsselungsmethode mit dynamischem IV
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

    // Entschlüsselungsmethode mit dynamischem IV
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
            throw new IllegalArgumentException("Ungültiges Padding: Wert " + paddingLength + " außerhalb der erwarteten Range 1-16.");
        }

        for (int i = 0; i < paddingLength; i++) {
            if (data[data.length - 1 - i] != (byte) paddingLength) {
                throw new IllegalArgumentException("Ungültiges Padding: Inkonsequentes Padding an Position " + (data.length - 1 - i));
            }
        }

        return Arrays.copyOf(data, data.length - paddingLength);
    }

    // Beispielhafte Implementierung der Transformationen
    private byte[] encryptBlock(byte[] block) {
        byte[] workingBlock = Arrays.copyOf(block, block.length);
        for (int round = 0; round < baseRounds; round++) {
            addRoundKey(workingBlock, round);
            substituteBytes(workingBlock, round);
            permuteBytes(workingBlock, round); // Dynamische Permutation
            mixColumns(workingBlock, round);
        }
        return workingBlock;
    }

    private byte[] decryptBlock(byte[] block) {
        byte[] workingBlock = Arrays.copyOf(block, block.length);
        for (int round = baseRounds - 1; round >= 0; round--) { // Verwende hier baseRounds
            reverseMixColumns(workingBlock, round);
            reversePermuteBytes(workingBlock, round); // Umgekehrte dynamische Permutation
            reverseSubstituteBytes(workingBlock, round);
            reverseAddRoundKey(workingBlock, round);
        }
        return workingBlock;
    }

    // Methoden zur Blocktransformation
    private void addRoundKey(byte[] block, int round) {
        for (int i = 0; i < BLOCK_SIZE; i++) {
            block[i] ^= key[i % key.length]; // XOR mit dem Schlüssel
        }
    }

    private void reverseAddRoundKey(byte[] block, int round) {
        for (int i = 0; i < BLOCK_SIZE; i++) {
            block[i] ^= key[i % key.length]; // XOR mit dem Schlüssel (bei der Rücktransformation dasselbe)
        }
    }

    // Dynamische S-Box
    private byte[] generateDynamicSBox(int round) {
        byte[] sBox = new byte[256];
        for (int i = 0; i < 256; i++) {
            sBox[i] = (byte) ((i + round) % 256); // Einfache dynamische S-Box
        }
        return sBox;
    }

    // Implementierung von substituteBytes
    private void substituteBytes(byte[] block, int round) {
        byte[] sBox = generateDynamicSBox(round); // Dynamisch generierte S-Box
        for (int i = 0; i < block.length; i++) {
            block[i] = sBox[block[i] & 0xFF]; // Anwenden der S-Box
        }
    }

    private void reverseSubstituteBytes(byte[] block, int round) {
        byte[] sBox = generateDynamicSBox(round); // Dynamisch generierte S-Box
        byte[] inverseSBox = new byte[256];
        for (int i = 0; i < 256; i++) {
            inverseSBox[sBox[i] & 0xFF] = (byte) i; // Erzeuge die inverse S-Box
        }
        for (int i = 0; i < block.length; i++) {
            block[i] = inverseSBox[block[i] & 0xFF]; // Anwenden der inversen S-Box
        }
    }

    // Implementierung von permuteBytes
    private void permuteBytes(byte[] block, int round) {
        // Dynamische Permutation basierend auf der aktuellen Runde
        byte[] permuted = new byte[BLOCK_SIZE];
        int[] permutation = generateDynamicPermutation(round); // Dynamische Permutation generieren

        for (int i = 0; i < BLOCK_SIZE; i++) {
            permuted[i] = block[permutation[i]];
        }
        System.arraycopy(permuted, 0, block, 0, BLOCK_SIZE);
    }

    // Dynamische Permutationsmethode
    private int[] generateDynamicPermutation(int round) {
        int[] permutation = new int[BLOCK_SIZE];
        for (int i = 0; i < BLOCK_SIZE; i++) {
            permutation[i] = (i + round) % BLOCK_SIZE; // Einfache Permutation basierend auf der Runde
        }
        return permutation;
    }

    // Implementierung von reversePermuteBytes
    private void reversePermuteBytes(byte[] block, int round) {
        // Umkehrung der dynamischen Permutation
        byte[] reversed = new byte[BLOCK_SIZE];
        int[] reversePermutation = generateDynamicPermutation(round); // Verwende dieselbe Permutation zur Umkehr

        for (int i = 0; i < BLOCK_SIZE; i++) {
            reversed[reversePermutation[i]] = block[i]; // Umkehren der Permutation
        }
        System.arraycopy(reversed, 0, block, 0, BLOCK_SIZE);
    }

    // Methoden für die Blocktransformationen
    private void mixColumns(byte[] block, int round) { /* Implementierung */ }
    private void reverseMixColumns(byte[] block, int round) { /* Implementierung */ }

    private void xorWithIV(byte[] block, byte[] iv) {
        for (int i = 0; i < block.length; i++) {
            block[i] ^= iv[i];
        }
    }

    // Methode zur Anzeige des Schlüssels und IVs in Hex-Format
    public void displayKeyAndIV() {
        System.out.println("Schlüssel (Hex): " + byteArrayToHexString(key));
        System.out.println("IV (Hex): " + byteArrayToHexString(iv));
    }

    // Getter für baseRounds und reserveRounds
    public int getBaseRounds() {
        return baseRounds;
    }

    public int getReserveRounds() {
        return reserveRounds;
    }

    // Setter für baseRounds und reserveRounds
    public void setBaseRounds(int baseRounds) {
        this.baseRounds = baseRounds;
    }

    public void setReserveRounds(int reserveRounds) {
        this.reserveRounds = reserveRounds;
    }
}
