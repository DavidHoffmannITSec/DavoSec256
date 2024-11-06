package org.example;

import java.util.Arrays;

public class DavoSec256 {
    private static final int KEY_SIZE = 32; // 256 bits
    private static final int BLOCK_SIZE = 16; // 128 bits
    private static final int BASE_ROUNDS = 24; // Default rounds

    private final byte[] key;
    private final byte[] iv;

    public DavoSec256() {
        CustomKeyGenerator keyGenerator = new CustomKeyGenerator();
        this.key = keyGenerator.getKey();
        this.iv = generateDynamicIV();
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

    // Beispielhafte Implementierung der Transformationen (Platzhalter)
    private byte[] encryptBlock(byte[] block) {
        byte[] workingBlock = Arrays.copyOf(block, block.length);
        for (int round = 0; round < BASE_ROUNDS; round++) {
            addRoundKey(workingBlock, round);
            substituteBytes(workingBlock, round);
            permuteBytes(workingBlock, round);
            mixColumns(workingBlock, round);
        }
        return workingBlock;
    }

    private byte[] decryptBlock(byte[] block) {
        byte[] workingBlock = Arrays.copyOf(block, block.length);
        for (int round = BASE_ROUNDS - 1; round >= 0; round--) {
            reverseMixColumns(workingBlock, round);
            reversePermuteBytes(workingBlock, round);
            reverseSubstituteBytes(workingBlock, round);
            reverseAddRoundKey(workingBlock, round);
        }
        return workingBlock;
    }

    // Zusätzliche Methoden für die Blocktransformationen (noch zu implementieren)
    private void addRoundKey(byte[] block, int round) { /* Implementierung */ }
    private void substituteBytes(byte[] block, int round) { /* Implementierung */ }
    private void permuteBytes(byte[] block, int round) { /* Implementierung */ }
    private void mixColumns(byte[] block, int round) { /* Implementierung */ }
    private void reverseAddRoundKey(byte[] block, int round) { /* Implementierung */ }
    private void reverseSubstituteBytes(byte[] block, int round) { /* Implementierung */ }
    private void reversePermuteBytes(byte[] block, int round) { /* Implementierung */ }
    private void reverseMixColumns(byte[] block, int round) { /* Implementierung */ }

    private void xorWithIV(byte[] block, byte[] iv) {
        for (int i = 0; i < block.length; i++) {
            block[i] ^= iv[i];
        }
    }
}
