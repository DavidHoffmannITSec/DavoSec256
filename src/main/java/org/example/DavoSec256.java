package org.example;

import java.util.Arrays;

public class DavoSec256 {
    private static final int KEY_SIZE = 32; // 256 bits
    private static final int BLOCK_SIZE = 16; // 128 bits
    private static final int DEFAULT_BASE_ROUNDS = 24; // Default rounds
    private int baseRounds; // Anzahl der Runden

    private final byte[] key;
    private final byte[] iv;

    public DavoSec256() {
        CustomKeyGenerator keyGenerator = new CustomKeyGenerator();
        this.key = keyGenerator.getKey(); // Dynamisch generierter Schlüssel
        this.iv = generateDynamicIV(); // Dynamisch generierter Initialisierungsvektor
        this.baseRounds = DEFAULT_BASE_ROUNDS; // Setze die Basisrunden auf den Standardwert
    }

    private byte[] generateDynamicIV() {
        byte[] iv = new byte[BLOCK_SIZE];
        // Zufällige IV-Generierung
        for (int i = 0; i < BLOCK_SIZE; i++) {
            iv[i] = (byte) (Math.random() * 256);
        }
        return iv;
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
            throw new IllegalArgumentException("Ungültiges Padding: Wert " + paddingLength + " außerhalb der erwarteten Range 1-16.");
        }

        for (int i = 0; i < paddingLength; i++) {
            if (data[data.length - 1 - i] != (byte) paddingLength) {
                throw new IllegalArgumentException("Ungültiges Padding: Inkonsequentes Padding an Position " + (data.length - 1 - i));
            }
        }

        return Arrays.copyOf(data, data.length - paddingLength);
    }

    private byte[] encryptBlock(byte[] block) {
        byte[] workingBlock = Arrays.copyOf(block, block.length);
        for (int round = 0; round < baseRounds; round++) {
            addRoundKey(workingBlock, round);
            substituteBytes(workingBlock, round);
            permuteBytes(workingBlock, round);
            mixColumns(workingBlock, round);
        }
        return workingBlock;
    }

    private byte[] decryptBlock(byte[] block) {
        byte[] workingBlock = Arrays.copyOf(block, block.length);
        for (int round = baseRounds - 1; round >= 0; round--) {
            reverseMixColumns(workingBlock, round);
            reversePermuteBytes(workingBlock, round);
            reverseSubstituteBytes(workingBlock, round);
            reverseAddRoundKey(workingBlock, round);
        }
        return workingBlock;
    }

    private void addRoundKey(byte[] block, int round) {
        for (int i = 0; i < BLOCK_SIZE; i++) {
            block[i] ^= key[i % key.length];
        }
    }

    private void reverseAddRoundKey(byte[] block, int round) {
        for (int i = 0; i < BLOCK_SIZE; i++) {
            block[i] ^= key[i % key.length];
        }
    }

    private byte[] generateDynamicSBox(int round) {
        byte[] sBox = new byte[256];
        for (int i = 0; i < 256; i++) {
            sBox[i] = (byte) ((i + round) % 256);
        }
        return sBox;
    }

    private void substituteBytes(byte[] block, int round) {
        byte[] sBox = generateDynamicSBox(round);
        for (int i = 0; i < block.length; i++) {
            block[i] = sBox[block[i] & 0xFF];
        }
    }

    private void reverseSubstituteBytes(byte[] block, int round) {
        byte[] sBox = generateDynamicSBox(round);
        byte[] inverseSBox = new byte[256];
        for (int i = 0; i < 256; i++) {
            inverseSBox[sBox[i] & 0xFF] = (byte) i;
        }
        for (int i = 0; i < block.length; i++) {
            block[i] = inverseSBox[block[i] & 0xFF];
        }
    }

    private void permuteBytes(byte[] block, int round) {
        byte[] permuted = new byte[BLOCK_SIZE];
        int[] permutation = generateDynamicPermutation(round);
        for (int i = 0; i < BLOCK_SIZE; i++) {
            permuted[i] = block[permutation[i]];
        }
        System.arraycopy(permuted, 0, block, 0, BLOCK_SIZE);
    }

    private int[] generateDynamicPermutation(int round) {
        int[] permutation = new int[BLOCK_SIZE];
        for (int i = 0; i < BLOCK_SIZE; i++) {
            permutation[i] = (i + round * 3) % BLOCK_SIZE; // Dynamische Permutation basierend auf der Runde
        }
        return permutation;
    }

    private void reversePermuteBytes(byte[] block, int round) {
        byte[] reversed = new byte[BLOCK_SIZE];
        int[] reversePermutation = generateDynamicPermutation(round);
        for (int i = 0; i < BLOCK_SIZE; i++) {
            reversed[reversePermutation[i]] = block[i];
        }
        System.arraycopy(reversed, 0, block, 0, BLOCK_SIZE);
    }

    private void mixColumns(byte[] block, int round) {
        // Matrixmultiplikation in GF(2^8)
        byte[][] matrix = {
                {2, 3, 1, 1},
                {1, 2, 3, 1},
                {1, 1, 2, 3},
                {3, 1, 1, 2}
        };

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

    private byte galoisMultiply(byte a, byte b) {
        int product = 0;
        for (int i = 0; i < 8; i++) {
            if ((b & 1) != 0) {
                product ^= a;
            }
            boolean highBitSet = (a & 0x80) != 0;
            a <<= 1;
            if (highBitSet) {
                a ^= 0x1b; // Reduziere Modulo x^8 + x^4 + x^3 + x + 1
            }
            b >>= 1;
        }
        return (byte) product;
    }

    private void reverseMixColumns(byte[] block, int round) {
        // Umkehrmatrix in GF(2^8)
        byte[][] invMatrix = {
                {14, 11, 13, 9},
                {9, 14, 11, 13},
                {13, 9, 14, 11},
                {11, 13, 9, 14}
        };

        byte[] reversed = new byte[BLOCK_SIZE];
        for (int i = 0; i < BLOCK_SIZE; i += 4) {
            for (int j = 0; j < 4; j++) {
                reversed[i + j] = 0;
                for (int k = 0; k < 4; k++) {
                    reversed[i + j] ^= galoisMultiply(block[i + k], invMatrix[j][k]);
                }
            }
        }
        System.arraycopy(reversed, 0, block, 0, BLOCK_SIZE);
    }

    private void xorWithIV(byte[] block, byte[] iv) {
        for (int i = 0; i < block.length; i++) {
            block[i] ^= iv[i];
        }
    }

    public void displayKeyAndIV() {
        System.out.println("Schlüssel (Hex): " + byteArrayToHexString(key));
        System.out.println("IV (Hex): " + byteArrayToHexString(iv));
    }
}
