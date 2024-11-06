package org.example;

import java.nio.charset.StandardCharsets;
import java.util.Random;

public class CustomKeyGenerator {
    private static final int KEY_SIZE = 32; // 256 bits
    private static final int SALT_SIZE = 64; // 512-bit Salt
    private static final int MEMORY_SIZE = Runtime.getRuntime().maxMemory() > (256 * 1024 * 1024) ? 128 * 1024 * 1024 : 64 * 1024 * 1024; // 128 MB oder 64 MB
    private static final int ROUNDS = MEMORY_SIZE > (64 * 1024 * 1024) ? 150 : 100; // Mehr Runden bei mehr Speicher

    private final byte[] key;
    private final byte[] salt;
    private final String seed;
    private final int delayMs; // Konfigurierbare Verzögerung in Millisekunden für Timing-Angriffsschutz
    private final int[] pBox; // Einmalige P-Box für alle Runden

    public CustomKeyGenerator(int delayMs) {
        this.seed = generateComplexSeed();
        this.salt = generateStrongSalt();
        this.delayMs = delayMs;
        this.pBox = generateComplexPBox(); // P-Box nur einmal erstellen
        this.key = generateKey(this.seed, this.salt);
    }

    public CustomKeyGenerator() {
        this(1);
    }

    public String getSeed() {
        return seed;
    }

    public byte[] getKey() {
        return key;
    }

    public byte[] getSalt() {
        return salt;
    }

    public byte[] reconstructKey(String seed, byte[] salt) {
        return generateKey(seed, salt);
    }

    private String generateComplexSeed() {
        long seedBase = System.nanoTime() ^ System.currentTimeMillis() ^ 0xCAFEBABE1234L;
        StringBuilder seedBuilder = new StringBuilder();

        for (int i = 0; i < 32; i++) {
            seedBase ^= (seedBase << 7) ^ (seedBase >> 5) ^ i;
            int nextChar = (int) ((seedBase & 0xFF) ^ (seedBase >> 4));
            seedBuilder.append((char) (nextChar & 0xFF));
            seedBase ^= seedBuilder.charAt(i) * 37;
        }
        return seedBuilder.toString();
    }

    private byte[] generateStrongSalt() {
        byte[] salt = new byte[SALT_SIZE];
        long entropySeed = 0xDEADBEEF5678L ^ System.currentTimeMillis();

        for (int i = 0; i < SALT_SIZE; i++) {
            entropySeed ^= (entropySeed << 13) ^ (entropySeed >> 7) ^ i;
            salt[i] = (byte) (entropySeed & 0xFF);
            salt[i] ^= rotateLeft(salt[i], i % 8);
            salt[i] ^= hashByte((byte) entropySeed, i);
            entropySeed ^= salt[i] * 31;
        }
        return salt;
    }

    private byte[] generateKey(String seed, byte[] salt) {
        byte[] key = new byte[KEY_SIZE];
        byte[] seedBytes = seed.getBytes(StandardCharsets.UTF_8);
        byte[] dynamicSalt = salt.clone();
        byte[] sBox = generateDynamicSBox(seedBytes.length); // Verbesserter Seed für S-Box

        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) ((seedBytes[i % seedBytes.length] + dynamicSalt[i % dynamicSalt.length] * 19 + i * 37) & 0xFF);
        }

        for (int round = 0; round < ROUNDS; round++) {
            for (int i = 0; i < key.length; i++) {
                key[i] ^= sBox[i % sBox.length];
                key = applyPBox(key); // Wendet die P-Box nur einmal an

                int memoryIndex = Math.abs((i * 17 + round) % MEMORY_SIZE);
                int alternateIndex = Math.abs((i * 31 + round) % MEMORY_SIZE);

                key[i] = rotateLeft(key[i], (i + round) % 8);
                key[i] ^= hashByte(seedBytes[i % seedBytes.length], i + round);
            }

            shuffleBytes(key, round);
            addDynamicNOPs(round);
            simulateDelay();
        }

        return key;
    }

    private byte[] generateDynamicSBox(int size) {
        byte[] sBox = new byte[size];
        Random random = new Random(KDFBasedSeed()); // Verbessertes Seed für Entropie
        for (int i = 0; i < size; i++) {
            sBox[i] = (byte) (random.nextInt(256));
        }
        return sBox;
    }

    // Key Derivation Function-basiertes Seed für höhere Entropie
    private int KDFBasedSeed() {
        long timeSeed = System.nanoTime();
        long entropySeed = timeSeed ^ (timeSeed << 13) ^ (timeSeed >> 7);
        return (int) ((entropySeed ^ 0xA5A5A5A5L) & 0xFFFFFFFFL);
    }

    private void simulateDelay() {
        int nopCount = customRandom((int) System.nanoTime()) % (delayMs * 100); // Skalierung der NOPs basierend auf delayMs
        for (int i = 0; i < nopCount; i++) {
            int dummy = i * customRandom(i);
        }
    }

    private void addDynamicNOPs(int round) {
        int nopCount = customRandom(round) % 10 + 5;
        for (int i = 0; i < nopCount; i++) {
            int dummy = i * round * customRandom(i + round);
        }
    }

    private int customRandom(int seed) {
        long result = (seed * 0x5DEECE66DL) + 0xBL;

        // Mehrere nichtlineare Transformationen für zusätzliche Komplexität
        result ^= (result << 13) ^ (result >> 21) ^ (result << 5);
        result += (result * 31) ^ 0x9E3779B97F4A7C15L; // Verwendet eine große, kryptografisch inspirierte Konstante
        result ^= (result << 27) ^ (result >> 19) ^ 0xA5A5A5A5A5A5L; // Füge eine weitere Permutation hinzu

        // XOR mit einer rotierenden Bitmaske
        result ^= Long.rotateLeft(result, (seed % 64));
        result *= 6364136223846793005L; // Multiplikation mit einer weiteren Primzahl zur Streuung

        // Begrenze das Ergebnis auf 32-Bit-Ganzzahlbereich und zusätzliche Permutation
        return (int) ((result ^ (result >>> 15)) & 0xFFFFFFFFL);
    }


    private byte rotateLeft(byte b, int bits) {
        return (byte) ((b << bits) | ((b & 0xFF) >>> (8 - bits)));
    }

    private void shuffleBytes(byte[] array, int round) {
        int jump = Math.abs(customRandom(round) % array.length);
        for (int i = 0; i < array.length; i++) {
            int swapIndex = ((i + jump) % array.length + array.length) % array.length;
            byte temp = array[i];
            array[i] = array[swapIndex];
            array[swapIndex] = temp;
        }
    }

    private byte hashByte(byte input, int modifier) {
        byte hash = (byte) (input * 37 + modifier * 19);
        hash ^= rotateLeft(hash, 3);
        hash ^= (byte) ((hash << 5) | (hash >>> 3));
        hash ^= (byte) ((modifier * 23) & 0xFF);
        hash = rotateLeft(hash, modifier % 7);
        hash ^= (byte) ((hash * 29 + (modifier * 13)) & 0xFF);
        return (byte) (hash ^ (modifier * 11));
    }

    private byte[] applyPBox(byte[] input) {
        byte[] output = new byte[input.length];
        for (int i = 0; i < input.length; i++) {
            output[i] = input[pBox[i]]; // Einmal generierte P-Box anwenden
        }
        return output;
    }

    private int[] generateComplexPBox() {
        int[] pBox = new int[KEY_SIZE];
        int seed = KDFBasedSeed(); // Verbesserter Seed für P-Box
        Random random = new Random(seed);

        for (int i = 0; i < pBox.length; i++) {
            pBox[i] = i;
        }

        for (int i = 0; i < pBox.length; i++) {
            int swapIndex = random.nextInt(KEY_SIZE);
            pBox[i] = Math.abs((pBox[i] + (swapIndex * 31) ^ rotateLeft((byte)pBox[i], 5)) % KEY_SIZE);
            pBox[swapIndex] = Math.abs((pBox[swapIndex] + (pBox[i] * 17) ^ rotateRight((byte)pBox[swapIndex], 7)) % KEY_SIZE);
        }

        return pBox;
    }

    private byte rotateRight(byte b, int bits) {
        return (byte) ((b >>> bits) | ((b & 0xFF) << (8 - bits)));
    }
}
