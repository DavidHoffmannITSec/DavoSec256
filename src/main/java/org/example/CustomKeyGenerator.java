package org.example;

import java.nio.charset.StandardCharsets;

public class CustomKeyGenerator {
    private static final int KEY_SIZE = 32; // 256 bits
    private static final int SALT_SIZE = 64; // 512-bit Salt
    // Adaptive Größe für memoryArray und ROUNDS abhängig von Systemkapazität
    private static final int MEMORY_SIZE = Runtime.getRuntime().maxMemory() > (256 * 1024 * 1024) ? 128 * 1024 * 1024 : 64 * 1024 * 1024; // 128 MB oder 64 MB
    private static final int ROUNDS = MEMORY_SIZE > (64 * 1024 * 1024) ? 150 : 100; // Mehr Runden bei mehr Speicher

    private final byte[] key;
    private final byte[] salt;
    private final String seed;
    private final int delayMs; // Konfigurierbare Verzögerung in Millisekunden für Timing-Angriffsschutz

    public CustomKeyGenerator(int delayMs) {
        this.seed = generateComplexSeed();
        this.salt = generateStrongSalt();
        this.delayMs = delayMs;
        this.key = generateKey(this.seed, this.salt);
    }

    public CustomKeyGenerator() {
        this(1);
    }

    public String getSeed() {
        return seed;
    }

    // Methode, um den Key basierend auf einem bestimmten Seed und Salt zu rekonstruieren
    public byte[] reconstructKey(String seed, byte[] salt) {
        return generateKey(seed, salt);
    }

    // Verbessertes customRandom mit zusätzlichen XOR-Schichten
    private int customRandom(int seed) {
        long result = (seed * 0x5DEECE66DL) + 0xBL;
        result ^= (result << 13) ^ (result >> 17) ^ (result << 5);
        result ^= (result * 31 + 0xA5A5A5A5A5A5L);
        result ^= (result << 23) ^ (result >> 19);
        result = result * 6364136223846793005L + 1442695040888963407L; // Lineare Kongruenz
        return (int) result;
    }

    // Generiert einen erweiterten komplexen Seed ohne Zeitabhängigkeit
    private String generateComplexSeed() {
        long seedBase = System.nanoTime() ^ System.currentTimeMillis() ^ 0xCAFEBABE1234L;
        StringBuilder seedBuilder = new StringBuilder();

        for (int i = 0; i < 32; i++) { // Erhöhte Länge für mehr Komplexität
            seedBase ^= (seedBase << 7) ^ (seedBase >> 5) ^ i;
            int nextChar = (int) ((seedBase & 0xFF) ^ (seedBase >> 4));
            seedBuilder.append((char) (nextChar & 0xFF));
            seedBase ^= seedBuilder.charAt(i) * 37;
        }
        return seedBuilder.toString();
    }

    // Optimierte Salt-Generierung mit noch komplexeren Operationen und erweitertem Salt-Buffer
    private byte[] generateStrongSalt() {
        byte[] salt = new byte[SALT_SIZE];
        long entropySeed = 0xDEADBEEF5678L ^ System.currentTimeMillis();

        for (int i = 0; i < SALT_SIZE; i++) {
            entropySeed ^= (entropySeed << 13) ^ (entropySeed >> 7) ^ i;
            salt[i] = (byte) (entropySeed & 0xFF);
            salt[i] ^= rotateLeft(salt[i], i % 8);
            salt[i] ^= hashByte((byte) entropySeed, i);
            entropySeed ^= salt[i] * 31;
            salt[i] ^= (byte) customRandom((int) entropySeed);
        }
        return salt;
    }

    private byte[] generateKey(String seed, byte[] salt) {
        byte[] key = new byte[KEY_SIZE];
        byte[] memoryArray = new byte[MEMORY_SIZE];
        byte[] seedBytes = seed.getBytes(StandardCharsets.UTF_8);
        byte[] dynamicSalt = salt.clone();

        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) ((seedBytes[i % seedBytes.length] + dynamicSalt[i % dynamicSalt.length] * 19 + i * 37) & 0xFF);
        }

        for (int round = 0; round < ROUNDS; round++) {
            for (int i = 0; i < key.length; i++) {
                // Berechnung des Index und Vermeidung negativer Indizes
                try {
                    int memoryIndex = Math.abs((i * 17 + round) % MEMORY_SIZE);
                    int alternateIndex = Math.abs((i * 31 + round) % MEMORY_SIZE);

                    memoryArray[memoryIndex] ^= key[i];
                    key[i] ^= memoryArray[alternateIndex];
                    dynamicSalt[i % dynamicSalt.length] ^= key[i];

                    // Zusätzliche zufällige Zugriffe, auch hier Absicherung gegen negative Indizes
                    int randomIndex = Math.abs(customRandom(round + i) % MEMORY_SIZE);
                    memoryArray[randomIndex] ^= key[i];

                    int extraRandomIndex = Math.abs((memoryIndex + customRandom(i) % 64) % MEMORY_SIZE);
                    memoryArray[extraRandomIndex] ^= key[i];
                } catch (ArrayIndexOutOfBoundsException e) {
                    System.err.println("ArrayIndexOutOfBoundsException: Round: " + round + ", i: " + i);
                    e.printStackTrace();
                    throw e; // Weiterleiten der Exception für vollständige Diagnose
                }

                key[i] = rotateLeft(key[i], (i + round) % 8);
                key[i] ^= hashByte(seedBytes[i % seedBytes.length], i + round);
            }

            shuffleBytes(key, round);
            addDynamicNOPs(round);
            delay();
        }
        return key;
    }


    private void delay() {
        try {
            int nopCount = customRandom((int) System.nanoTime()) % 15 + 5;
            for (int i = 0; i < nopCount; i++) {
                int dummy = i * customRandom(i);
            }
            Thread.sleep(delayMs);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void addDynamicNOPs(int round) {
        int nopCount = customRandom(round) % 10 + 5;
        for (int i = 0; i < nopCount; i++) {
            int dummy = i * round * customRandom(i + round);
        }
    }

    public byte[] getKey() {
        return key;
    }

    public byte[] getSalt() {
        return salt;
    }

    private byte rotateLeft(byte b, int bits) {
        return (byte) ((b << bits) | ((b & 0xFF) >>> (8 - bits)));
    }

    // Zyklische Permutation mit variierendem Sprungindex
    private void shuffleBytes(byte[] array, int round) {
        int jump = Math.abs(customRandom(round) % array.length); // Absicherung gegen negative Sprungwerte
        for (int i = 0; i < array.length; i++) {
            // Berechnung des swapIndex und Sicherstellen, dass der Index positiv ist
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
}
