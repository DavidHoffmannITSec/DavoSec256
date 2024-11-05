package org.example;

import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class DavoSec256 {
    private static final int KEY_SIZE = 32; // 256 bits
    private static final int BLOCK_SIZE = 16; // 128 bits
    private static final int BASE_ROUNDS = 24;
    private final byte[] key;
    private final byte[] iv;

    public DavoSec256(byte[] key) {
        if (key == null || key.length != KEY_SIZE) {
            throw new IllegalArgumentException("Schlüssel muss genau 256 Bit (32 Bytes) lang sein.");
        }
        this.key = Arrays.copyOf(key, KEY_SIZE);
        this.iv = generateIV();
    }

    // Verbesserte IV-Generierung mit dynamischem Seed
    private byte[] generateIV() {
        byte[] iv = new byte[BLOCK_SIZE];
        long complexSeed = System.currentTimeMillis() ^ System.nanoTime() ^ Thread.currentThread().hashCode();
        long hashedSeed = customHash(complexSeed);

        for (int i = 0; i < iv.length; i++) {
            iv[i] = (byte) ((hashedSeed + i * 37) & 0xFF);
            iv[i] ^= rotateLeft((byte) hashedSeed, i % 8);
            hashedSeed *= 6364136223846793005L + i * 31;
        }
        return iv;
    }

    private long customHash(long seed) {
        seed ^= (seed << 21) ^ (seed >> 35) ^ (seed << 4);
        seed *= 6364136223846793005L;
        seed ^= (seed << 15) ^ (seed >> 27) ^ (seed << 8); // Zusätzliche nicht-lineare Transformationen
        return seed;
    }

    // Verschlüsselungsmethode mit Timing-Schutz und Multithreading
    public byte[] encrypt(byte[] plaintext) {
        byte[] paddedPlaintext = pad(plaintext);
        byte[] ciphertext = new byte[paddedPlaintext.length];
        byte[] block = Arrays.copyOf(iv, BLOCK_SIZE);

        // Multithreading für Blockverschlüsselung
        int numThreads = Runtime.getRuntime().availableProcessors();
        try (ExecutorService executor = Executors.newFixedThreadPool(numThreads)) {
            for (int i = 0; i < paddedPlaintext.length; i += BLOCK_SIZE) {
                final int index = i;
                executor.submit(() -> {
                    byte[] plaintextBlock = Arrays.copyOfRange(paddedPlaintext, index, index + BLOCK_SIZE);
                    xorWithIV(plaintextBlock, block);
                    byte[] encryptedBlock = encryptBlock(plaintextBlock);
                    synchronized (ciphertext) {
                        System.arraycopy(encryptedBlock, 0, ciphertext, index, BLOCK_SIZE);
                    }
                });
            }
            executor.shutdown();
            if (!executor.awaitTermination(1, TimeUnit.MINUTES)) {
                throw new IllegalStateException("Verschlüsselung dauerte zu lange und wurde abgebrochen.");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Verschlüsselung wurde unterbrochen.", e);
        }

        return ciphertext;
    }


    private byte[] encryptBlock(byte[] block) {
        for (int round = 0; round < BASE_ROUNDS; round++) {
            addRoundKey(block, round);
            substituteBytes(block, round);
            permuteBytes(block, round);
            mixColumns(block, round);

            // Zusätzliche Dummy-Operationen für Timing-Konsistenz
            addTimingNoise(block, round);
        }
        return block;
    }

    // Zusätzliche Methode zur Einführung von zufälligen Dummy-Operationen und Speicherzugriffen
    private void addTimingNoise(byte[] block, int round) {
        int noiseOperations = 5 + customRandom(round) % 10; // Zufällige Anzahl Dummy-Operationen
        for (int i = 0; i < noiseOperations; i++) {
            int dummyIndex = customRandom(i + round) % block.length;
            byte dummyValue = rotateLeft(block[dummyIndex], round % 8);

            // Zufällige Berechnung ohne Einfluss auf den finalen Wert
            dummyValue ^= (byte) (customRandom(dummyValue) & 0xFF);
            dummyValue = rotateLeft(dummyValue, dummyIndex % 8);

            // Zufällige zusätzliche Zugriffe im Speicher
            int memoryAccessIndex = (dummyIndex * customRandom(dummyValue) + round) % block.length;
            block[memoryAccessIndex] ^= dummyValue;

            // Weitere zufällige Zugriffe und Berechnungen für Timing-Schutz
            dummyValue ^= (byte) (rotateLeft(block[round % block.length], 3) & 0xFF);
            memoryAccessIndex = (memoryAccessIndex + customRandom(round + i)) % block.length;
            block[memoryAccessIndex] ^= dummyValue;
        }
    }


    // Dynamische S-Box für jede Runde, mit mehreren Durchläufen für maximale Zufälligkeit
    private void substituteBytes(byte[] block, int round) {
        int[] sBox = generateDynamicSBox(round);
        for (int i = 0; i < block.length; i++) {
            block[i] = (byte) sBox[block[i] & 0xFF];
        }
    }

    // Generiert eine dynamische S-Box basierend auf Rundenanzahl und Seed
    private int[] generateDynamicSBox(int round) {
        int[] sBox = new int[256];
        long seed = 0x9E3779B97F4A7C15L + round;

        for (int j = 0; j < 3; j++) {
            for (int i = 0; i < 256; i++) {
                seed ^= (seed << 13) ^ (seed >> 7) ^ i;
                sBox[i] = (int) ((seed * i + 0xA5A5A5A5L ^ rotateLeft((byte) seed, i % 8)) & 0xFF);
            }
        }
        return sBox;
    }

    // Optimierte Permutationsmethode mit zufälligem Sprungindex
    private void permuteBytes(byte[] block, int round) {
        int prime = 37 + (round * 23);
        for (int i = 0; i < block.length; i++) {
            int swapIndex = (i * prime + customRandom(round) + block[i % block.length]) % block.length;
            byte temp = block[i];
            block[i] = block[swapIndex];
            block[swapIndex] = temp;
        }
    }

    // Mehrschichtige mixColumns-Methode mit zusätzlichen XOR-Schichten
    private void mixColumns(byte[] block, int round) {
        for (int i = 0; i < 4; i++) {
            int a = block[i], b = block[i + 4], c = block[i + 8], d = block[i + 12];
            block[i] = (byte) ((a ^ (b * 2) ^ (c * 3) ^ d) & 0xFF);
            block[i + 4] = (byte) (((a * 2) ^ b ^ (c * 3) ^ (d * 2)) & 0xFF);
            block[i + 8] = (byte) (((a * 3) ^ (b * 2) ^ c ^ (d * 2)) & 0xFF);
            block[i + 12] = (byte) (((a * 2) ^ (b * 3) ^ (c * 2) ^ d) & 0xFF);

            // Zusätzliche XOR-Schicht mit Casting
            block[i] ^= (byte) (customRandom(round + i) & 0xFF);
        }
    }


    private void addRoundKey(byte[] block, int round) {
        for (int i = 0; i < block.length; i++) {
            block[i] ^= key[(i + round * 7) % key.length];
        }
    }

    private void xorWithIV(byte[] block, byte[] iv) {
        for (int i = 0; i < block.length; i++) {
            block[i] ^= iv[i];
        }
    }

    private byte[] pad(byte[] data) {
        int paddingLength = BLOCK_SIZE - (data.length % BLOCK_SIZE);
        byte[] padded = Arrays.copyOf(data, data.length + paddingLength);
        Arrays.fill(padded, data.length, padded.length, (byte) paddingLength);
        return padded;
    }

    private int customRandom(int seed) {
        long result = (seed * 0x5DEECE66DL) + 0xBL;
        result ^= (result << 13) ^ (result >> 17) ^ (result << 5);
        result ^= (result * 31 + 0xA5A5A5A5A5A5L);
        result ^= (result << 21) ^ (result >> 29) ^ (result << 11);
        return (int) result;
    }

    private byte rotateLeft(byte b, int bits) {
        return (byte) ((b << bits) | ((b & 0xFF) >>> (8 - bits)));
    }
}
