

import org.example.DavoSec256;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import java.util.HashSet;
import java.util.Set;

public class DavoSecTest {
    private final DavoSec256 davoSec = new DavoSec256();

    @Test
    public void testEncryptionDecryptionConsistency() {
        byte[] plaintext = "TestString12345".getBytes();
        davoSec.generateKey();

        byte[] encrypted = davoSec.encrypt(plaintext);
        byte[] decrypted = davoSec.decrypt(encrypted);

        assertArrayEquals(plaintext, decrypted, "Der entschlüsselte Text sollte mit dem Klartext übereinstimmen.");

        // Wiederholte Verschlüsselung/Entschlüsselung für Konsistenz über mehrere Durchläufe
        for (int i = 0; i < 10; i++) {
            encrypted = davoSec.encrypt(plaintext);
            decrypted = davoSec.decrypt(encrypted);
            assertArrayEquals(plaintext, decrypted, "Der entschlüsselte Text sollte immer mit dem Klartext übereinstimmen.");
        }
    }

    @Test
    public void testTimingConsistency() {
        byte[] plaintext = "TimingTestInput".getBytes();
        davoSec.generateKey();

        long averageDuration = 0;
        int trials = 1000;

        for (int i = 0; i < trials; i++) {
            long startTime = System.nanoTime();
            davoSec.encrypt(plaintext);
            averageDuration += System.nanoTime() - startTime;
        }

        averageDuration /= trials;

        for (int i = 0; i < trials; i++) {
            long startTime = System.nanoTime();
            davoSec.encrypt(plaintext);
            long duration = System.nanoTime() - startTime;
            double timingDifference = Math.abs(duration - averageDuration) / (double) averageDuration;
            assertTrue(timingDifference < 0.1, "Der Timing-Unterschied sollte weniger als 10% betragen."); // Erhöhte Toleranz auf 10%
        }
    }



    @Test
    public void testAvalancheEffect() {
        byte[] plaintext1 = "AvalancheTestData".getBytes();
        byte[] plaintext2 = "AvalancheTestDatu".getBytes(); // minimaler Unterschied

        davoSec.generateKey();
        byte[] encrypted1 = davoSec.encrypt(plaintext1);
        byte[] encrypted2 = davoSec.encrypt(plaintext2);

        int changedBits = countChangedBits(encrypted1, encrypted2);
        double avalancheEffect = changedBits / (double) (encrypted1.length * 8);

        assertTrue(avalancheEffect > 0.55, "Avalanche-Effekt sollte mindestens 55% betragen.");

        // Teste mit zufälligen minimalen Variationen im Klartext
        for (int i = 0; i < 5; i++) {
            plaintext2[i % plaintext2.length] ^= 1; // kleines Bit-Flip
            encrypted2 = davoSec.encrypt(plaintext2);
            changedBits = countChangedBits(encrypted1, encrypted2);
            avalancheEffect = changedBits / (double) (encrypted1.length * 8);
            assertTrue(avalancheEffect > 0.55, "Avalanche-Effekt sollte auch bei zufälligen Änderungen mindestens 55% betragen.");
        }
    }

    @Test
    public void testSBoxCollisions() {
        davoSec.generateKey();
        Set<Byte> uniqueSBoxValues = new HashSet<>();

        for (byte value : davoSec.getS_BOX()) {
            uniqueSBoxValues.add(value);
        }

        assertEquals(256, uniqueSBoxValues.size(), "Die S-Box sollte alle Werte ohne Kollision enthalten.");

        // Teste zufällige Variationen der S-Box für Entropie
        for (int i = 0; i < 10; i++) {
            davoSec.generateKey();
            uniqueSBoxValues.clear();
            for (byte value : davoSec.getS_BOX()) {
                uniqueSBoxValues.add(value);
            }
            assertEquals(256, uniqueSBoxValues.size(), "Jede generierte S-Box sollte alle Werte ohne Kollision enthalten.");
        }
    }

    @Test
    public void testPermutationMatrixIntegrity() {
        davoSec.generateKey();
        Set<Integer> uniquePermutationValues = new HashSet<>();

        for (int value : davoSec.getPERMUTATION()) {
            uniquePermutationValues.add(value);
        }

        assertEquals(16, uniquePermutationValues.size(), "Die Permutationsmatrix sollte 16 eindeutige Werte enthalten.");

        // Teste Variationen der Permutationsmatrix für Entropie und Eindeutigkeit
        for (int i = 0; i < 10; i++) {
            davoSec.generateKey();
            uniquePermutationValues.clear();
            for (int value : davoSec.getPERMUTATION()) {
                uniquePermutationValues.add(value);
            }
            assertEquals(16, uniquePermutationValues.size(), "Jede generierte Permutationsmatrix sollte 16 eindeutige Werte enthalten.");
        }
    }

    @Test
    public void testInvalidCipherTextLength() {
        int BLOCK_SIZE = 16;
        byte[] invalidCipherText = new byte[BLOCK_SIZE - 1];
        davoSec.generateKey();

        assertThrows(IllegalArgumentException.class, () -> davoSec.decrypt(invalidCipherText),
                "Ungültige Länge des verschlüsselten Textes sollte eine Ausnahme auslösen.");
    }

    @Test
    public void testInvalidPaddingDetection() {
        byte[] plaintext = "PaddingTestInput".getBytes();
        davoSec.generateKey();
        byte[] encrypted = davoSec.encrypt(plaintext);

        // Füge ungültiges Padding hinzu
        encrypted[encrypted.length - 1] = 0x00;

        assertThrows(IllegalArgumentException.class, () -> davoSec.decrypt(encrypted),
                "Ungültiges Padding sollte eine Ausnahme auslösen.");
    }

    @Test
    public void testKeyUniqueness() {
        Set<String> uniqueKeys = new HashSet<>();
        for (int i = 0; i < 200; i++) { // erhöhte Anzahl der Schlüsseltests
            davoSec.generateKey();
            uniqueKeys.add(davoSec.bytesToHex(davoSec.getKey()));
        }
        assertEquals(200, uniqueKeys.size(), "Jeder generierte Schlüssel sollte einzigartig sein.");
    }

    private int countChangedBits(byte[] array1, byte[] array2) {
        int changedBits = 0;
        for (int i = 0; i < array1.length; i++) {
            byte diff = (byte) (array1[i] ^ array2[i]);
            for (int j = 0; j < 8; j++) {
                changedBits += (diff >> j) & 1;
            }
        }
        return changedBits;
    }
}
