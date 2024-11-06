package org.example;

import java.nio.charset.StandardCharsets;

public class Main {
    public static void main(String[] args) {
        String originalText = "Geheimer Text für die Verschlüsselung";
        System.out.println("Originaltext: " + originalText);

        // Erzeugung eines Schlüssels mit CustomKeyGenerator
        CustomKeyGenerator keyGenerator = new CustomKeyGenerator();
        byte[] key = keyGenerator.getKey();
        byte[] salt = keyGenerator.getSalt();

        // Initialisiere die Verschlüsselungsklasse mit dem generierten Schlüssel
        DavoSec256 davoSec256 = new DavoSec256();

        // Text in Bytes umwandeln und verschlüsseln
        byte[] plaintextBytes = originalText.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedBytes = davoSec256.encrypt(plaintextBytes);
        String encryptedHex = DavoSec256.byteArrayToHexString(encryptedBytes);
        System.out.println("Verschlüsselter Text (Hex): " + encryptedHex);

        // Zurück in Bytes konvertieren und entschlüsseln
        byte[] decryptedBytes = davoSec256.decrypt(encryptedBytes);
        String decryptedText = new String(decryptedBytes, StandardCharsets.UTF_8);
        System.out.println("Entschlüsselter Text: " + decryptedText);
    }

}