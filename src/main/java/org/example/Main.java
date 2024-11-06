package org.example;


import java.io.File;
import java.io.IOException;

public class Main {
    public static void main(String[] args) {

        DavoSec256 davoSec256 = new DavoSec256();

        // Generiere den Schlüssel
        davoSec256.generateKey();

        // Ursprünglicher Text für die Verschlüsselung
        String originalText = "Geheimer Text für die Verschlüsselung xD";
        byte[] plaintext = originalText.getBytes();

        // Verschlüsseln des Textes
        byte[] ciphertext = davoSec256.encrypt(plaintext);
        System.out.println("Verschlüsselter Text: " + DavoSec256.byteArrayToHexString(ciphertext));

        // Entschlüsseln des Textes
        byte[] decryptedText = davoSec256.decrypt(ciphertext);
        String decryptedString = new String(decryptedText);
        System.out.println("Entschlüsselter Text: " + decryptedString);

        File inputFile = new File("C:/Users/hoffmann/Documents/test.txt");
        File encryptedFile = new File("C:/Users/hoffmann/Documents/test_Encrypted.txt");
        File decryptedFile = new File("C:/Users/hoffmann/Documents/test_Decrypted.txt");

        try {
            // Datei verschlüsseln
            davoSec256.encryptFile(inputFile, encryptedFile);
            System.out.println("Datei erfolgreich verschlüsselt: " + encryptedFile.getAbsolutePath());

            // Datei entschlüsseln
            davoSec256.decryptFile(encryptedFile, decryptedFile);
            System.out.println("Datei erfolgreich entschlüsselt: " + decryptedFile.getAbsolutePath());
        } catch (IOException e) {
            System.err.println("Fehler bei der Dateioperation: " + e.getMessage());
        }
    }

}