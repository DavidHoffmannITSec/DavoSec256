package org.example;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

public class Main {
    private static final String keyPath = "C:/Users/PC/Documents/keyAndIV.dat"; // Speicherort für Schlüssel und IV
    private static final String filePath = "C:/Users/PC/Documents/hashtest.txt"; // Pfad zur unverschlüsselten Datei
    private static final DavoSec256 davoSec256 = new DavoSec256();

    public static void main(String[] args) {

        try {
            // Schlüssel und IV laden oder generieren
            loadOrGenerateKeyAndIV();

           // encryptAndDecryptText();

           // encryptFile();
            decryptFile();


        } catch (IOException e) {
            System.err.println("Fehler bei der Dateioperation: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            System.err.println("Fehler bei der Verschlüsselung/Entschlüsselung: " + e.getMessage());
        }
    }

    private static void encryptAndDecryptText() {
        String originalText = "Dies ist ein Teststring für die Verschlüsselung.";
        System.out.println("\nOriginal-String: " + originalText);

        byte[] encryptedText = davoSec256.encrypt(originalText.getBytes(StandardCharsets.UTF_8));
        System.out.println("Verschlüsselter String (Hex): " + davoSec256.bytesToHex(encryptedText));

        byte[] decryptedBytes = davoSec256.decrypt(encryptedText);
        String decryptedText = new String(decryptedBytes, StandardCharsets.UTF_8);
        System.out.println("Entschlüsselter String: " + decryptedText);
    }

    private static void encryptFile() {
        File inputFile = new File(filePath);

        if (!inputFile.exists() || inputFile.length() == 0) {
            System.err.println("Die Datei existiert nicht oder ist leer: " + inputFile.getAbsolutePath());
            return;
        }

        try {
            byte[] fileContent = Files.readAllBytes(inputFile.toPath());
            byte[] encryptedContent = davoSec256.encrypt(fileContent);
            Files.write(inputFile.toPath(), encryptedContent);
            System.out.println("Datei erfolgreich verschlüsselt: " + inputFile.getAbsolutePath());
        } catch (IOException e) {
            System.err.println("Fehler bei der Dateioperation: " + e.getMessage());
        }
    }

    private static void decryptFile() {
        File inputFile = new File(filePath);

        if (!inputFile.exists() || inputFile.length() == 0) {
            System.err.println("Die Datei existiert nicht oder ist leer: " + inputFile.getAbsolutePath());
            return;
        }

        try {
            byte[] fileContent = Files.readAllBytes(inputFile.toPath());
            byte[] decryptedContent = davoSec256.decrypt(fileContent);
            Files.write(inputFile.toPath(), decryptedContent);
            System.out.println("Datei erfolgreich entschlüsselt: " + inputFile.getAbsolutePath());
        } catch (IOException e) {
            System.err.println("Fehler bei der Dateioperation: " + e.getMessage());
        }
    }

    private static void loadOrGenerateKeyAndIV() throws IOException {
        if (Files.exists(Paths.get(keyPath))) {
            davoSec256.loadKeyAndIV(keyPath);
            System.out.println("Schlüssel und IV erfolgreich geladen.");
        } else {
            davoSec256.generateKey();
            davoSec256.saveKeyAndIV(keyPath);
            System.out.println("Neuer Schlüssel und IV generiert und gespeichert.");
        }
    }
}
