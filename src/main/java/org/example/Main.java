package org.example;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class Main {
    public static void main(String[] args) {
        DavoSec256 davoSec256 = new DavoSec256();
        String keyPath = "C:/Users/hoffmann/Documents/keyAndIV.dat"; // Speicherort für Schlüssel und IV

        // Fester Pfad zur unverschlüsselten Datei
        String filePath = "C:/Users/hoffmann/Documents/test.txt";
        File inputFile = new File(filePath);

        // Überprüfen, ob die Datei existiert und nicht leer ist
        if (!inputFile.exists() || inputFile.length() == 0) {
            System.err.println("Die Datei existiert nicht oder ist leer: " + inputFile.getAbsolutePath());
            return; // Programm beenden
        }

        try {
            // Überprüfen, ob der Schlüssel und IV bereits gespeichert sind
            if (Files.exists(Paths.get(keyPath))) {
                davoSec256.loadKeyAndIV(keyPath);
                System.out.println("Schlüssel und IV erfolgreich geladen.");
            } else {
                davoSec256.generateKey();
                System.out.println("Neuer Schlüssel generiert.");
                davoSec256.saveKeyAndIV(keyPath);
                System.out.println("Schlüssel und IV erfolgreich gespeichert.");
            }

            byte[] fileContent = Files.readAllBytes(inputFile.toPath());

            // Datei verschlüsseln
//            byte[] ciphertext = davoSec256.encrypt(fileContent);
//            // Verschlüsselten Inhalt in die Datei zurückschreiben
//            Files.write(inputFile.toPath(), ciphertext);
//            System.out.println("Datei erfolgreich verschlüsselt: " + inputFile.getAbsolutePath());

            // Datei entschlüsseln
            byte[] decryptedText = davoSec256.decrypt(fileContent /*ciphertext*/);
            // Entschlüsselten Inhalt zurück in die Datei schreiben (oder in eine neue Datei, wenn gewünscht)
            Files.write(inputFile.toPath(), decryptedText);
            System.out.println("Datei erfolgreich entschlüsselt: " + inputFile.getAbsolutePath());
        } catch (IOException e) {
            System.err.println("Fehler bei der Dateioperation: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            System.err.println("Fehler bei der Verschlüsselung/Entschlüsselung: " + e.getMessage());
        }
    }
}
