package org.example;


import java.io.File;
import java.io.IOException;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {

        DavoSec256 davoSec256 = new DavoSec256();

        davoSec256.generateKey();

        String path = "C:/Users/hoffmann/Documents/test.txt";
        File inputFile = new File(path);

        try {
            // Datei verschlüsseln
            davoSec256.encryptFile(inputFile);
            System.out.println("Datei erfolgreich verschlüsselt: " + inputFile.getAbsolutePath());

            // Datei entschlüsseln
            davoSec256.decryptFile(inputFile);
            System.out.println("Datei erfolgreich entschlüsselt: " + inputFile.getAbsolutePath());
        } catch (IOException e) {
            System.err.println("Fehler bei der Dateioperation: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            System.err.println("Fehler bei der Verschlüsselung/Entschlüsselung: " + e.getMessage());
        }
    }

}