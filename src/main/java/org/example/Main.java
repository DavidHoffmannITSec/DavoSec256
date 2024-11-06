package org.example;


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
    }

}