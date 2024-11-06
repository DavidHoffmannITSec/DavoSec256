# DavoSec256 - Ein benutzerdefinierter symmetrischer Verschlüsselungsalgorithmus

## Übersicht

DavoSec256 ist ein benutzerdefinierter symmetrischer Verschlüsselungsalgorithmus in Java, der eine Kombination aus dynamischer Schlüsselerzeugung, S-Box-Generierung und Permutation verwendet, um Daten sicher zu verschlüsseln und zu entschlüsseln. Der Algorithmus nutzt eine 256-Bit-Schlüssellänge und eine 128-Bit-Blochgröße. Die Implementierung enthält eine `CustomKeyGenerator`-Klasse zur sicheren Erzeugung von Schlüsseln und Salzen.

## Funktionen

- **Symmetrische Verschlüsselung**: Verschlüsselt und entschlüsselt Daten mit demselben Schlüssel.
- **Dynamische Schlüsselerzeugung**: Erzeugt einen starken Schlüssel, der aus einem zufälligen Seed und einem Salt generiert wird.
- **Padding und Entpadding**: Behandelt die Notwendigkeit von Padding bei der Verschlüsselung von Daten, die nicht ein Vielfaches der Blockgröße sind.
- **Kollisionssicherheit**: Prüft die generierten S-Boxen und Permutationen auf Kollisionen, um sicherzustellen, dass die Verschlüsselung sicher ist.

## Technische Details

### S-Boxen

Die S-Box (Substitutionsbox) ist ein zentrales Element der Verschlüsselung, das die byteweise Substitution der Daten ermöglicht. DavoSec256 generiert eine dynamische S-Box basierend auf dem Schlüssel und einem Initialisierungsvektor (IV). Die S-Box wird verwendet, um jedem Byte im Datenblock einen neuen Wert zuzuweisen, was die Nichtlinearität der Verschlüsselung erhöht und es schwieriger macht, Muster zu erkennen.

- **Erzeugung**: Die S-Box wird initial mit den Werten von 0 bis 255 gefüllt. Danach wird sie basierend auf verschiedenen Operationen, einschließlich XOR und Permutation, modifiziert.
- **Inverse S-Box**: Eine inverse S-Box wird ebenfalls erzeugt, um die Rücksubstitution während der Entschlüsselung zu ermöglichen.

### Diffusion

Diffusion ist ein weiterer wichtiger Aspekt der Verschlüsselung, der sicherstellt, dass eine kleine Änderung im Eingabetext (wie ein einzelnes Bit) eine signifikante Änderung im verschlüsselten Text bewirkt. DavoSec256 implementiert Diffusion durch:

- **Mixing Columns**: Der Algorithmus verwendet eine Mix-Columns-Operation, die Galois-Multiplikation anwendet, um sicherzustellen, dass die Bytes des Blocks über alle Positionen hinweg gleichmäßig verteilt werden. Dies bedeutet, dass eine Änderung in einem Byte den Wert in mehreren anderen Bytes beeinflussen kann.

### Bit-Shift-Operationen

Bit-Shift-Operationen sind entscheidend für die Erhöhung der Komplexität der Verschlüsselung und das Erzeugen von Pseudorandom-Effekten. DavoSec256 verwendet sowohl Links- als auch Rechtsverschiebungen in mehreren Funktionen:

- **Rotation**: Bytes werden mit Links- und Rechtsrotationen manipuliert, um die Verteilung der Bits zu verändern und sicherzustellen, dass jede Runde des Algorithmus einzigartige Ergebnisse liefert.
- **Dynamische P-Box**: Die P-Box wird einmalig generiert und während der Schlüsselgenerierung auf die Schlüsselbytes angewendet. Dies sorgt für zusätzliche Verwirrung und erhöht die Sicherheit.

### Sicherheit gegen Angriffe

- **Timing-Angriffe**: Der Algorithmus implementiert Verzögerungen in der Ausführung, um das Risiko von Timing-Angriffen zu minimieren. Diese Verzögerungen sind konfigurierbar und werden in die Schlüsselerzeugung integriert.
- **Kollisionsresistenz**: Der Algorithmus führt Tests auf Kollisionen in der S-Box und der P-Box durch, um sicherzustellen, dass jeder Wert einzigartig ist und somit die Sicherheit erhöht wird.

## Anforderungen

- **Java 11 oder höher**: Dieses Projekt verwendet Java 11 oder höher. Stelle sicher, dass du die richtige Version installiert hast.
- **Maven (optional)**: Wenn du das Projekt mit Maven verwalten möchtest, erstelle eine `pom.xml`-Datei mit den notwendigen Abhängigkeiten.

## Verwendung

1. **Kompilieren**: Stelle sicher, dass alle Abhängigkeiten korrekt sind. Du kannst das Projekt in einer IDE deiner Wahl öffnen oder es über die Kommandozeile kompilieren.
2. **Eingabedatei vorbereiten**: Erstelle eine `.txt`-Datei, die du verschlüsseln möchtest, und speichere sie in einem bekannten Verzeichnis.
3. **Konfiguration**: Stelle sicher, dass die Pfade in der `main`-Methode korrekt auf die Eingabedatei und den Speicherort für den Schlüssel verweisen.
4. **Ausführen**: Führe die `main`-Methode aus. Die Datei wird verschlüsselt und der verschlüsselte Inhalt wird in derselben Datei gespeichert.
5. **Entschlüsselung**: Beim nächsten Ausführen des Programms wird der verschlüsselte Inhalt automatisch entschlüsselt, wenn die Schlüsseldatei vorhanden ist.
