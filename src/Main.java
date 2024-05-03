/**
 * @author Tin Phu, Hieu Doan, An Ho
 */

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 *  First, type in command <code>javac Main.java</code> to compile the file at its current dir. <br>
 *                            SERVICES: <br>
 * ========================================================= <br>
 * COMPUTE A PLAIN CRYPTOGRAPHIC HASH (KMACXOF256) <br><br>
 *
 * Compute a plain cryptographic hash from user input: <br>
 *          <code>java Main hash -code HexaCode(01 02 03)</code> <br><br>
 * Compute a plain cryptographic hash from file: <br>
 *  Hashing from the default file: (./dataInput.txt) <br>
 *          <code>java Main hash -file</code> <br>
 *  Hashing from a pathFile: <br>
 * 	        <code>java Main hash -file C:\Users\xx\xx</code> <br>
 * ========================================================= <br>
 * COMPUTE AN AUTHENTICATION TAG (MAC) <br><br>
 *
 * Compute an authentication tag (MAC) from user input: <br>
 *         <code>java Main mac -pw passwords -code HexaCode(01 02 03)</code> <br><br>
 * Compute an authentication tag (MAC) from file: <br>
 * 		Computing from the default file (./dataInput.txt): <br>
 *          <code>java Main mac -pw passwords -file</code> <br>
 *      Computing from a pathFile: <br>
 * 	        <code>java Main mac -pw passwords -file C:\Users\xx\xx</code> <br>
 * ========================================================= <br>
 * ENCRYPT A FILE SYMMETRICALLY <br><br>
 * 	    Computing from the default file (./toBeEncrypted.txt): <br>
 *          <code>java Main encrypt -pw passwords</code> <br><br>
 *      Computing from a pathFile: <br>
 * 	        <code>java Main encrypt -pw passwords -file C:\Users\xx\xx</code> <br>
 * ========================================================= <br>
 * DECRYPT A SYMMETRIC CRYPTOGRAM <br><br>
 * 		Decrypt from the default file (./encryptedFile.txt): <br>
 * 			<code>java Main decrypt -pw passwords</code> <br><br>
 * 		Decrypt from a pathFile: <br>
 * 			<code>java Main decrypt -pw passwords -file C:\Users\xx\xx</code>
 */
public class Main {
    /**
     * Secured-random number.
     */
    private static final SecureRandom random = new SecureRandom();

    /**
     * Driver code to handle command line arguments.
     *
     * @author Tin Phu
     * @param args command line arguments
     * @throws IOException If an input file can't be read.
     */
    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.out.println("Usage: java Main <command>");
            return;
        }

        CommandLineArgsHandler handler = new CommandLineArgsHandler(args);
        System.out.println(handler);

        String command = args[0];
        switch (command) {
            case "hash" -> {
                if (handler.hasTag("file")) {
                    if (handler.getValue("file").isEmpty()) { // using default filePath: ./dataInput.txt
                        String currentDir = System.getProperty("user.dir");
                        String filePath = currentDir + File.separator + "dataInput.txt";
                        System.out.println("Readding from: " + filePath);
                        computeHashFromFile(filePath);
                    } else computeHashFromFile(handler.getValue("file"));
                } else if (!handler.hasTag("code")) {
                    System.out.println("Missing -code");
                } else computeHashFromUserInput(handler.getValue("code"));
            }

            case "mac" -> {
                if (handler.hasTag("file")) {
                    if (!handler.hasTag("pw")) {
                        System.out.println("Missing -pw");
                    } else if (handler.getValue("file").isEmpty()) {
                        String currentDir = System.getProperty("user.dir");
                        String filePath = currentDir + File.separator + "dataInput.txt";
                        System.out.println("Readding from: " + filePath);
                        computeMACFromFile(handler.getValue("pw"), filePath);
                    } else {
                        System.out.println("Readding from: " + handler.getValue("file"));
                        computeMACFromFile(handler.getValue("pw"), handler.getValue("file"));
                    }
                } else {
                    if (!handler.hasTag("pw")) {
                        System.out.println("Missing -pw");
                    } else if (!handler.hasTag("code")) {
                        System.out.println("Missing -code");
                    } else {
                        computeMACFromUserInput(handler.getValue("code"), handler.getValue("pw"));
                    }
                }
            }

            case "encrypt" -> {
                if (!handler.hasTag("pw")) {
                    System.out.println("Missing -pw");
                } else {
                    if (!handler.hasTag("file") || handler.getValue("file").isEmpty()) {
                        String currentDir = System.getProperty("user.dir");
                        String filePath = currentDir + File.separator + "toBeEncrypted.txt";
                        System.out.println("Readding from: " + filePath);
                        encryptFile(handler.getValue("pw"), filePath);
                    } else encryptFile(handler.getValue("pw"), handler.getValue("file"));
                }
            }

            case "decrypt" -> {
                if (!handler.hasTag("pw")) {
                    System.out.println("Missing -pw");
                } else {
                    if (!handler.hasTag("file") || handler.getValue("file").isEmpty()) {
                        String currentDir = System.getProperty("user.dir");
                        String filePath = currentDir + File.separator + "encryptedFile.txt";
                        decryptFromFile(handler.getValue("pw"), filePath);
                    } else decryptFromFile(handler.getValue("pw"), handler.getValue("file"));
                }
            }
            default -> System.out.println("Invalid command.");
        }
    }

    /**
     * Computes a hash from user input given as a byte array string.
     *
     * @param byteArrayString The byte array string provided by the user in format of 01 02 03.
     * @author An Ho, Tin Phu
     */
    private static void computeHashFromUserInput(String byteArrayString) {
        // Convert the byte array string to a byte array
        byte[] byteArray = readByteArrayFromString(byteArrayString);
        byte[] outBytes = Keccak.KMACXOF256("", byteArray, 512, "D");
        System.out.println("Hashed Output:");
        System.out.println(byteArrayToHexString(outBytes) + "\n");
    }

    /**
     * Computes a hash from data read from a file.
     *
     * @author An Ho, Tin Phu
     * @param filePath absolute file path to .txt file
     */
    private static void computeHashFromFile(String filePath) {
        try {
            // Read the byte array from the specified file
            byte[] byteArray = readByteArrayFromFile(filePath);
            System.out.println("Byte array read from file: \n" + byteArrayToHexString(byteArray));
            byte[] outBytes = Keccak.KMACXOF256("", byteArray, 512, "D");
            System.out.println("Hashed Output:");
            System.out.println(byteArrayToHexString(outBytes));

        } catch (IOException e) {
            System.err.println(e.getMessage());
        }
    }

    /**
     * Computes a MAC (Message Authentication Code) from user input using a passphrase.
     *
     * @author An Ho, Tin Phu
     * @param byteArrayString The byte array string provided by the user in format of 01 02 03.
     * @param pw The passphrase or passwords provided by the user.
     */
    private static void computeMACFromUserInput(String byteArrayString, String pw) {
        // Convert the byte array string to a byte array
        byte[] byteArray = readByteArrayFromString(byteArrayString);
        System.out.println("User passphrase input: " + pw);
        byte[] outBytes = Keccak.KMACXOF256(pw, byteArray, 512, "D");
        System.out.println("Hashed Output:");
        System.out.println(byteArrayToHexString(outBytes) + "\n");
    }

    /**
     * Computes a MAC (Message Authentication Code) from data read from a file using a passphrase.
     *
     * @author An Ho, Tin Phu
     * @param pw The passphrase provided by the user.
     * @param filePath The path of the file containing data for MAC computation.
     */
    private static void computeMACFromFile(String pw, String filePath) {
        try {
            // Read the byte array from the specified file
            byte[] byteArray = readByteArrayFromFile(filePath);
            System.out.println("Byte array read from file: \n" + byteArrayToHexString(byteArray));
            System.out.println("User passphrase input: " + pw);
            byte[] outBytes = Keccak.KMACXOF256(pw, byteArray, 512, "D");
            System.out.println("Hashed Output:");
            System.out.println(byteArrayToHexString(outBytes));

        } catch (IOException e) {
            System.err.println("Error reading file: Please make sure that data is stored in the right format.");
        }
    }

    /**
     * Encrypts a given data file symmetrically under a given passphrase
     * and stores the cryptogram in a file as z || c || t.
     * Ref Programming Project Part 1 document.
     *
     * @author An Ho, Hieu Doan
     * @throws IOException if the file can't be written to
     */
    private static void encryptFile(String pw, String filePath) throws IOException {
        // converting file content to a byte array
        String fileContent = readStringFromFile(filePath);
        assert fileContent != null;
        byte[] byteArray = fileContent.getBytes();

        byte[] z = new byte[64];
        byte[] ke = new byte[64];
        byte[] ka = new byte[64];

        Main.random.nextBytes(z); // z <- Random(512)

        // (ke || ka) <- KMACXOF256(z || pw, “”, 1024, “S”)
        byte[] keka = Keccak.KMACXOF256(new String(Keccak.concatByteArrays(z, pw.getBytes())), "".getBytes(), 1024, "S");
        System.arraycopy(keka,0,ke,0,64);
        System.arraycopy(keka, 64,ka,0,64);

        // c <- KMACXOF256(ke, “”, |m|, “SKE”) XOR m
        byte[] c = Keccak.KMACXOF256(new String(ke), "".getBytes(), (byteArray.length * 8), "SKE");
        c =  Keccak.xorBytes(c, byteArray);

        // t <- KMACXOF256(ka, m, 512, “SKA”)
        byte[] t = Keccak.KMACXOF256(new String(ka), byteArray, 512, "SKA");

        // writing the cryptogram (z,c,t) to a file and printing it
        byte[] previousCryptogram =  Keccak.concatByteArrays(Keccak.concatByteArrays(z, c), t);
        writeToFile(byteArrayToHexString(previousCryptogram));
        System.out.println("Cryptogram:\n" + byteArrayToHexString(previousCryptogram));
    }

    /**
     * Decrypts data from a file using the provided passphrase.
     * Writes the given byte array to a file path "./encryptedFile.txt".
     * Ref Programming Project Part 1 document.
     *
     * @author Hieu Doan
     * @param pw The passphrase used for decryption.
     * @param filePath The path of the file containing the encrypted data.
     */
    private static void decryptFromFile(String pw, String filePath) {
        byte[] decryptedByteArray;

        try {
            // parsing the necessary components of the cryptogram
            byte[] inputByteArray = readByteArrayFromFile(filePath);
            byte[] z = new byte[64];
            System.arraycopy(inputByteArray, 0, z, 0, 64);
            byte[] c = Arrays.copyOfRange(inputByteArray, 64, inputByteArray.length - 64);
            byte[] t = Arrays.copyOfRange(inputByteArray, inputByteArray.length - 64, inputByteArray.length);

            // (ke || ka) <- KMACXOF256(z || pw, “”, 1024, “S”)
            byte[] keka = Keccak.KMACXOF256(new String(Keccak.concatByteArrays(z, pw.getBytes())), "".getBytes(), 1024, "S");
            byte[] ke = new byte[64];
            System.arraycopy(keka,0,ke,0,64);
            byte[] ka = new byte[64];
            System.arraycopy(keka, 64,ka,0,64);

            // m <- KMACXOF256(ke, “”, |c|, “SKE”) XOR c
            byte[] m = Keccak.KMACXOF256(new String(ke), "".getBytes(), (c.length * 8), "SKE");
            m = Keccak.xorBytes(m, c);

            // t’ <- KMACXOF256(ka, m, 512, “SKA”)
            byte[] tPrime = Keccak.KMACXOF256(new String(ka), m, 512, "SKA");

            // printing the successful decryption when t' = t
            if (Arrays.equals(t, tPrime)) {
                decryptedByteArray = m;
                System.out.println("\nDecrypted output:\n" + new String(decryptedByteArray, StandardCharsets.UTF_8));
            } else {
                System.out.println("Tags didn't match!");
            }
        } catch (IOException e) {
            System.err.println("Error reading file: " + e.getMessage());
        }
    }

    /************************************************************
     *                      Helper Methods                      *
     ************************************************************/

    /**
     * Prompts the user for a file path and returns the corresponding file if the path exists.
     *
     * @author Tin Phu
     * @param bytes the scanner used to scan the user's file path.
     * @return the File object from the path.
     */
    private static String byteArrayToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }

    /**
     * Reads the content of a file specified by the given file path and returns it as a single string.
     *
     * @author Tin Phu
     * @param filePath The path of the file to read from.
     * @return The content of the file as a single string, or null if an error occurs.
     */
    private static String readStringFromFile(String filePath) {
        // StringBuilder to store the content of the file
        StringBuilder contentBuilder = new StringBuilder();
        try {
            File file = new File(filePath);
            BufferedReader reader = new BufferedReader(new FileReader(file));
            String line;
            while ((line = reader.readLine()) != null) {
                contentBuilder.append(line).append(System.lineSeparator());
            }
            reader.close();
        } catch (IOException e) {
            System.err.println("Error reading file: Please make sure that data is stored in the right format.");
            return null;
        }
        return contentBuilder.toString();
    }

    /**
     * Reads a byte array from a file specified by the given file path.
     *
     * @author Hieu Doan
     * @param filePath The path of the file to read from.
     * @return The byte array read from the file.
     * @throws IOException If an I/O error occurs while reading the file.
     */
    private static byte[] readByteArrayFromFile(String filePath) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line = reader.readLine();
            // handle empty string when read from the file
            if (line == null || line.trim().isEmpty()) {
                return new byte[0];
            }
            String[] hexValues = line.trim().split("\\s+");
            byte[] byteArray = new byte[hexValues.length];
            for (int i = 0; i < hexValues.length; i++) {
                byteArray[i] = (byte) Integer.parseInt(hexValues[i], 16);
            }
            return byteArray;
        }
    }

    /**
     * Writes the given byte array to a file named "encryptedFile.txt".
     *
     * @author Hieu Doan, An Ho
     * @param byteArray The byte array to be written to the file.
     * @throws IOException If an I/O error occurs while writing to the file.
     */
    private static void writeToFile(String byteArray) throws IOException {
        // Get the current directory path
        String currentDir = System.getProperty("user.dir");
        String filePath = currentDir + File.separator + "encryptedFile.txt";
        // Write the byte array to the file named "encryptedFile.txt" in the current directory
        try (FileWriter writer = new FileWriter(filePath)) {
            writer.write(byteArray);
        }
    }

    /**
     * Parses a string containing hexadecimal values separated by whitespace
     * and converts it into a byte array.
     *
     * @author An Ho
     * @param s The string containing hexadecimal values.
     * @return The byte array representing the hexadecimal values.
     */
    private static byte[] readByteArrayFromString(String s) {
        // Split the input string by whitespace into string array.
        String[] hexValues = s.split("\\s+");
        byte[] byteArray = new byte[hexValues.length];
        if (s.isEmpty()) return new byte[0];
        for (int i = 0; i < hexValues.length; i++) {
            // Parse the hexadecimal string and convert it to a byte
            byteArray[i] = (byte) Integer.parseInt(hexValues[i], 16);
        }
        return byteArray;
    }
}
