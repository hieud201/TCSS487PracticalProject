import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;

public class Main {
    /**
     * Secure random field variable.
     */
    private static final SecureRandom z = new SecureRandom();

    /**
     * Resulted cryptogram from encryption.
     */
    private static byte[] previousCryptogram;

    public static void main(String[] args) throws IOException {

        Scanner scanner = new Scanner(System.in);
        System.out.println("Welcome to CryptoApp!");

        while (true) {
            System.out.println("\nChoose an option:");
            System.out.println("1. Compute a plain cryptographic hash (KMACXOF256)");
            System.out.println("2. Compute an authentication tag (MAC)");
            System.out.println("3. Encrypt a file symmetrically");
            System.out.println("4. Decrypt a symmetric cryptogram");
            System.out.println("5. Exit");
            System.out.print("Enter your choice: ");
            int choice = scanner.nextInt();
            scanner.nextLine(); // Consume newline

            switch (choice) {
                case 1 -> computePlainHashOption();
                case 2 -> computeAuthMACOption();
                case 3 -> encryptFile();
                case 4 -> decryptFile(decryptPreviousEncryptOrGivenCryptogram(scanner));
                case 5 -> {
                    System.out.println("Exiting CryptoApp. Goodbye!");
                    System.exit(0);
                }
                default -> System.out.println("Invalid choice. Please try again.");
            }
            System.out.println("===============================================");
        }

    }

    private static void computePlainHashOption() {
        Scanner scanner = new Scanner(System.in);
        System.out.println("\nChoose an option:");
        System.out.println("1. Compute a plain cryptographic hash from user input");
        System.out.println("2. Compute a plain cryptographic hash from file (src/dataInput.txt)");
        System.out.print("Enter your choice: ");
        int choice = scanner.nextInt();
        scanner.nextLine(); // Consume newline

        switch (choice) {
            case 1 -> computePlainHashFromInput();
            case 2 -> computePlainHashFromFile();
            default -> System.out.println("Invalid choice. Please try again.");
        }
        System.out.println("===============================================");
    }

    private static void computePlainHashFromInput() {

        byte[] byteArrayInputData = readByteArray("Enter Data as a byte array in hexadecimal format (e.g., 01 A8 02): ");
        if (byteArrayInputData != null) {
            System.out.println("Byte array input: ");
            System.out.println(byteArrayToHexString(byteArrayInputData));
        }

        byte[] outBytes = Keccak.KMACXOF256("", byteArrayInputData, 512, "D");
        System.out.println("Hashed Output:");
        System.out.println(byteArrayToHexString(outBytes) + "\n");
    }

    private static void computePlainHashFromFile() {
        String filePath = "src/dataInput.txt";
        try {
            byte[] byteArray = readByteArrayFromFile(filePath);
            System.out.println("Byte array read from file: \n" + byteArrayToHexString(byteArray));
            byte[] outBytes = Keccak.KMACXOF256("", byteArray, 512, "D");
            System.out.println("Hashed Output:");

            System.out.println(byteArrayToHexString(outBytes));

        } catch (IOException e) {
            System.err.println("Error reading file: " + e.getMessage());
        }
    }

    private static void computeAuthMACOption() {
        Scanner scanner = new Scanner(System.in);
        System.out.println("\nChoose an option:");
        System.out.println("1. Compute an authentication tag (MAC) from user input");
        System.out.println("2. Compute an authentication tag (MAC) from file (src/dataInput.txt)");
        System.out.print("Enter your choice: ");
        int choice = scanner.nextInt();
        scanner.nextLine(); // Consume newline

        switch (choice) {
            case 1 -> computeAuthMACFromInput();
            case 2 -> computeAuthMACFromFile();
            default -> System.out.println("Invalid choice. Please try again.");
        }
        System.out.println("===============================================");
    }

    private static void computeAuthMACFromInput() {
        byte[] byteArrayInputData = readByteArray("Enter Data as a byte array in hexadecimal format (e.g., 01 A8 02): ");
        if (byteArrayInputData != null) {
            System.out.println("Byte array input: ");
            System.out.println(byteArrayToHexString(byteArrayInputData));
        }
        String pw = readStringInput("Enter passphrase  (as a character string): ");
        System.out.println("User passphrase input: " + pw);

        byte[] outBytes = Keccak.KMACXOF256(pw, byteArrayInputData, 512, "D");
        System.out.println("Hashed Output:");
        System.out.println(byteArrayToHexString(outBytes) + "\n");
    }

    private static void computeAuthMACFromFile() {
        String filePath = "src/dataInput.txt";
        try {
            byte[] byteArray = readByteArrayFromFile(filePath);
            System.out.println("Byte array read from file: \n" + byteArrayToHexString(byteArray));
            String pw = readStringInput("Enter passphrase  (as a character string): ");
            System.out.println("User passphrase input: " + pw);

            byte[] outBytes = Keccak.KMACXOF256(pw, byteArray, 512, "D");
            System.out.println("Hashed Output:");

            System.out.println(byteArrayToHexString(outBytes));

        } catch (IOException e) {
            System.err.println("Error reading file: " + e.getMessage());
        }
    }

    private static void encryptFile() {
        Scanner userIn = new Scanner(System.in);
        File theFile = getUserInputFile(userIn);
        String theFileContent = fileToString(theFile);
        byte[] byteArray = theFileContent.getBytes();
        String pw = readStringInput("Enter passphrase  (as a character string): ");
        System.out.println("User passphrase input: " + pw);
        previousCryptogram = encryptKMAC(byteArray, pw);
        System.out.println(byteArrayToHexString(previousCryptogram));
    }

    /**
     * Helper method that contains the logical work of the encryption service.
     * @param m the byte array to be encrypted.
     * @param pw the passphrase given by the user.
     * @return an encrypted version of the given byte array.
     */
    private static byte[] encryptKMAC(byte[] m, String pw) {
        byte[] rand = new byte[64];
        z.nextBytes(rand);

        //squeeze bits from sponge
        byte[] keka = Keccak.KMACXOF256(new String(Keccak.concatByteArrays(rand, pw.getBytes())), "".getBytes(), 1024, "S");
        byte[] ke = new byte[64];
        System.arraycopy(keka,0,ke,0,64);
        byte[] ka = new byte[64];
        System.arraycopy(keka, 64,ka,0,64);

        byte[] c = Keccak.KMACXOF256(new String(ke), "".getBytes(), (m.length * 8), "SKE");
        c =  Keccak.xorBytes(c, m);
        byte[] t = Keccak.KMACXOF256(new String(ka), m, 512, "SKA");

        return Keccak.concatByteArrays(Keccak.concatByteArrays(rand, c), t);
    }

    /**
     * Decrypts a symmetric cryptogram under a given passphrase.
     *
     * @throws IOException if an I/O error with reading from a file occurs during the decryption process.
     * @author Hieu Doan
     * Largely inspired from
     * <a href="https://github.com/skweston/SHA3/blob/master/Driver.java#L388">
     * https://github.com/skweston/SHA3/blob/master/Driver.java#L388
     * </a>
     */
    private static void decryptFile(String input) throws IOException {
        Scanner userIn = new Scanner(System.in);
        String thePassphrase;
        byte[] decryptedByteArray = new byte[0];
        System.out.println("Please enter a passphrase used to encrypt: ");
        thePassphrase = userIn.nextLine();
        if (input.equals("prev encrypt")) { //input from file
            decryptedByteArray = decryptKMAC(previousCryptogram, thePassphrase);
        } else if (input.equals("user input")) { //input from command line
            System.out.println("\nPlease input a cryptogram in hex string format in one line (spaces okay, NO NEW LINES!!!!!): \n");
            String userString = userIn.nextLine();
            byte[] hexBytes = hexStringToBytes(userString);
            decryptedByteArray = decryptKMAC(hexBytes, thePassphrase);
        }
        System.out.println("\nDecryption in Hex format:\n" + byteArrayToHexString(decryptedByteArray));
        System.out.println("\nDecryption in String format:\n" + new String (decryptedByteArray, StandardCharsets.UTF_8));
    }

    private static String decryptPreviousEncryptOrGivenCryptogram(Scanner userIn) {
        String menuPrompt = """
                What format would you like your input:
                    1) Most recently encrypted (requires use of encryption service first).
                    2) User inputted cryptogram
                """;
        int response = getIntInRange(userIn, menuPrompt, 1, 2);
        if (response == 1) {
            return "prev encrypt";
        } else {
            return "user input";
        }
    }

    /**
     * Checks to see whether the user inputted an int or not.
     * @param userIn is the scanner that will be used for user input.
     * @param prompt is the prompt that the user is answering.
     * @return the user inputted int.
     */
    public static int getInt(final Scanner userIn, final String prompt) {
        System.out.println(prompt);
        while (!userIn.hasNextInt()) {
            userIn.next();
            System.out.println("Invalid input. Please enter an integer.");
            System.out.println(prompt);
        }
        return userIn.nextInt();
    }

    /**
     * Checks whether the user inputted integer is within the desired range.
     * This will keep running until the user inputs an integer that is in the desired range.
     * @param userIn is the scanner that will be used for user input.
     * @param prompt is the prompt that the user is answering from.
     * @param minMenuInput the low end of the options on the menu.
     * @param maxMenuInput the high end of the options on the menu.
     * @return the user inputted int that is within the desired range.
     */
    public static int getIntInRange(final Scanner userIn, final String prompt,
                                    final int minMenuInput, final int maxMenuInput) {
        int input = getInt(userIn, prompt);
        while (input < minMenuInput || input > maxMenuInput) {
            System.out.print("Input out of range.\nPlease enter a number that corresponds to a menu prompt.\n");
            input = getInt(userIn, prompt);
        }
        return input;
    }

    /**
     * Helper method that contains the logical work of the decryption service.
     * @param cryptogram the symmetric cryptogram to be decrypted.
     * @param pw the passphrase given by the user.
     * @return a decrypted version of the given cryptogram.
     */
    private static byte[] decryptKMAC(byte[] cryptogram, String pw) {
        byte[] rand = new byte[64];
        //retrieve 512-bit random number contacted to beginning of cryptogram
        System.arraycopy(cryptogram, 0, rand, 0, 64);

        //retrieve the encrypted message
        byte[] in = Arrays.copyOfRange(cryptogram, 64, cryptogram.length - 64);

        //retrieve tag that was appended to cryptogram
        byte[] tag = Arrays.copyOfRange(cryptogram, cryptogram.length - 64, cryptogram.length);

        //squeeze bits from sponge
        byte[] keka = Keccak.KMACXOF256(new String(Keccak.concatByteArrays(rand, pw.getBytes())), "".getBytes(), 1024, "S");
        byte[] ke = new byte[64];
        System.arraycopy(keka,0,ke,0,64);
        byte[] ka = new byte[64];
        System.arraycopy(keka, 64,ka,0,64);

        byte[] m = Keccak.KMACXOF256(new String(ke), "".getBytes(), (in.length*  8), "SKE");
        m = Keccak.xorBytes(m, in);

        byte[] tPrime = Keccak.KMACXOF256(new String(ka), m, 512, "SKA");

        if (Arrays.equals(tag, tPrime)) {
            return m;
        }
        else {
            throw new IllegalArgumentException("Tags didn't match");
        }
    }

    /************************************************************
     *                      Helper Methods                      *
     ************************************************************/

    /**
     * Converts the content of a file to String format.
     * @param theFile the File object to be converted.
     * @return the converted String object.
     */
    public static String fileToString(final File theFile) {
        String theString = null;
        try {
            theString = new String(Files.readAllBytes(theFile.getAbsoluteFile().toPath()));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return theString;
    }

    /**
     * Asks the user for a file path.
     * If correctly verified, the method will create a File object from that path.
     * @param userIn the scanner used when asking the user for the file path.
     * @return the File object created from the verified path.
     */
    public static File getUserInputFile(final Scanner userIn) {
        File theFile;
        boolean pathVerify = false;
        String filePrompt = "Please enter the full path of the file:";
        do {
            System.out.println(filePrompt);
            theFile = new File(userIn.nextLine());
            if (theFile.exists()) {
                pathVerify = true;
            } else {
                System.out.println("ERROR: File doesn't exist.");
            }
        } while (!pathVerify);

        return theFile;
    }

    private static String byteArrayToBinary(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0'));
        }
        return sb.toString();
    }

    private static String byteArrayToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }

    /**
     * Takes a String representation of Hex values and coverts it to a byte array.
     * <a href="https://www.tutorialspoint.com/convert-hex-string-to-byte-array-in-java#:~:text=To%20convert%20hex%20string%20to,length%20of%20the%20byte%20array">
     *     https://www.tutorialspoint.com/convert-hex-string-to-byte-array-in-java
     * </a>.
     * @param s String of hex values
     * @return byte array
     */
    public static byte[] hexStringToBytes(String s) {
        s = s.replaceAll("\\s", "");
        byte[] val = new byte[s.length()/2];
        for (int i = 0; i < val.length; i++) {
            int index = i * 2;
            int j = Integer.parseInt(s.substring(index,index + 2), 16);
            val[i] = (byte) j;
        }
        return val;
    }

    private static String readStringInput(String prompt) {
        Scanner scanner = new Scanner(System.in);
        System.out.print(prompt);
        return scanner.nextLine();
    }

    private static byte[] readByteArray(String prompt) {
        Scanner scanner = new Scanner(System.in);
        System.out.print(prompt);
        String input = scanner.nextLine();

        List<Byte> byteList = new ArrayList<>();
        String[] parts = input.split("\\s+");
        for (String part : parts) {
            if (part.isEmpty()) continue;
            try {
                byte b = (byte) Integer.parseInt(part, 16);
                byteList.add(b);
            } catch (NumberFormatException e) {
                System.out.println("Invalid input format. Please use hexadecimal format (e.g., 01 A8 02).");
                return null;
            }
        }

        byte[] byteArray = new byte[byteList.size()];
        for (int i = 0; i < byteList.size(); i++) {
            byteArray[i] = byteList.get(i);
        }
        return byteArray;

    }

    private static byte[] readByteArrayFromString(String s) {
        String[] hexValues = s.split("\\s+");
        byte[] byteArray = new byte[hexValues.length];

        for (int i = 0; i < hexValues.length; i++) {
            byteArray[i] = (byte) Integer.parseInt(hexValues[i], 16);
        }
        return byteArray;
    }

    public static byte[] readByteArrayFromFile(String filePath) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line = reader.readLine();
            if (line == null) {
                throw new IOException("File is empty");
            }
            String[] hexValues = line.trim().split("\\s+");
            byte[] byteArray = new byte[hexValues.length];
            for (int i = 0; i < hexValues.length; i++) {
                byteArray[i] = (byte) Integer.parseInt(hexValues[i], 16);
            }
            return byteArray;
        }
    }
}