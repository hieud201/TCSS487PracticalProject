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
                case 4 -> decryptOption();
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

    /**
     * Encrypts a given data file symmetrically under a given passphrase
     * and stores the cryptogram in an encrypted file.
     * Ref NIST Special Publication 800-185.
     *
     * @throws IOException if the file can't be read
     */
    private static void encryptFile() throws IOException {
        Scanner userIn = new Scanner(System.in);
        File inputFile = getInputFile(userIn);
        String fileContent = fileToString(inputFile);
        byte[] byteArray = fileContent.getBytes();
        String pw = readStringInput("Enter a passphrase (as a character string): ");

        byte[] z = new byte[64];
        Main.z.nextBytes(z);

        byte[] keka = Keccak.KMACXOF256(new String(Keccak.concatByteArrays(z, pw.getBytes())), "".getBytes(), 1024, "S");
        byte[] ke = new byte[64];
        System.arraycopy(keka,0,ke,0,64);
        byte[] ka = new byte[64];
        System.arraycopy(keka, 64,ka,0,64);

        byte[] c = Keccak.KMACXOF256(new String(ke), "".getBytes(), (byteArray.length * 8), "SKE");
        c =  Keccak.xorBytes(c, byteArray);

        byte[] t = Keccak.KMACXOF256(new String(ka), byteArray, 512, "SKA");

        byte[] previousCryptogram =  Keccak.concatByteArrays(Keccak.concatByteArrays(z, c), t);
        writeToFile(byteArrayToHexString(previousCryptogram));

        System.out.println("Cryptogram:\n" + byteArrayToHexString(previousCryptogram));
    }

    private static void decryptOption() {
        Scanner scanner = new Scanner(System.in);
        System.out.println("\nChoose an option:");
        System.out.println("1. Decrypt a symmetric cryptogram from user input");
        System.out.println("2. Decrypt a symmetric cryptogram from given file (src/encryptedFile.txt). This option requires prior encryption.");
        System.out.print("Enter your choice: ");
        int choice = scanner.nextInt();
        scanner.nextLine(); // Consume newline

        switch (choice) {
            case 1 -> decryptFromInput();
            case 2 -> decryptFromFile();
            default -> {
                System.out.println("Invalid choice. Please try again.");
                System.out.println("===============================================");
                decryptOption();
            }
        }
    }

    private static void decryptFromInput() {
        Scanner scanner = new Scanner(System.in);
        byte[] decryptedByteArray;

        System.out.println("Please enter the passphrase used to encrypt: ");
        String pw = scanner.nextLine();
        System.out.println("Please input a cryptogram in hex string format in only one line:");
        String inputString = scanner.nextLine();
        byte[] inputByteArray = readByteArrayFromString(inputString);

        byte[] z = new byte[64];
        //retrieve 512-bit random number contacted to beginning of cryptogram
        System.arraycopy(inputByteArray, 0, z, 0, 64);

        //retrieve the encrypted message
        byte[] c = Arrays.copyOfRange(inputByteArray, 64, inputByteArray.length - 64);

        //retrieve tag that was appended to cryptogram
        byte[] t = Arrays.copyOfRange(inputByteArray, inputByteArray.length - 64, inputByteArray.length);

        //squeeze bits from sponge
        byte[] keka = Keccak.KMACXOF256(new String(Keccak.concatByteArrays(z, pw.getBytes())), "".getBytes(), 1024, "S");
        byte[] ke = new byte[64];
        System.arraycopy(keka,0,ke,0,64);
        byte[] ka = new byte[64];
        System.arraycopy(keka, 64,ka,0,64);

        byte[] m = Keccak.KMACXOF256(new String(ke), "".getBytes(), (c.length * 8), "SKE");
        m = Keccak.xorBytes(m, c);

        byte[] tPrime = Keccak.KMACXOF256(new String(ka), m, 512, "SKA");

        if (Arrays.equals(t, tPrime)) {
            decryptedByteArray = m;
            System.out.println("\nDecrypted output:\n" + new String(decryptedByteArray, StandardCharsets.UTF_8));
        }
        else {
            System.out.println("Tags didn't match!");
            decryptFromInput();
        }
    }

    private static void decryptFromFile() {
        byte[] decryptedByteArray = new byte[0];
        Scanner scanner = new Scanner(System.in);
        String filePath = "src/encryptedFile.txt";
        System.out.println("Please enter the passphrase used to encrypt: ");
        String pw = scanner.nextLine();

        try {
            File inputFile = new File(filePath);
            byte[] inputByteArray = readByteArrayFromFile(inputFile.getPath());

            byte[] z = new byte[64];
            System.arraycopy(inputByteArray, 0, z, 0, 64);
            byte[] c = Arrays.copyOfRange(inputByteArray, 64, inputByteArray.length - 64);
            byte[] t = Arrays.copyOfRange(inputByteArray, inputByteArray.length - 64, inputByteArray.length);

            byte[] keka = Keccak.KMACXOF256(new String(Keccak.concatByteArrays(z, pw.getBytes())), "".getBytes(), 1024, "S");
            byte[] ke = new byte[64];
            System.arraycopy(keka,0,ke,0,64);
            byte[] ka = new byte[64];
            System.arraycopy(keka, 64,ka,0,64);

            byte[] m = Keccak.KMACXOF256(new String(ke), "".getBytes(), (c.length * 8), "SKE");
            m = Keccak.xorBytes(m, c);

            byte[] tPrime = Keccak.KMACXOF256(new String(ka), m, 512, "SKA");

            if (Arrays.equals(t, tPrime)) {
                decryptedByteArray = m;
                System.out.println("\nDecrypted output:\n" + new String(decryptedByteArray, StandardCharsets.UTF_8));
            }
            else {
                System.out.println("Tags didn't match!");
                decryptFromFile();
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
     * @param scanner the scanner used to scan the user's file path.
     * @return the File object from the path.
     */
    public static File getInputFile(Scanner scanner) {
        File inputFile;
        boolean legit = false;

        do {
            System.out.println("Please enter the full path of the file: ");
            inputFile = new File(scanner.nextLine());
            if (inputFile.exists()) {
                legit = true;
            } else {
                System.out.println("ERROR: File doesn't exist.");
            }
        } while (!legit);

        return inputFile;
    }

    private static String byteArrayToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
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

    public static String fileToString(final File theFile) {
        String theString = null;
        try {
            theString = new String(Files.readAllBytes(theFile.getAbsoluteFile().toPath()));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return theString;
    }

    private static byte[] readByteArrayFromFile(String filePath) throws IOException {
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

    private static void writeToFile(String byteArray) throws IOException {
        try (FileWriter writer = new FileWriter("src/encryptedFile.txt")) {
            writer.write(byteArray);
        }
    }
}