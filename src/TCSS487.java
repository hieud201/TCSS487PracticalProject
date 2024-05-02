import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;

public class TCSS487 {

    private static final SecureRandom z = new SecureRandom();

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.out.println("Usage: java Main <command>");
            return;
        }

        String command = args[0];
        switch (command) {
            case "hashUserInput":
                if (args.length < 2) {
                    System.out.println("Usage: java Main hashUserInput <input>");
                    return;
                }
                String userInput = args[1];
                computeHash(userInput);
                break;
            case "hashFromFile":
                if (args.length == 1) { // using default filePath: ./dataInput.txt
                    String currentDir = System.getProperty("user.dir");
                    computeHashFromFile(currentDir + "\\dataInput.txt");
                } else computeHashFromFile(args[1]);
                break;
            case "macUserInput":
                if (args.length < 2) {
                    System.out.println("Usage: java Main macUserInput <input>");
                    return;
                }
                String macInput = args[1];
                computeMAC(macInput);
                break;
            case "macFromFile":
                computeMACFromFile(args[1], args[2]);
                break;
            case "encrypt":
                if (args.length < 2) {
                    System.out.println("Usage: java Main encryptFromFile <inputFile>");
                    return;
                }else if( args.length ==  2){ // using the default toBeEncrypted filepath.
                    String currentDir = System.getProperty("user.dir");
                    encryptFile(args[1], currentDir + "\\toBeEncrypted.txt");
                } else encryptFile(args[1], args[2]);
                break;
            case "decrypt":
                if (args.length < 2) {
                    System.out.println("Usage: java Main encryptFromFile <inputFile>");
                    return;
                }else if( args.length ==  2){ // using the default toBeEncrypted filepath.
                    String currentDir = System.getProperty("user.dir");
                    decryptFromFile(args[1], currentDir + "\\encryptedFile.txt");
                } else decryptFromFile(args[1], args[2]);

                break;
            default:
                System.out.println("Invalid command.");
        }
    }

    private static void computeHash(String input) {
        // Implement hash computation from user input
    }

    private static void computeHashFromFile(String filename) {
        try {
            byte[] byteArray = readByteArrayFromFile(filename);
            System.out.println("Byte array read from file: \n" + byteArrayToHexString(byteArray));
            byte[] outBytes = Keccak.KMACXOF256("", byteArray, 512, "D");
            System.out.println("Hashed Output:");

            System.out.println(byteArrayToHexString(outBytes));

        } catch (IOException e) {
            System.err.println("Error reading file: " + e.getMessage());
        }
    }

    private static void computeMAC(String input) {
        // Implement MAC computation from user input
    }

    private static void computeMACFromFile(String pw, String filePath) {
        try {
            byte[] byteArray = readByteArrayFromFile(filePath);
            System.out.println("Byte array read from file: \n" + byteArrayToHexString(byteArray));
            System.out.println("User passphrase input: " + pw);

            byte[] outBytes = Keccak.KMACXOF256(pw, byteArray, 512, "D");
            System.out.println("Hashed Output:");

            System.out.println(byteArrayToHexString(outBytes));

        } catch (IOException e) {
            System.err.println("Error reading file: " + e.getMessage());
        }
    }

    private static void encryptFile(String inputFile) {
        // Implement file encryption
    }

    private static void decryptFile(String encryptedFile) {
        // Implement file decryption
    }
    /**
     * Encrypts a given data file symmetrically under a given passphrase
     * and stores the cryptogram in an encrypted file.
     * Ref NIST Special Publication 800-185.
     *
     * @throws IOException if the file can't be read
     */
    private static void encryptFile(String pw, String filePath) throws IOException {

        String fileContent = readStringFromFile(filePath);
        byte[] byteArray = fileContent.getBytes();

        byte[] z = new byte[64];
        TCSS487.z.nextBytes(z);

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

    private static void decryptFromFile(String pw, String filePath) {
        byte[] decryptedByteArray = new byte[0];

        try {
            byte[] inputByteArray = readByteArrayFromFile(filePath);
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

    private static String readStringFromFile(String filePath) {
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
            e.printStackTrace();
            return null;
        }
        return contentBuilder.toString();
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
        String currentDir = System.getProperty("user.dir");

        try (FileWriter writer = new FileWriter(currentDir + "/encryptedFile.txt")) {
            writer.write(byteArray);
        }
    }
}
