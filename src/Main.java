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

        // Initialize Scanner object to read user input
        Scanner scanner = new Scanner(System.in);
        System.out.println("Welcome to CryptoApp!");

        // Main menu loop
        while (true) {
            // Display the main menu options
            System.out.println("\nChoose an option:");
            System.out.println("1. Compute a plain cryptographic hash (KMACXOF256)");
            System.out.println("2. Compute an authentication tag (MAC)");
            System.out.println("3. Encrypt a file symmetrically");
            System.out.println("4. Decrypt a symmetric cryptogram");
            System.out.println("5. Exit");
            System.out.print("Enter your choice: ");
            
            // Read the user's choice
            int choice = scanner.nextInt();
            scanner.nextLine(); // Consume newline

            // Execute the corresponding action based on the user's choice
            switch (choice) {
                case 1 -> computePlainHashOption(); // Compute plain cryptographic hash
                case 2 -> computeAuthMACOption(); // Compute authentication tag (MAC)
                case 3 -> encryptFile(); // Encrypt a file symmetrically
                case 4 -> decryptOption(); // Decrypt a symmetric cryptogram
                case 5 -> {
                    // Exit the program
                    System.out.println("Exiting CryptoApp. Goodbye!");
                    System.exit(0);
                }
                default -> System.out.println("Invalid choice. Please try again."); // Invalid choice
            }
            System.out.println("===============================================");
        }

    }

    /**
     * Allows the user to choose between computing a plain cryptographic hash
     * from user input or from a file, and executes the corresponding method.
     * Author: An Ho
     */
    private static void computePlainHashOption() {
        // Initialize a Scanner object to read user input
        Scanner scanner = new Scanner(System.in);
        
        // Print the menu options for the user
        System.out.println("\nChoose an option:");
        System.out.println("1. Compute a plain cryptographic hash from user input");
        System.out.println("2. Compute a plain cryptographic hash from file (src/dataInput.txt)");
        System.out.print("Enter your choice: ");
        
        // Read the user's choice
        int choice = scanner.nextInt();
        scanner.nextLine(); // Consume newline
        
        // Execute the corresponding action based on the user's choice
        switch (choice) {
            case 1 -> computePlainHashFromInput(); // Compute hash from user input
            case 2 -> computePlainHashFromFile(); // Compute hash from file
            default -> System.out.println("Invalid choice. Please try again."); // Invalid choice
        }
        
        // Print a separator to visually separate the output
        System.out.println("===============================================");
    }
    /**
     * Computes a plain hash from input data provided as a byte array in hexadecimal format.
     * Author: An Ho
     */
    private static void computePlainHashFromInput() {
        // Prompt the user to enter data as a byte array in hexadecimal format
        byte[] byteArrayInputData = readByteArray("Enter Data as a byte array in hexadecimal format (e.g., 01 A8 02): ");
        if (byteArrayInputData != null) {
            // Print the byte array input in hexadecimal format
            System.out.println("Byte array input: ");
            System.out.println(byteArrayToHexString(byteArrayInputData));
        }
        // Compute the hash using the Keccak algorithm
        // Parameters: key (empty string), input data byte array, output length (512 bits), customization string ("D")
        byte[] outBytes = Keccak.KMACXOF256("", byteArrayInputData, 512, "D");
        // Print the hashed output in hexadecimal format
        System.out.println("Hashed Output:");
        System.out.println(byteArrayToHexString(outBytes) + "\n");
    }
    /**
     * Reads data from a file, computes its hash, and prints the result.
     * Author: An Ho
     */
    private static void computePlainHashFromFile() {
        // Define the file path from which data will be read
        String filePath = "src/dataInput.txt";
        try {
            // Read data from the file and store it in a byte array
            byte[] byteArray = readByteArrayFromFile(filePath);
            
            // Print the byte array read from the file in hexadecimal format
            System.out.println("Byte array read from file: \n" + byteArrayToHexString(byteArray));
            
            // Compute the hash using the Keccak algorithm
            // Parameters: key (empty string), input data byte array, output length (512 bits), customization string ("D")
            byte[] outBytes = Keccak.KMACXOF256("", byteArray, 512, "D");
            
            // Print the hashed output in hexadecimal format
            System.out.println("Hashed Output:");
            System.out.println(byteArrayToHexString(outBytes));

        } catch (IOException e) {
            // Handle file reading errors
            System.err.println("Error reading file: " + e.getMessage());
        }
    }

    /**
     * Allows the user to choose between computing an authentication tag (MAC)
     * from user input or from a file, and executes the corresponding method.
     * Author: An Ho
     */
    private static void computeAuthMACOption() {
        // Initialize a Scanner object to read user input
        Scanner scanner = new Scanner(System.in);
        
        // Print the menu options for the user
        System.out.println("\nChoose an option:");
        System.out.println("1. Compute an authentication tag (MAC) from user input");
        System.out.println("2. Compute an authentication tag (MAC) from file (src/dataInput.txt)");
        System.out.print("Enter your choice: ");
        
        // Read the user's choice
        int choice = scanner.nextInt();
        scanner.nextLine(); // Consume newline
        
        // Execute the corresponding action based on the user's choice
        switch (choice) {
            case 1 -> computeAuthMACFromInput(); // Compute MAC from user input
            case 2 -> computeAuthMACFromFile(); // Compute MAC from file
            default -> System.out.println("Invalid choice. Please try again."); // Invalid choice
        }
        
        // Print a separator to visually separate the output
        System.out.println("===============================================");
    }




    /**
     * Computes an authentication tag (MAC) from user input data and passphrase.
     * Author: An Ho
     */
    private static void computeAuthMACFromInput() {
        // Prompt the user to enter data as a byte array in hexadecimal format
        byte[] byteArrayInputData = readByteArray("Enter Data as a byte array in hexadecimal format (e.g., 01 A8 02): ");
        
        // If input data is not null, print it in hexadecimal format
        if (byteArrayInputData != null) {
            System.out.println("Byte array input: ");
            System.out.println(byteArrayToHexString(byteArrayInputData));
        }
        
        // Prompt the user to enter a passphrase as a character string
        String pw = readStringInput("Enter passphrase  (as a character string): ");
        System.out.println("User passphrase input: " + pw);

        // Compute the hash using the Keccak algorithm
        // Parameters: passphrase, input data byte array, output length (512 bits), customization string ("D")
        byte[] outBytes = Keccak.KMACXOF256(pw, byteArrayInputData, 512, "D");
        
        // Print the hashed output in hexadecimal format
        System.out.println("Hashed Output:");
        System.out.println(byteArrayToHexString(outBytes) + "\n");
    }


    /**
     * Computes an authentication tag (MAC) from data read from a file and a passphrase.
     * @throws IOException if the file can't be read
     * Author: An Ho
     */
    private static void computeAuthMACFromFile() {
        // Define the file path from which data will be read
        String filePath = "src/dataInput.txt";
        try {
            // Read data from the file and store it in a byte array
            byte[] byteArray = readByteArrayFromFile(filePath);
            
            // Print the byte array read from the file in hexadecimal format
            System.out.println("Byte array read from file: \n" + byteArrayToHexString(byteArray));
            
            // Prompt the user to enter a passphrase as a character string
            String pw = readStringInput("Enter passphrase  (as a character string): ");
            System.out.println("User passphrase input: " + pw);

            // Compute the hash using the Keccak algorithm
            // Parameters: passphrase, input data byte array, output length (512 bits), customization string ("D")
            byte[] outBytes = Keccak.KMACXOF256(pw, byteArray, 512, "D");
            
            // Print the hashed output in hexadecimal format
            System.out.println("Hashed Output:");
            System.out.println(byteArrayToHexString(outBytes));

        } catch (IOException e) {
            // Handle file reading errors
            System.err.println("Error reading file: " + e.getMessage());
        }
    }


    /**
     * Encrypts a given data file symmetrically under a given passphrase
     * and stores the cryptogram in an encrypted file.
     * Reference: NIST Special Publication 800-185.
     *
     * @throws IOException if the file can't be read
     * 
     */
    private static void encryptFile() throws IOException {
        // Initialize Scanner object to read user input
        Scanner userIn = new Scanner(System.in);
        
        // Get input file from user
        File inputFile = getInputFile(userIn);
        
        // Read file content into a string
        String fileContent = fileToString(inputFile);
        
        // Convert file content to byte array
        byte[] byteArray = fileContent.getBytes();
        
        // Prompt the user to enter a passphrase
        String pw = readStringInput("Enter a passphrase (as a character string): ");

        // Generate random bytes 'z' and derive 'ke' and 'ka' from the passphrase and 'z'
        byte[] z = new byte[64];
        Main.z.nextBytes(z); // Assuming Main.z is an instance of SecureRandom
        byte[] keka = Keccak.KMACXOF256(new String(Keccak.concatByteArrays(z, pw.getBytes())), "".getBytes(), 1024, "S");
        byte[] ke = new byte[64];
        System.arraycopy(keka,0,ke,0,64);
        byte[] ka = new byte[64];
        System.arraycopy(keka, 64,ka,0,64);

        // Encrypt the file content using symmetric encryption (SKE) and derive the tag 't' (SKA)
        byte[] c = Keccak.KMACXOF256(new String(ke), "".getBytes(), (byteArray.length * 8), "SKE");
        c =  Keccak.xorBytes(c, byteArray);
        byte[] t = Keccak.KMACXOF256(new String(ka), byteArray, 512, "SKA");

        // Concatenate 'z', 'c', and 't' to form the cryptogram
        byte[] previousCryptogram =  Keccak.concatByteArrays(Keccak.concatByteArrays(z, c), t);
        
        // Write the cryptogram to a file
        writeToFile(byteArrayToHexString(previousCryptogram));

        // Print the cryptogram
        System.out.println("Cryptogram:\n" + byteArrayToHexString(previousCryptogram));
    }

    /**
     * Allows the user to choose between decrypting a symmetric cryptogram
     * from user input or from a file, and executes the corresponding method.
     */
    private static void decryptOption() {
        // Initialize a Scanner object to read user input
        Scanner scanner = new Scanner(System.in);
        
        // Print the menu options for the user
        System.out.println("\nChoose an option:");
        System.out.println("1. Decrypt a symmetric cryptogram from user input");
        System.out.println("2. Decrypt a symmetric cryptogram from given file (src/encryptedFile.txt). This option requires prior encryption.");
        System.out.print("Enter your choice: ");
        
        // Read the user's choice
        int choice = scanner.nextInt();
        scanner.nextLine(); // Consume newline
        
        // Execute the corresponding action based on the user's choice
        switch (choice) {
            case 1 -> decryptFromInput(); // Decrypt from user input
            case 2 -> decryptFromFile(); // Decrypt from file
            default -> {
                // Invalid choice, prompt user to try again
                System.out.println("Invalid choice. Please try again.");
                System.out.println("===============================================");
                decryptOption(); // Recursively call decryptOption() to prompt again
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

    /**
     * Converts a byte array to a hexadecimal string representation.
     * Each byte is converted to its hexadecimal equivalent and concatenated with a space.
     * Example: [0x01, 0xA8, 0x02] -> "01 A8 02 "
     *
     * @param bytes The byte array to be converted.
     * @return The hexadecimal string representation of the byte array.
     */
    private static String byteArrayToHexString(byte[] bytes) {
        // Create a StringBuilder to construct the hexadecimal string
        StringBuilder sb = new StringBuilder();
        
        // Iterate through each byte in the byte array
        for (byte b : bytes) {
            // Convert the byte to its hexadecimal representation and append it to the StringBuilder
            // The "%02X" format specifier ensures that each byte is represented by two hexadecimal digits
            sb.append(String.format("%02X ", b));
        }
        
        // Convert the StringBuilder to a string and return
        return sb.toString();
    }

    /**
     * Author: An Ho
     * Reads a string input from the user.
     *
     * @param prompt The prompt message to display to the user.
     * @return The string input provided by the user.
     * 
     */
    private static String readStringInput(String prompt) {
        // Create a Scanner object to read input from the console
        Scanner scanner = new Scanner(System.in);
        
        // Print the prompt message to the console
        System.out.print(prompt);
        
        // Read the string input provided by the user and return it
        return scanner.nextLine();
    }

    /**
     * Author: An Ho
     * Reads a byte array input from the user in hexadecimal format.
     *
     * @param prompt The prompt message to display to the user.
     * @return The byte array input provided by the user.
     */
    private static byte[] readByteArray(String prompt) {
        // Create a Scanner object to read input from the console
        Scanner scanner = new Scanner(System.in);
        
        // Print the prompt message to the console
        System.out.print(prompt);
        
        // Read the input string provided by the user
        String input = scanner.nextLine();

        // Create a list to store bytes parsed from the input
        List<Byte> byteList = new ArrayList<>();

        // Split the input string by whitespace
        String[] parts = input.split("\\s+");

        // Iterate through each part of the input
        for (String part : parts) {
            // Skip empty parts
            if (part.isEmpty()) continue;
            try {
                // Parse the part as a hexadecimal integer and convert it to a byte
                byte b = (byte) Integer.parseInt(part, 16);
                // Add the byte to the byte list
                byteList.add(b);
            } catch (NumberFormatException e) {
                // Handle invalid input format (non-hexadecimal characters)
                System.out.println("Invalid input format. Please use hexadecimal format (e.g., 01 A8 02).");
                return null; // Return null to indicate error
            }
        }

        // Convert the byte list to a byte array
        byte[] byteArray = new byte[byteList.size()];
        for (int i = 0; i < byteList.size(); i++) {
            byteArray[i] = byteList.get(i);
        }
        
        // Return the byte array
        return byteArray;
    }


    /**
     * Author: An Ho
     * Parses a string containing hexadecimal values separated by whitespace
     * and converts it into a byte array.
     *
     * @param s The string containing hexadecimal values.
     * @return The byte array representing the hexadecimal values.
     */
    private static byte[] readByteArrayFromString(String s) {
        // Split the input string by whitespace to get individual hexadecimal values
        String[] hexValues = s.split("\\s+");
        
        // Create a byte array to store the parsed hexadecimal values
        byte[] byteArray = new byte[hexValues.length];

        // Iterate through each hexadecimal value
        for (int i = 0; i < hexValues.length; i++) {
            // Parse the hexadecimal string and convert it to a byte
            byteArray[i] = (byte) Integer.parseInt(hexValues[i], 16);
        }
        
        // Return the byte array
        return byteArray;
    }
    /**
     * Author: An Ho
     * Reads the contents of a file and returns it as a string.
     *
     * @param theFile The file to read.
     * @return The contents of the file as a string.
     */
    public static String fileToString(final File theFile) {
        // Initialize the string to store the file content
        String theString = null;
        try {
            // Read all bytes from the file and convert them to a string
            theString = new String(Files.readAllBytes(theFile.getAbsoluteFile().toPath()));
        } catch (IOException e) {
            // Handle file reading errors by printing the stack trace
            e.printStackTrace();
        }
        // Return the string representing the file content
        return theString;
    }


    /**
     * Author: An Ho
     * Reads a byte array from a file containing hexadecimal values separated by whitespace.
     *
     * @param filePath The path of the file to read.
     * @return The byte array representing the hexadecimal values from the file.
     * @throws IOException if an I/O error occurs while reading the file.
     */
    private static byte[] readByteArrayFromFile(String filePath) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            // Read the first line of the file
            String line = reader.readLine();
            // Check if the file is empty
            if (line == null) {
                throw new IOException("File is empty");
            }
            // Split the line into individual hexadecimal values
            String[] hexValues = line.trim().split("\\s+");
            // Create a byte array to store the parsed hexadecimal values
            byte[] byteArray = new byte[hexValues.length];
            // Convert each hexadecimal value to a byte and store it in the byte array
            for (int i = 0; i < hexValues.length; i++) {
                byteArray[i] = (byte) Integer.parseInt(hexValues[i], 16);
            }
            // Return the byte array representing the hexadecimal values from the file
            return byteArray;
        }
    }

/**
 * Author: An Ho
 * Writes a byte array representation to a file.
 *
 * @param byteArray The byte array representation to write to the file.
 * @throws IOException if an I/O error occurs while writing to the file.
 */
private static void writeToFile(String byteArray) throws IOException {
    // Use try-with-resources to ensure the FileWriter is properly closed
    try (FileWriter writer = new FileWriter("src/encryptedFile.txt")) {
        // Write the byte array representation to the file
        writer.write(byteArray);
    }
}
}