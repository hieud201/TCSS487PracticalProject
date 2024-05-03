/**
 * @author Tin Phu, Hieu Doan, An Ho
 */

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 *  javac TCSS487.java to compile the file at its current dir.
 *  services:
 * Compute a plain cryptographic hash (KMACXOF256)
 *
 * Compute a plain cryptographic hash from user input:
 *          java TCSS478 hash -code HexaCode(01 02 03)
 * Compute a plain cryptographic hash from file:
 *  Hashing from the default file (./dataInput.txt)
 *          java TCSS478 hash -file C:\Users\xx\xx
 *  Hashing from a pathFile  (./dataInput.txt)
 * 	        java TCSS478 hash -file C:\Users\xx\xx
 * ====================================================
 * Compute an authentication tag (MAC)
 *
 * Compute an authentication tag (MAC) from user input:
 *         java TCSS478 mac -pw passwords -code HexaCode(01 02 03)
 * Compute an authentication tag (MAC) from file
 * 		Computing from the default file (./dataInput.txt):
 *          java TCSS478 mac -pw passwords -file
 *      Computing from a pathFile:
 * 	        java TCSS478 mac -pw passwords -file C:\Users\xx\xx
 *=========================================================
 * Encrypt a file symmetrically
 * 	    Computing from the default file (./toBeEncrypted.txt):
 *          java TCSS478 encrypt -pw passwords
 *      Computing from a pathFile:
 * 	        java TCSS478 encrypt -pw passwords -file C:\Users\xx\xx
 * ==================================================
 * Decrypt a symmetric cryptogram
 * 		Decrypt from the default file (./encryptedFile.txt):
 * 			java TCSS478 decrypt -pw passwords
 * 		Decrypt from a pathFile  (./encryptedFile.txt):
 * 			java TCSS478 decrypt -pw passwords -file C:\Users\xx\xx
 */
public class TCSS487 {
    //generate Secured Random number.
    private static final SecureRandom z = new SecureRandom();

    /**
     * main to handle cmd
     * @author Tin Phu
     * @param args
     * @throws IOException
     */
    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.out.println("Usage: java Main <command>");
            return;
        }
        CommandLineArgsHandler handler = new CommandLineArgsHandler(args);
        System.out.println(handler.toString());
        String command = args[0];
        switch (command) {
            case "hash":
                if(handler.hasTag("file")){
                    if (handler.getValue("file").isEmpty()) { // using default filePath: ./dataInput.txt
                        String currentDir = System.getProperty("user.dir");
                        String filePath = currentDir + File.separator + "dataInput.txt";
                        System.out.println("Readding from: " + filePath );

                        computeHashFromFile(filePath);
                    } else computeHashFromFile(handler.getValue("file"));
                    break;
                } else if(!handler.hasTag("code")) {
                    System.out.println("Missing -code");
                } else computeHashFromUserInput(handler.getValue("code"));
                break;
            case "mac":
                if(handler.hasTag("file")){
                    if(!handler.hasTag("pw")){
                        System.out.println("Missing -pw");
                    } else if(handler.getValue("file").isEmpty()) {
                        String currentDir = System.getProperty("user.dir");
                        String filePath = currentDir + File.separator + "dataInput.txt";
                        System.out.println("Readding from: " + filePath );
                        computeMACFromFile(handler.getValue("pw"), filePath);
                    } else {
                        System.out.println("Readding from: " + handler.getValue("file"));
                        computeMACFromFile(handler.getValue("pw"), handler.getValue("file"));
                    }
                    break;
                } else {
                    if(!handler.hasTag("pw")){
                        System.out.println("Missing -pw");
                    } else if(!handler.hasTag("code")){
                        System.out.println("Missing -code");
                    } else
                    {
                        computeMACFromUserInput(handler.getValue("code"), handler.getValue("pw"));
                    }
                }
                break;
            case "encrypt":
                if(!handler.hasTag("pw")){
                    System.out.println("Missing -pw");
                } else {
                    if( !handler.hasTag("file") || handler.getValue("file").isEmpty()){
                        String currentDir = System.getProperty("user.dir");
                        String filePath = currentDir + File.separator + "toBeEncrypted.txt";
                        System.out.println("Readding from: " + filePath );
                        encryptFile(handler.getValue("pw"), filePath);
                    }else encryptFile(handler.getValue("pw"),handler.getValue("file") );
                }
                break;
            case "decrypt":
                if(!handler.hasTag("pw")){
                    System.out.println("Missing -pw");
                }else {
                    if (!handler.hasTag("file") || handler.getValue("file").isEmpty()) {
                        String currentDir = System.getProperty("user.dir");
                        String filePath = currentDir + File.separator + "encryptedFile.txt";
                        decryptFromFile(handler.getValue("pw"), filePath);
                    } else decryptFromFile(handler.getValue("pw"), handler.getValue("file"));
                }
                break;
            default:
                System.out.println("Invalid command.");
        }
    }

    /**
     * Computes a hash from user input given as a byte array string.
     *
     * @param byteArrayString The byte array string provided by the user.
     * @author An Ho
     */
    private static void computeHashFromUserInput(String byteArrayString) {
        // Convert the byte array string to a byte array
        byte[] byteArray = readByteArrayFromString(byteArrayString);
        
        // Compute the hash using the Keccak algorithm
        // Parameters: key (empty string), input data byte array, output length (512 bits), customization string ("D")
        byte[] outBytes = Keccak.KMACXOF256("", byteArray, 512, "D");
        
        // Print the hashed output in hexadecimal format
        System.out.println("Hashed Output:");
        System.out.println(byteArrayToHexString(outBytes) + "\n");
    }



    /**
     * Computes a hash from data read from a file.
     * @author An Ho
     * @param filename The name of the file containing data for hashing.
     */
    private static void computeHashFromFile(String filename) {
        try {
            // Read the byte array from the specified file
            byte[] byteArray = readByteArrayFromFile(filename);
            
            // Print the byte array read from the file in hexadecimal format
            System.out.println("Byte array read from file: \n" + byteArrayToHexString(byteArray));
            
            // Compute the hash using the Keccak algorithm
            // Parameters: key (empty string), input data byte array, output length (512 bits), customization string ("D")
            byte[] outBytes = Keccak.KMACXOF256("", byteArray, 512, "D");
            
            // Print the hashed output in hexadecimal format
            System.out.println("Hashed Output:");
            System.out.println(byteArrayToHexString(outBytes));

        } catch (IOException e) {
            // Handle file reading errors by printing the error message
            System.err.println(e.getMessage());
        }
    }


    /**
     * Computes a MAC (Message Authentication Code) from user input using a passphrase.
     * @author An Ho
     * @param byteArrayString The byte array string provided by the user.
     * @param pw The passphrase provided by the user.
     */
    private static void computeMACFromUserInput(String byteArrayString, String pw) {
        // Convert the byte array string to a byte array
        byte[] byteArray = readByteArrayFromString(byteArrayString);

        // Print the user passphrase input
        System.out.println("User passphrase input: " + pw);

        // Compute the MAC using the Keccak algorithm
        // Parameters: passphrase, input data byte array, output length (512 bits), customization string ("D")
        byte[] outBytes = Keccak.KMACXOF256(pw, byteArray, 512, "D");

        // Print the MAC output in hexadecimal format
        System.out.println("Hashed Output:");
        System.out.println(byteArrayToHexString(outBytes) + "\n");
    }


    /**
     * Computes a MAC (Message Authentication Code) from data read from a file using a passphrase.
     * @author An Ho
     * @param pw The passphrase provided by the user.
     * @param filePath The path of the file containing data for MAC computation.
     */
    private static void computeMACFromFile(String pw, String filePath) {
        try {
            // Read the byte array from the specified file
            byte[] byteArray = readByteArrayFromFile(filePath);
            
            // Print the byte array read from the file in hexadecimal format
            System.out.println("Byte array read from file: \n" + byteArrayToHexString(byteArray));
            
            // Print the user passphrase input
            System.out.println("User passphrase input: " + pw);

            // Compute the MAC using the Keccak algorithm
            // Parameters: passphrase, input data byte array, output length (512 bits), customization string ("D")
            byte[] outBytes = Keccak.KMACXOF256(pw, byteArray, 512, "D");
            
            // Print the MAC output in hexadecimal format
            System.out.println("Hashed Output:");
            System.out.println(byteArrayToHexString(outBytes));

        } catch (IOException e) {
            // Handle file reading errors by printing the error message
            System.err.println("Error reading file: Please make sure that data is stored in the right format.");
        }
    }


    /**
     * Encrypts a given data file symmetrically under a given passphrase
     * and stores the cryptogram in an encrypted file.
     * Ref NIST Special Publication 800-185.
     * @author An Ho
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

    
    
    
    /**
     * Decrypts data from a file using the provided passphrase.
     * @author Hieu Doan
     * @param pw The passphrase used for decryption.
     * @param filePath The path of the file containing the encrypted data.
     */
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
     * @param filePath The path of the file to read from.
     * @return The content of the file as a single string, or null if an error occurs.
     */
    private static String readStringFromFile(String filePath) {
        // StringBuilder to store the content of the file
        StringBuilder contentBuilder = new StringBuilder();
        try {
            // Create a File object with the specified file path
            File file = new File(filePath);
            
            // Create a BufferedReader to read from the file
            BufferedReader reader = new BufferedReader(new FileReader(file));
            
            // Read each line from the file and append it to the StringBuilder
            String line;
            while ((line = reader.readLine()) != null) {
                contentBuilder.append(line).append(System.lineSeparator());
            }
            
            // Close the reader
            reader.close();
        } catch (IOException e) {
            // Handle file reading errors by printing the error message
            System.err.println("Error reading file: Please make sure that data is stored in the right format.");
            return null; // Return null if an error occurs
        }
        
        // Return the content of the file as a single string
        return contentBuilder.toString();
    }
    /**
     * Reads a byte array from a file specified by the given file path.
     *
     * @param filePath The path of the file to read from.
     * @return The byte array read from the file.
     * @throws IOException If an I/O error occurs while reading the file.
     */
    private static byte[] readByteArrayFromFile(String filePath) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            // Read the first line from the file
            String line = reader.readLine();
            
            // Check if the line is empty or null
            if (line == null || line.trim().isEmpty()) {
                // Return an empty byte array if the line is empty or null
                return new byte[0];
            }
            
            // Split the line into hexadecimal values
            String[] hexValues = line.trim().split("\\s+");
            
            // Create a byte array to store the converted hexadecimal values
            byte[] byteArray = new byte[hexValues.length];
            
            // Convert each hexadecimal string to a byte and store it in the byte array
            for (int i = 0; i < hexValues.length; i++) {
                byteArray[i] = (byte) Integer.parseInt(hexValues[i], 16);
            }
            
            // Return the byte array read from the file
            return byteArray;
        }
    }

    /**
     * Writes the given byte array to a file named "encryptedFile.txt".
     * @author An Ho
     * @param byteArray The byte array to be written to the file.
     * @throws IOException If an I/O error occurs while writing to the file.
     */
    private static void writeToFile(String byteArray) throws IOException {
        // Get the current directory path
        String currentDir = System.getProperty("user.dir");

        // Write the byte array to the file named "encryptedFile.txt" in the current directory
        try (FileWriter writer = new FileWriter(currentDir + "/encryptedFile.txt")) {
            writer.write(byteArray);
        }
    }

    /**
     *
     * Parses a string containing hexadecimal values separated by whitespace
     * and converts it into a byte array.
     * @author An Ho
     * @param s The string containing hexadecimal values.
     * @return The byte array representing the hexadecimal values.
     */
    private static byte[] readByteArrayFromString(String s) {
        // Split the input string by whitespace to get individual hexadecimal values
        String[] hexValues = s.split("\\s+");

        // Create a byte array to store the parsed hexadecimal values
        byte[] byteArray = new byte[hexValues.length];
        if (s.isEmpty()) return new byte[0];;
        // Iterate through each hexadecimal value
        for (int i = 0; i < hexValues.length; i++) {
            // Parse the hexadecimal string and convert it to a byte
            byteArray[i] = (byte) Integer.parseInt(hexValues[i], 16);
        }

        // Return the byte array
        return byteArray;
    }
}
