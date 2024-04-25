import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {

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
                case 1:
                    computeplainHashOption();
                    break;
                case 2:
                    computeAuthMACOption();
                    break;
                case 3:
                    encryptFile();
                    break;
                case 4:
                    decryptFile();
                    break;
                case 5:
                    System.out.println("Exiting CryptoApp. Goodbye!");
                    System.exit(0);
                    break;
                default:
                    System.out.println("Invalid choice. Please try again.");
            }
            System.out.println("===============================================");
        }

    }

    private static void computeplainHashOption() {
        Scanner scanner = new Scanner(System.in);
        System.out.println("\nChoose an option:");
        System.out.println("1. Compute a plain cryptographic hash from user input");
        System.out.println("2. Compute a plain cryptographic hash from file (src/dataInput.txt)");
        System.out.print("Enter your choice: ");
        int choice = scanner.nextInt();
        scanner.nextLine(); // Consume newline

        switch (choice) {
            case 1:
                computePlainHashFromInput();
                break;
            case 2:
                computePlainHashFromFile();
                break;
            default:
                System.out.println("Invalid choice. Please try again.");
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
            case 1:
                computeAuthMACFromInput();
                break;
            case 2:
                computeAuthMACFromFile();
                break;
            default:
                System.out.println("Invalid choice. Please try again.");
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
        //Use must create a new Xor for Byte[], the one that we have is for States only long[] (Tin Phu)
//        String filePath = "src/dataInput.txt";
//        try {
//            byte[] byteArray = readByteArrayFromFile(filePath);
//            System.out.println("Byte array read from file: \n" + byteArrayToHexString(byteArray));

//        } catch (IOException e) {
//            System.err.println("Error reading file: " + e.getMessage());
//        }
    }

    private static void decryptFile() {
        // Implement symmetric encryption of a file
        //Use must create a new Xor for Byte[], the one that we have is for States only long[] (Tin Phu)
//        String filePath = "src/dataInput.txt";
//        try {
//            byte[] byteArray = readByteArrayFromFile(filePath);
//            System.out.println("Byte array read from file: \n" + byteArrayToHexString(byteArray));

//        } catch (IOException e) {
//            System.err.println("Error reading file: " + e.getMessage());
//        }
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

    public static byte[] readByteArrayFromFile(String filePath) throws IOException {
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new FileReader(filePath));
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
        } finally {
            if (reader != null) {
                reader.close();
            }
        }
    }

}