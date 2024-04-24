import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {

//        byte[] input = {
//                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07,
//                (byte) 0x08, (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C, (byte) 0x0D, (byte) 0x0E, (byte) 0x0F,
//                (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13, (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17,
//                (byte) 0x18, (byte) 0x19, (byte) 0x1A, (byte) 0x1B, (byte) 0x1C, (byte) 0x1D, (byte) 0x1E, (byte) 0x1F,
//                (byte) 0x20, (byte) 0x21, (byte) 0x22, (byte) 0x23, (byte) 0x24, (byte) 0x25, (byte) 0x26, (byte) 0x27,
//                (byte) 0x28, (byte) 0x29, (byte) 0x2A, (byte) 0x2B, (byte) 0x2C, (byte) 0x2D, (byte) 0x2E, (byte) 0x2F,
//                (byte) 0x30, (byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34, (byte) 0x35, (byte) 0x36, (byte) 0x37,
//                (byte) 0x38, (byte) 0x39, (byte) 0x3A, (byte) 0x3B, (byte) 0x3C, (byte) 0x3D, (byte) 0x3E, (byte) 0x3F,
//                (byte) 0x40, (byte) 0x41, (byte) 0x42, (byte) 0x43, (byte) 0x44, (byte) 0x45, (byte) 0x46, (byte) 0x47,
//                (byte) 0x48, (byte) 0x49, (byte) 0x4A, (byte) 0x4B, (byte) 0x4C, (byte) 0x4D, (byte) 0x4E, (byte) 0x4F,
//                (byte) 0x50, (byte) 0x51, (byte) 0x52, (byte) 0x53, (byte) 0x54, (byte) 0x55, (byte) 0x56, (byte) 0x57,
//                (byte) 0x58, (byte) 0x59, (byte) 0x5A, (byte) 0x5B, (byte) 0x5C, (byte) 0x5D, (byte) 0x5E, (byte) 0x5F,
//                (byte) 0x60, (byte) 0x61, (byte) 0x62, (byte) 0x63, (byte) 0x64, (byte) 0x65, (byte) 0x66, (byte) 0x67,
//                (byte) 0x68, (byte) 0x69, (byte) 0x6A, (byte) 0x6B, (byte) 0x6C, (byte) 0x6D, (byte) 0x6E, (byte) 0x6F,
//                (byte) 0x70, (byte) 0x71, (byte) 0x72, (byte) 0x73, (byte) 0x74, (byte) 0x75, (byte) 0x76, (byte) 0x77,
//                (byte) 0x78, (byte) 0x79, (byte) 0x7A, (byte) 0x7B, (byte) 0x7C, (byte) 0x7D, (byte) 0x7E, (byte) 0x7F,
//                (byte) 0x80, (byte) 0x81, (byte) 0x82, (byte) 0x83, (byte) 0x84, (byte) 0x85, (byte) 0x86, (byte) 0x87,
//                (byte) 0x88, (byte) 0x89, (byte) 0x8A, (byte) 0x8B, (byte) 0x8C, (byte) 0x8D, (byte) 0x8E, (byte) 0x8F,
//                (byte) 0x90, (byte) 0x91, (byte) 0x92, (byte) 0x93, (byte) 0x94, (byte) 0x95, (byte) 0x96, (byte) 0x97,
//                (byte) 0x98, (byte) 0x99, (byte) 0x9A, (byte) 0x9B, (byte) 0x9C, (byte) 0x9D, (byte) 0x9E, (byte) 0x9F,
//                (byte) 0xA0, (byte) 0xA1, (byte) 0xA2, (byte) 0xA3, (byte) 0xA4, (byte) 0xA5, (byte) 0xA6, (byte) 0xA7,
//                (byte) 0xA8, (byte) 0xA9, (byte) 0xAA, (byte) 0xAB, (byte) 0xAC, (byte) 0xAD, (byte) 0xAE, (byte) 0xAF,
//                (byte) 0xB0, (byte) 0xB1, (byte) 0xB2, (byte) 0xB3, (byte) 0xB4, (byte) 0xB5, (byte) 0xB6, (byte) 0xB7,
//                (byte) 0xB8, (byte) 0xB9, (byte) 0xBA, (byte) 0xBB, (byte) 0xBC, (byte) 0xBD, (byte) 0xBE, (byte) 0xBF,
//                (byte) 0xC0, (byte) 0xC1, (byte) 0xC2, (byte) 0xC3, (byte) 0xC4, (byte) 0xC5, (byte) 0xC6, (byte) 0xC7
//        };
//
//        byte[] input1 = {
//
//        };
//
//        byte[] key = {
//                (byte) 0x40, (byte) 0x41, (byte) 0x42, (byte) 0x43,
//                (byte) 0x44, (byte) 0x45, (byte) 0x46, (byte) 0x47,
//                (byte) 0x48, (byte) 0x49, (byte) 0x4A, (byte) 0x4B,
//                (byte) 0x4C, (byte) 0x4D, (byte) 0x4E, (byte) 0x4F,
//                (byte) 0x50, (byte) 0x51, (byte) 0x52, (byte) 0x53,
//                (byte) 0x54, (byte) 0x55, (byte) 0x56, (byte) 0x57,
//                (byte) 0x58, (byte) 0x59, (byte) 0x5A, (byte) 0x5B,
//                (byte) 0x5C, (byte) 0x5D, (byte) 0x5E, (byte) 0x5F
//        };
////        byte[] outBytes = Keccak.cSHAKE256(input, 512, "", "Email Signature");
////        System.out.println(byteArrayToHexString(outBytes));
//
//
//        byte[] outBytes3 = Keccak.KMACXOF256(key, input, 512, "My Tagged Application");
//        System.out.println(byteArrayToHexString(outBytes3));
//        //expected output: D5 BE 73 1C 95 4E D7 73 28 46 BB 59 DB E3 A8 E3
//        //0F 83 E7 7A 4B FF 44 59 F2 F1 C2 B4 EC EB B8 CE
//        //67 BA 01 C6 2E 8A B8 57 8D 2D 49 9B D1 BB 27 67
//        //68 78 11 90 02 0A 30 6A 97 DE 28 1D CC 30 30 5D
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
                    computeHashOption();
                    break;
                case 2:
                    computeMACOption();
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

    private static void computeHashOption() {
        Scanner scanner = new Scanner(System.in);
        System.out.println("\nChoose an option:");
        System.out.println("1. Compute a plain cryptographic hash from user input");
        System.out.println("2. Compute a plain cryptographic hash from file");
        System.out.print("Enter your choice: ");
        int choice = scanner.nextInt();
        scanner.nextLine(); // Consume newline

        switch (choice) {
            case 1:
                computeHashFromInput();
                break;
            case 2:
                computeFileHash();
                break;
            default:
                System.out.println("Invalid choice. Please try again.");
        }
        System.out.println("===============================================");
    }

    private static void computeHashFromInput() {


        byte[] byteArrayInputKey = readByteArray("Enter Key as a byte array in hexadecimal format (e.g., 01 A8 02): ");
        if (byteArrayInputKey != null) {
            System.out.print("Key Byte array input: ");
            for (byte b : byteArrayInputKey) {
                System.out.print(String.format("%02X ", b));
            }
            System.out.println("");
        }
        byte[] byteArrayInputData = readByteArray("Enter Data as a byte array in hexadecimal format (e.g., 01 A8 02): ");
        if (byteArrayInputData != null) {
            System.out.print("Data Byte array input: ");
            for (byte b : byteArrayInputData) {
                System.out.print(String.format("%02X ", b));
            }
            System.out.println("");
        }

        String userInputS = readStringInput("Enter S  (as a character string): ");
        System.out.println("User S input: " + userInputS);
        System.out.println("Hashing...");
        System.out.println("Cryptographic Hash Output:");

        byte[] outBytes3 = Keccak.KMACXOF256(byteArrayInputKey, byteArrayInputData, 512, userInputS);
        System.out.println(byteArrayToHexString(outBytes3));

        System.out.println("");



    }

    private static void computeFileHash() {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter the path to the file: ");
        String filePath = scanner.nextLine();

//        try {
//            FileInputStream fis = new FileInputStream(filePath);
//            byte[] buffer = new byte[1024];
//            MessageDigest md = MessageDigest.getInstance("SHA-256");
//
//            int bytesRead;
//            while ((bytesRead = fis.read(buffer)) != -1) {
//                md.update(buffer, 0, bytesRead);
//            }
//
//            byte[] hashBytes = md.digest();
//            String hash = Hex.toHexString(hashBytes);
//            System.out.println("Hash of the file: " + hash);
//
//            fis.close();
//        } catch (IOException | NoSuchAlgorithmException e) {
//            e.printStackTrace();
//        }
    }

    private static void computeMACOption() {
        Scanner scanner = new Scanner(System.in);
        System.out.println("\nChoose an option:");
        System.out.println("1. Compute MAC from user input");
        System.out.println("2. Compute MAC from file");
        System.out.print("Enter your choice: ");
        int choice = scanner.nextInt();
        scanner.nextLine(); // Consume newline

        switch (choice) {
            case 1:
                computeMACFromInput();
                break;
            case 2:
                computeFileMAC();
                break;
            default:
                System.out.println("Invalid choice. Please try again.");
        }
        System.out.println("===============================================");
    }

    private static void computeMACFromInput() {
        // Similar to computeHashFromInput(), but for MAC computation
        // You need to implement this method
    }

    private static void computeFileMAC() {
        // Similar to computeFileHash(), but for MAC computation
        // You need to implement this method
    }

    private static void encryptFile() {
        // Implement symmetric encryption of a file
    }

    private static void decryptFile() {
        // Implement symmetric decryption of a file
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

}