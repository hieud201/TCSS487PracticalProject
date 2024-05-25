/**
 * @author Tin Phu, Hieu Doan, An Ho
 */

import java.io.*;
import java.math.BigInteger;
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

    private static int ZyByteArrayLength;


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


        /* TEST ENCRYPTION & DECRYPTION */
        byte[] k_temp = new byte[448/8];
        Main.random.nextBytes(k_temp);
        BigInteger k = new BigInteger(k_temp);
        k = (BigInteger.valueOf(4)).multiply(k).mod(EllipticCurve.R); // k <- 4k mod r
        GoldilocksPoint W = V.multByScalar(k); // W = k*V
        GoldilocksPoint Z = EllipticCurve.G.multByScalar(k); // Z = k*G
        // (ke || ka) <- KMACXOF256(Wx, “”, 2×448, “PK”)
        byte[] keka = Keccak.KMACXOF256(W.x.toByteArray(), "".getBytes(), 2*448, "PK");
        int halfLength = keka.length / 2;
        byte[] ke = Arrays.copyOfRange(keka, 0, halfLength);
        byte[] ka = Arrays.copyOfRange(keka, halfLength, keka.length);
        // c <- KMACXOF256(ke, “”, |m|, “PKE”) XOR m
        byte[] c = Keccak.KMACXOF256(ke, "".getBytes(), (m.length * 8), "PKE");
        c =  Keccak.xorBytes(c, m);
        // t <- KMACXOF256(ka, m, 448, “SKA”)
        byte[] t = Keccak.KMACXOF256(ka, m, 448, "PKA");
        byte[] previousCryptogram =  Keccak.concatByteArrays(Keccak.concatByteArrays(Z.y.toByteArray(), c), t);
        ZyByteArrayLength = Z.y.toByteArray().length;
        System.out.println("Cryptogram:\n" + byteArrayToHexString(previousCryptogram));

        //extracts Z'
        byte[] ZBytes = Arrays.copyOfRange(previousCryptogram, 0, ZyByteArrayLength);
        GoldilocksPoint ZPrime = new GoldilocksPoint(false, new BigInteger(ZBytes));
        //extract t'
        byte[] tPrime = Arrays.copyOfRange(previousCryptogram, previousCryptogram.length - (448/8), previousCryptogram.length);
        //extract c', know that c' bytes = previousCryptogram.length - (Z'.length + t'.length)
        byte[] cPrime = Arrays.copyOfRange(previousCryptogram, ZBytes.length, previousCryptogram.length - tPrime.length);
        GoldilocksPoint Wprime = ZPrime.multByScalar(s); // W = s*Z
        System.out.println("Wprime = W: " + Wprime.isEquals(W));
        // (ke || ka)' <- KMACXOF256(W'x, “”, 2×448, “PK”)
        byte[] kekaPrime = Keccak.KMACXOF256(Wprime.x.toByteArray(), "".getBytes(), 2*448, "PK");
        byte[] kePrime = Arrays.copyOfRange(kekaPrime,0, kekaPrime.length/2);
        byte[] kaPrime = Arrays.copyOfRange(kekaPrime,kekaPrime.length/2, kekaPrime.length);
        // m' <- KMACXOF256(ke', “”, |c|, “PKE”) XOR c'
        byte[] mPrime = Keccak.KMACXOF256(kePrime, "".getBytes(), (cPrime.length * 8), "PKE");
        mPrime = Keccak.xorBytes(mPrime, cPrime);
        // t’' <- KMACXOF256(ka', m', 448, “PKA”)
        byte[] tPrimePrime = Keccak.KMACXOF256(kaPrime, mPrime, 448, "PKA");
        // printing the successful decryption when t' = t
        if (Arrays.equals(tPrime, tPrimePrime)) {
            System.out.println("Decrypted output: " + Arrays.toString(mPrime));
        } else {
            System.out.println("Fail to decrypt!");
        }




            case "gen" -> {
                if (!handler.hasTag("pw")) {
                    System.out.println("Missing -pw");
                } else {
                    generateAsymmetricKey(handler.getValue("pw"));
                }
            }

            case "sign" -> {
                if (handler.hasTag("file")) {
                    if (!handler.hasTag("pw")) {
                        System.out.println("Missing -pw");
                    } else if (handler.getValue("file").isEmpty()) {
                        String currentDir = System.getProperty("user.dir");
                        String filePath = currentDir + File.separator + "dataInput.txt";
                        System.out.println("Readding from: " + filePath);
                        byte[] m = readByteArrayFromFile(filePath);
                        String pw = handler.getValue("pw");
                        signByteArrayAndWriteSignatureKey(m, pw);
                    } else {
                        System.out.println("Readding from: " + handler.getValue("file"));
                        String filePath = handler.getValue("file");
                        System.out.println("Readding from: " + filePath);
                        byte[] m = readByteArrayFromFile(filePath);
                        String pw = handler.getValue("pw");
                        signByteArrayAndWriteSignatureKey(m, pw);
                    }
                } else {
                    if (!handler.hasTag("pw")) {
                        System.out.println("Missing -pw");
                    } else if (!handler.hasTag("code")) {
                        System.out.println("Missing -code");
                    } else {
                        byte[] m = readByteArrayFromString(handler.getValue("code"));
                        String pw = handler.getValue("pw");
                        signByteArrayAndWriteSignatureKey(m, pw);
                    }
                }
            }
            case "verify" -> {
                //read Signature from  the default file location ./signatureKey.txt
                String currentDir = System.getProperty("user.dir");
                String signatureFilePath = currentDir + File.separator + "signatureKey.txt";
                byte[] hz = readByteArrayFromFile(signatureFilePath);
                System.out.println("Reading Signature from " + signatureFilePath);
                //geting a given data
                byte[] m = {};
                //Bonus: from user input
                if(handler.hasTag("mCode")){
                    m = readByteArrayFromString(handler.getValue("mCode"));
                    System.out.println("Reading data from user input ");
                }else{
                    //From file path.
                    if(handler.hasTag("mFile")){
                        String mFilePath =  handler.getValue("mFile");
                        m = readByteArrayFromFile(mFilePath);
                        System.out.println("Reading data from mFilePath ");
                    }else{
                        System.out.println("Missing -mFile");
                        break;
                    }

                }

                byte[] byteArrayPublicKey = {};
                ////Bonus: from user input
                if(handler.hasTag("pubKey")){
                    byteArrayPublicKey = readByteArrayFromString(handler.getValue("pubKey"));
                }else {
                    //From file path.
                    if(handler.hasTag("pubKeyFile")){
                        //Using default public key file path
                        // which is ./generatedPublicKey.txt
                        if(handler.getValue("pubKeyFile").isEmpty()){
                            String pubKeyFilePath = currentDir + File.separator + "generatedPublicKey.txt";
                            byteArrayPublicKey = readByteArrayFromFile(pubKeyFilePath);
                            System.out.println("Reading public key from" + pubKeyFilePath);

                        }else{
                            String pubKeyFilePath =  handler.getValue("pubKeyFile");
                            byteArrayPublicKey = readByteArrayFromFile(pubKeyFilePath);
                            System.out.println("Reading public key from" + pubKeyFilePath);

                        }
                    }else{
                        System.out.println("Missing -pubKeyFile, which could be empty (using default pubKey file path)");
                        break;
                    }
                }
                //turn byteArrayPublicKey in to Goldilocks Point
                GoldilocksPoint publicKeyPoint = EllipticCurve.getGoldPointFromPublicKey(byteArrayPublicKey);
                System.out.println("===========================================");
                System.out.println("Verified: " + EllipticCurve.signatureVerify(hz,m,publicKeyPoint));
            }

            default -> System.out.println("Invalid command.");
        }
    }

    /**
     *  sign a  Byte Array And Write SignatureKey
     *  the pathfile ./signatureKey.txt
     * @Author Tin Phu
     * @param m
     * @param pw
     * @throws IOException
     */
    private static void signByteArrayAndWriteSignatureKey(byte[] m, String pw) throws IOException {
        //generate AsymmetricKey
        //the main purpose is to write the current correct Public Key
        generateAsymmetricKey(pw);

        //Sign
        byte[] conCatOfHZ = EllipticCurve.signatureGenerator(m, pw);
        //write signature to a ./signatureKey.txt file.
        writeStringToFile(byteArrayToHexString(conCatOfHZ), "signatureKey.txt");
        System.out.println("===========================================");
        System.out.println(byteArrayToHexString(conCatOfHZ));

    }

    /**
     * Write public key to generatedPublic.txt and
     * encrypted private key generatedPrivateKey.txt
     * Generating a (Schnorr/DHIES) key pair from passphrase pw:
     * ▪ s  KMACXOF256(pw, “”, 448, “SK”); s  4s (mod r)
     * ▪ V  s*G
     * ▪ key pair: (s, V)
     * @param pw
     */
    private static void generateAsymmetricKey(String pw){
        byte[][] thePair = EllipticCurve.generateAsymmetricKey(pw);
        byte[] publicKey = thePair[1];
        byte[] privateKey = thePair[0];
  //      System.out.println(Arrays.toString(publicKey));
//        System.out.println(publicKey.length);

        try {
            writeStringToFile(byteArrayToHexString(publicKey), "generatedPublicKey.txt");
            System.out.println("Wrote Hexadecimal of Public Key to ./generatedPublicKey.txt ");
            //Bonus points:
            //Encrypt the private key from that pair under the given password
            writeStringToFile(byteArrayToHexString(encryptByteArrayKey(pw,privateKey)), "generatedPrivateKey.txt");
            System.out.println("Wrote Hexadecimal of Encrypted Private Key to ./generatedPrivateKey.txt ");

        } catch (IOException e) {
            throw new RuntimeException("Fail to Write pub/pri key to files: " + e);
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


        Main.random.nextBytes(z); // z <- Random(512)

        // (ke || ka) <- KMACXOF256(z || pw, “”, 1024, “S”)
        byte[] keka = Keccak.KMACXOF256(new String(Keccak.concatByteArrays(z, pw.getBytes())), "".getBytes(), 1024, "S");
        //System.out.println(keka.length);
        int halfLength = keka.length / 2;
        byte[] ke = Arrays.copyOfRange(keka, 0, halfLength);
        byte[] ka = Arrays.copyOfRange(keka, halfLength, keka.length);

        // c <- KMACXOF256(ke, “”, |m|, “SKE”) XOR m
        byte[] c = Keccak.KMACXOF256(new String(ke), "".getBytes(), (byteArray.length * 8), "SKE");
        c =  Keccak.xorBytes(c, byteArray);


        // t <- KMACXOF256(ka, m, 512, “SKA”)
        byte[] t = Keccak.KMACXOF256(new String(ka), byteArray, 512, "SKA");
        // writing the cryptogram (z,c,t) to a file and printing it
        byte[] previousCryptogram =  Keccak.concatByteArrays(Keccak.concatByteArrays(z, c), t);
        writeStringToFile(byteArrayToHexString(previousCryptogram), "encryptedFile.txt");
        System.out.println("Cryptogram:\n" + byteArrayToHexString(previousCryptogram));

    }

    /**
     * Encrypts a given data file symmetrically under a given passphrase
     * and stores the cryptogram in a file as z || c || t.
     * Ref Programming Project Part 1 document.
     *
     * @author Hieu Doan
     * @throws IOException if the file can't be written to
     */
    private static byte[] encryptByteArrayKey(String pw, byte[] byteArray) throws IOException {
        byte[] z = new byte[64];
        Main.random.nextBytes(z); // z <- Random(512)

        // (ke || ka) <- KMACXOF256(z || pw, “”, 1024, “S”)
        byte[] keka = Keccak.KMACXOF256(new String(Keccak.concatByteArrays(z, pw.getBytes())), "".getBytes(), 1024, "S");
        //System.out.println(keka.length);
        int halfLength = keka.length / 2;
        byte[] ke = Arrays.copyOfRange(keka, 0, halfLength);
        byte[] ka = Arrays.copyOfRange(keka, halfLength, keka.length);

        // c <- KMACXOF256(ke, “”, |m|, “SKE”) XOR m
        byte[] c = Keccak.KMACXOF256(new String(ke), "".getBytes(), (byteArray.length * 8), "SKE");
        c =  Keccak.xorBytes(c, byteArray);


        // t <- KMACXOF256(ka, m, 512, “SKA”)
        byte[] t = Keccak.KMACXOF256(new String(ka), byteArray, 512, "SKA");
        // writing the cryptogram (z,c,t) to a file and printing it
        return Keccak.concatByteArrays(Keccak.concatByteArrays(z, c), t);
    }


    /**
     * Encrypts a byte array under a Schnorr/DHIES given public key file,
     * stores the cryptogram in a file as z || c || t,
     * and returns that cryptogram as bytes. <br>
     * Ref Programming Project Part 2 document.
     * @author Hieu Doan
     * @param byteArray the message byte array
     * @return the cryptogram in the form of as z || c || t.
     * @throws IOException if the file can't be written to
     */
    private static byte[] encryptByteArrayUnderDHIES(byte[] byteArray) throws IOException {
        byte[] k_temp = new byte[448/8];
        Main.random.nextBytes(k_temp); // k <- Random(448)
        BigInteger k = new BigInteger(k_temp);
        k = (BigInteger.valueOf(4)).multiply(k).mod(EllipticCurve.R); // k <- 4k mod r

        // converting the public key bytes to a GoldilocksPoint
        byte[] publicKeyByte = readByteArrayFromFile("generatedPublicKey.txt");
        GoldilocksPoint V = EllipticCurve.getPointFromPublicKey(publicKeyByte);

        GoldilocksPoint W = V.multByScalar(k); // W = k*V
        GoldilocksPoint Z = EllipticCurve.G.multByScalar(k); // Z = k*G

        // (ke || ka) <- KMACXOF256(Wx, “”, 2×448, “PK”)
        byte[] keka = Keccak.KMACXOF256(W.x.toByteArray(), "".getBytes(), 2*448, "PK");
        int halfLength = keka.length / 2;
        byte[] ke = Arrays.copyOfRange(keka, 0, halfLength);
        byte[] ka = Arrays.copyOfRange(keka, halfLength, keka.length);

        // c <- KMACXOF256(ke, “”, |m|, “PKE”) XOR m
        byte[] c = Keccak.KMACXOF256(ke, "".getBytes(), (byteArray.length * 8), "PKE");
        c =  Keccak.xorBytes(c, byteArray);

        // t <- KMACXOF256(ka, m, 448, “SKA”)
        byte[] t = Keccak.KMACXOF256(ka, byteArray, 448, "PKA");

        byte[] previousCryptogram =  Keccak.concatByteArrays(Keccak.concatByteArrays(Z.y.toByteArray(), c), t);
        ZyByteArrayLength = Z.y.toByteArray().length;
        // I save the cryptogram under a new file for testing purpose.
        // Let me know if this is not needed for our final work.
        writeStringToFile(byteArrayToHexString(previousCryptogram), "src/encryptedFileUnderDHIES.txt");
        System.out.println("Cryptogram:\n" + byteArrayToHexString(previousCryptogram));

        return previousCryptogram;
    }



    /**
     * Decrypts data from a file using the provided passphrase.
     * Ref Programming Project Part 1 document.
     *
     * @author Hieu Doan
     * @param pw The passphrase used for decryption.
     * @param filePath The path of the file containing the encrypted data.
     * @return The decrypted data as bytes.
     */
    private static byte[] decryptFromFile(String pw, String filePath) {
        byte[] decryptedByteArray = null;

        try {
            // parsing the necessary components of the cryptogram
            byte[] inputByteArray = readByteArrayFromFile(filePath);

            //extract z
            byte[] z = Arrays.copyOfRange(inputByteArray,0, 64);
            //int ctLength = (inputByteArray.length - z.length)/2;

            //extract t
            byte[] t = Arrays.copyOfRange(inputByteArray, inputByteArray.length - 64, inputByteArray.length );

            //extract c, know that c bytes = inputByteArray.length - (z.length + t.length)
            // z.length and t.length are always a constant of 64 bytes.
            // 64bytes||c.byte||64bytes
            byte[] c = Arrays.copyOfRange(inputByteArray, z.length  , inputByteArray.length - 64);

            // (ke || ka) <- KMACXOF256(z || pw, “”, 1024, “S”)
            byte[] keka = Keccak.KMACXOF256(new String(Keccak.concatByteArrays(z, pw.getBytes())), "".getBytes(), 1024, "S");
            byte[] ke = Arrays.copyOfRange(keka,0, keka.length/2);
            byte[] ka = Arrays.copyOfRange(keka,keka.length/2, keka.length);

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
                System.out.println("Fail to decrypt!");
            }
        } catch (IOException e) {
            System.err.println("Error reading file: " + e.getMessage());
        }

        return decryptedByteArray;
    }

    /**
     * Decrypts data from an elliptic-encrypted file using the provided passphrase,
     * writes the decrypted data to a file and returns it.
     * Ref Programming Project Part 2 document.
     *
     * @author Hieu Doan
     * @param pw The passphrase used for decryption.
     * @param filePath The path of the file containing the elliptic-encrypted data.
     * @return The decrypted data as bytes.
     */
    private static byte[] decryptFromEllipticFile(String pw, String filePath) {
        byte[] decryptedByteArray = null;

        try {
            // extracts the elliptic-encrypted data from the input file
            byte[] inputByteArray = readByteArrayFromFile(filePath);

            // decrypts the encrypted private key file and extracts the private key
            byte[] privateKeyByteArray = decryptFromFile(pw, "generatedPrivateKey.txt");
            BigInteger s = new BigInteger(privateKeyByteArray);

            //extracts Z
            byte[] ZBytes = Arrays.copyOfRange(inputByteArray, 0, ZyByteArrayLength);
            GoldilocksPoint Z = new GoldilocksPoint(false, new BigInteger(ZBytes));

            //extract t
            byte[] t = Arrays.copyOfRange(inputByteArray, inputByteArray.length - (448/8), inputByteArray.length);

            //extract c, know that c bytes = inputByteArray.length - (Z.length + t.length)
            byte[] c = Arrays.copyOfRange(inputByteArray, ZBytes.length, inputByteArray.length - t.length);

            GoldilocksPoint W = Z.multByScalar(s); // W = s*Z

            // (ke || ka) <- KMACXOF256(Wx, “”, 2×448, “PK”)
            byte[] keka = Keccak.KMACXOF256(W.x.toByteArray(), "".getBytes(), 2*448, "PK");
            byte[] ke = Arrays.copyOfRange(keka,0, keka.length/2);
            byte[] ka = Arrays.copyOfRange(keka,keka.length/2, keka.length);

            // m <- KMACXOF256(ke, “”, |c|, “PKE”) XOR c
            byte[] m = Keccak.KMACXOF256(ke, "".getBytes(), (c.length * 8), "PKE");
            m = Keccak.xorBytes(m, c);

            // t’ <- KMACXOF256(ka, m, 448, “PKA”)
            byte[] tPrime = Keccak.KMACXOF256(ka, m, 448, "PKA");

            // printing the successful decryption when t' = t
            if (Arrays.equals(t, tPrime)) {
                decryptedByteArray = m;
                writeStringToFile(byteArrayToHexString(decryptedByteArray), "decryptedFile.txt");
            } else {
                System.out.println("Fail to decrypt!");
            }
        } catch (IOException e) {
            System.err.println("Error reading file: " + e.getMessage());
        }

        return decryptedByteArray;
    }



    /************************************************************
     *                      Helper Methods                      *
     ************************************************************/

    /**
     * Converts the given byte array to a hexadecimal string.
     *
     * @author Tin Phu
     * @param bytes the given byte array
     * @return the hexadecimal string representation of the byte array
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
    private static void writeStringToFile(String byteArray, String fileName) throws IOException {
        // Get the current directory path
        String currentDir = System.getProperty("user.dir");
        String filePath = currentDir + File.separator + fileName;
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
