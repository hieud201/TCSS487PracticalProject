import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class EllipticCurve {
    private static final String ALLOWED_CHARACTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+";

    public static void main(String[] args) throws Exception {
        String pw = "IU3x1+123123123123s%"; //V3CY!RZ4aNL2*=x // 8XZq^o#3SCkx //(yI5##B&h6%Fx //PPnxIEN(K^0wLnh$L0x
        byte[] m = {
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05
        };
        //Manually get Public Key
//        BigInteger s = new BigInteger(Keccak.KMACXOF256(pw, "".getBytes(), 448, "SK"));
//        s = s.multiply(BigInteger.valueOf(4)).mod(EllipticCurve.R);
//        GoldilocksPoint a = EllipticCurve.G.multByScalar(s);
//        byte[] z_x = a.x.toByteArray();
//        var x_lsb = (z_x[z_x.length - 1] & 1) == 1;
//
//        GoldilocksPoint V = new GoldilocksPoint(x_lsb,a.y);
//        byte[] hz = signatureGenerator(m,pw);
//
//        System.out.println(signatureVerify(hz,m,V));
//
//        byte[][] result =   generateAsymmetricKey(pw);
//
//        System.out.println(getGoldPointFromPublicKey(result[1]));
//
         int numberOfPasswords = 10;
//////
//////        // Generate and print 100 passwords
        for (int i = 0; i < numberOfPasswords; i++) {

            String pww = generatePassword();
            System.out.println( "Passwords: " + pww);
            byte[][] result1 =   generateAsymmetricKey(pww);

            System.out.println( "public Point In:  " + getGoldPointFromPublicKey(result1[1]));
            System.out.println( "========================================= ");
        }

    }


    private static String generatePassword() {
        // Define password length (e.g., between 8 and 20 characters)
        int minLength = 8;
        int maxLength = 20;

        // Generate a random password length between minLength and maxLength
        int passwordLength = new SecureRandom().nextInt(maxLength - minLength + 1) + minLength;

        // Generate the password
        StringBuilder password = new StringBuilder();
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < passwordLength*2; i++) {
            int randomIndex = random.nextInt(ALLOWED_CHARACTERS.length());
            char randomChar = ALLOWED_CHARACTERS.charAt(randomIndex);
            password.append(randomChar);
        }
        return password.toString();
    }

    private static final BigInteger G_y = GoldilocksPoint.PRIME_P.subtract(BigInteger.valueOf(3));
    public static final GoldilocksPoint G = new GoldilocksPoint(
            //BigInteger.valueOf(-3).mod(PRIME_P),
            // ± √((1 − 𝑦^2)/(1 + 39081𝑦^2)) mod 𝑝.
            false,
            G_y
    );

    final static BigInteger R = (BigInteger.TWO).pow(446).subtract(
            new BigInteger("13818066809895115352007386748515426880336692474882178609894547503885"));
    /**
     * result[0] is private key
     * result[1] is public key
     */
    public static byte[][]  generateAsymmetricKey(String pw){
        byte[][] result = new byte[2][];
        // s <- KMACXOF256(pw, "", 448, "SK")
        byte[] s = Keccak.KMACXOF256(pw, "".getBytes(), 448, "SK");
        BigInteger privateKey = new BigInteger(s);

        //The number of points 𝑛 on any Edwards curve is always a multiple of 4, and for
        //Ed448-Goldilocks that number is 𝑛 ≔ 4𝑟
        privateKey = (BigInteger.valueOf(4)).multiply(privateKey).mod(R);
        result[0] = privateKey.toByteArray();
        GoldilocksPoint publicKey = G.multByScalar(privateKey);
     //   System.out.println("public Point Out: " + publicKey.toString());
        byte[] hexXYPublicKey = Keccak.concatByteArrays(Keccak.encode_string(publicKey.x.toByteArray()),
                Keccak.encode_string(publicKey.y.toByteArray()));
        result[1] = hexXYPublicKey;
     //   System.out.println("hexXYPublicKey Out: " + Arrays.toString(hexXYPublicKey));
        return result;

    }

    public static GoldilocksPoint getGoldPointFromPublicKey(byte[] hexXYPublicKeyWithLength){
        int ptr = 0;
        List<byte[]> lst = new ArrayList<>();
        while (ptr < hexXYPublicKeyWithLength.length) {
            int len = hexXYPublicKeyWithLength[ptr] & 0xFF;
            int arrLen = bytesToInt(Arrays.copyOfRange(hexXYPublicKeyWithLength, ptr + 1, ptr + 1 + len)) / 8;
            ptr += 1 + len;
            byte[] arr = Arrays.copyOfRange(hexXYPublicKeyWithLength, ptr, ptr + arrLen);
            ptr += arrLen;
            lst.add(arr);
        }

        if (lst.size() < 2) {
            throw new IllegalArgumentException("Insufficient data for constructing GoldilocksPoint");
        }


        return new GoldilocksPoint( new BigInteger(lst.get(0)),  new BigInteger(lst.get(1)));
    }
    public static int bytesToInt(byte[] bytes) {
        int value = 0;
        for(byte b : bytes) {
            value = (value << 8) + (b & 0xFF);
        }
        return value;
    }


    public static GoldilocksPoint getPointFromPublicKey(byte[] bytesKey){
        return new GoldilocksPoint(false, new BigInteger(bytesKey));
    }

    /**
     * Generates a digital signature from the message and private key.
     * @param m The message to be signed.
     * @param pw The private key.
     * @return A byte array containing the generated digital signature.
     * @author An Ho, Tin phu
     */
    public static byte[] signatureGenerator(byte[] m,String pw){
        BigInteger s = new BigInteger(Keccak.KMACXOF256(pw, "".getBytes(), 448, "SK"));

        s = s.multiply(BigInteger.valueOf(4)).mod(EllipticCurve.R);
        GoldilocksPoint a = EllipticCurve.G.multByScalar(s);
        BigInteger k = new BigInteger(Keccak.KMACXOF256(s.toByteArray(),m, 448, "N"));
        k = k.multiply(BigInteger.valueOf(4)).mod(EllipticCurve.R);;

        GoldilocksPoint U = EllipticCurve.G.multByScalar(k);

        BigInteger h = new BigInteger(Keccak.KMACXOF256(U.x.toByteArray(), m, 448, "T")).mod(GoldilocksPoint.r);
        BigInteger z = k.subtract(h.multiply(s).mod(EllipticCurve.R)).mod(GoldilocksPoint.r);
        return Keccak.concatByteArrays(h.toByteArray(), z.toByteArray());
    }

    /**
     * Verify a digital signature without receiving the private key used to sign.
     * @param hz The digital signature as provided.
     * @param m The data signed by digital signature.
     * @param V A point on E521 generated using the private key.
     * @return true if the signature can be verified; false otherwise.
     * @author An Ho
     */
    public static boolean signatureVerify(byte[] hz, byte[] m, GoldilocksPoint V) {
        byte[] h = new byte[56];
        byte[] z = new byte[hz.length -56];
        for (int i = 0; i < h.length; i++) {
            h[i] = hz[i];
        }
        for (int i = 0; i < z.length; i++) {
            z[i] = hz[56+i];
        }
        var U = EllipticCurve.G.multByScalar(new BigInteger(z)).add(V.multByScalar(new BigInteger(h)));
        var L = 448;
        // accept if, and only if, KMACXOF256(Ux, m, 448, "T") = h
        var h_prime = new BigInteger(Keccak.KMACXOF256(U.x.toByteArray(), m, L, "T")).mod(EllipticCurve.R);
        return h_prime.equals(new BigInteger(h));
    }


}
