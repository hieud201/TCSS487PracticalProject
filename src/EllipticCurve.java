import java.math.BigInteger;

public class EllipticCurve {

    public static void main(String[] args) {
        String pw = "phuhuut123123123in";
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
                (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05
        };
        //Manually get Public Key
        BigInteger s = new BigInteger(Keccak.KMACXOF256(pw, "".getBytes(), 448, "SK"));
        s = s.multiply(BigInteger.valueOf(4)).mod(EllipticCurve.R);
        GoldilocksPoint a = EllipticCurve.G.multByScalar(s);

        byte[] hz = signatureGenerator(m,pw);

        System.out.println(signatureVerify(hz,m,a));


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
        System.out.println("privateKey From Git:" + privateKey);

        //The number of points 𝑛 on any Edwards curve is always a multiple of 4, and for
        //Ed448-Goldilocks that number is 𝑛 ≔ 4𝑟
        privateKey = (BigInteger.valueOf(4)).multiply(privateKey).mod(R);
        result[0] = privateKey.toByteArray();
        GoldilocksPoint publicKey = G.multByScalar(privateKey);
        System.out.println("publicKey From Git:" + publicKey.toString() );

        //taking GoldilocksPoint.y as hexPublicKey
        // because we can always find x with y.
        byte[] hexPublicKey = publicKey.y.toByteArray();
        result[1] = hexPublicKey;


        return result;

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
