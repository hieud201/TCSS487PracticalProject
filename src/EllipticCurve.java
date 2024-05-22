import java.math.BigInteger;

public class EllipticCurve {

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

        //Bonus points:
        //Encrypt the private key from that pair under the given password

        result[0] = privateKey.toByteArray();

        GoldilocksPoint publicKey = G.multByScalar(privateKey);
        // encode the coordinates separately and concatenate them to form the hexadecimal string key.

        byte[] hexPublicKey = Keccak.concatByteArrays(Keccak.encode_string(publicKey.x.toByteArray()), Keccak.encode_string(publicKey.y.toByteArray()));
        result[1] = hexPublicKey;


        return result;

    }

}
