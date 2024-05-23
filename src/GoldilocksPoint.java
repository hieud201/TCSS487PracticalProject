import java.math.BigInteger;
import static java.math.BigInteger.ONE;
public class GoldilocksPoint {
    
    // Define the value of r for Ed448-Goldilocks (static final for class constant)
    public static final BigInteger r = BigInteger.TWO.pow(446).subtract(
            new BigInteger("13818066809895115352007386748515426880336692474882178609894547503885"));

    public static final GoldilocksPoint O = new GoldilocksPoint();

    final static  BigInteger PRIME_P = (BigInteger.TWO.pow(448) // 2^448
                    .subtract(BigInteger.TWO.pow(224)) // - 2^224
                    .subtract(BigInteger.ONE)); // - 1
    private static final BigInteger D = BigInteger.valueOf(-39081); // The value of 'd' for the curve

    public BigInteger x;
    public BigInteger y;

    public static void main(String[] args) {
      BigInteger a = new BigInteger("563400200929088152613609629378641385410102682117258566404750214022059686929583319585040850282322731241505930835997382613319689400286258");
        // test GoldilocksPoint f();
        // must return 8;
        System.out.println(new GoldilocksPoint(false, a).x);
        // var a = new BigInteger("-1");
        //(𝑘 ⋅ 𝐺) + ((ℓ ⋅ 𝐺) + (𝑚 ⋅ 𝐺)) = ((𝑘 ⋅ 𝐺) + (ℓ ⋅ 𝐺)) + (𝑚 ⋅ 𝐺) test
        var k = new BigInteger("45");
        var l = new BigInteger("4555");
        var m = new BigInteger("4555");
        var A = EllipticCurve.G.multByScalar(k).add((EllipticCurve.G.multByScalar(l)).add(EllipticCurve.G.multByScalar(m)));
        var B = (EllipticCurve.G.multByScalar(k).add(EllipticCurve.G.multByScalar(l))).add(EllipticCurve.G.multByScalar(m));
        System.out.println(A.toString());
        System.out.println(B.toString());
        System.out.println(EllipticCurve.G.multByScalar(EllipticCurve.R));

    }

    public GoldilocksPoint(BigInteger x, BigInteger y) {
        this.x = x;
        this.y = y;
    }

    /**
     * Neutral Elements
     */
    public GoldilocksPoint() {
        this.x = BigInteger.valueOf(0);
        this.y = BigInteger.valueOf(1);
    }

    public GoldilocksPoint(boolean x_lsb, BigInteger y) {
        this.y = y;
        this.x = findXFromYwithLSB(y, x_lsb);

    }

    /**
     * Compute x = ±√((1 − y^2)/(1 + 39081y^2)) mod p
     * =============================================
     * test case: new BigInteger("563400200929088152613609629378641385410102682117258566404750214022059686929583319585040850282322731241505930835997382613319689400286258")
     * and false
     * return 8
     * @param y
     * @param x_lsb
     * @return
     */
    public static BigInteger findXFromYwithLSB(BigInteger y, boolean x_lsb){
        // Calculate y^2 mod p
        BigInteger ySquaredModP = y.multiply(y).mod(PRIME_P);

        BigInteger v = BigInteger.ONE.subtract(ySquaredModP)
                .multiply(BigInteger.ONE.add(BigInteger.valueOf(39081).multiply(ySquaredModP)).modInverse(PRIME_P))
                .mod(PRIME_P);
        return sqrt(v ,PRIME_P,x_lsb);
    }

    /**
     * Compute a square root of v mod p with a specified least-significant bit
     * if such a root exists.
     *  @param v   the radicand.
     * @param p   the modulus (must satisfy p mod 4 = 3).
     * @param lsb desired least significant bit (true: 1, false: 0).
     * @return a square root r of v mod p with r mod 2 = 1 iff lsb = true
     * if such a root exists, otherwise null.
     */
    public static BigInteger sqrt(BigInteger v, BigInteger p, boolean lsb) {
        assert (p.testBit(0) && p.testBit(1));
        if (v.signum() == 0) {
            return BigInteger.ZERO;
        }
        BigInteger r = v.modPow(p.shiftRight(2).add(BigInteger.ONE), p);
        if (r.testBit(0) != lsb) {
            r = p.subtract(r); // correct the lsb
        }
        return (r.multiply(r).subtract(v).mod(p).signum() == 0) ? r : null;
    }

    public boolean isEquals(Object point) {
        if (!(point instanceof GoldilocksPoint) | point == null) return false;
        var otherGPoint = (GoldilocksPoint) point;
        if (this.x == null || this.y == null) return false;
        if (otherGPoint.x == null || otherGPoint.y == null) return false;

        return this.x.equals(otherGPoint.x) && this.y.equals(otherGPoint.y);
    }

    public GoldilocksPoint getOppositePoint() {
        // -x == x * (P - 1)
        var negX = this.x.multiply(PRIME_P.subtract(ONE)).mod(PRIME_P);
        return new GoldilocksPoint(this.x.multiply(BigInteger.valueOf(-1)), this.y);
    }

    /**
     * Multiply various given BigIntegers together, mod PRIME_P
     *
     * @param lst list of bigints to be multiplied
     * @return result mod PRIME_P
     */
    private static BigInteger mult(BigInteger... lst) {
        var result = ONE;

        for (var x : lst) {
            result = (x != null) ? result.multiply(x).mod(PRIME_P) : result;
        }
        return result; // 36.489s pre-karatsuba
    }

    public GoldilocksPoint add(GoldilocksPoint other){
        BigInteger x1 = this.x;
        BigInteger x2 = other.x;
        BigInteger y1 = this.y;
        BigInteger y2 = other.y;

        BigInteger dx1x2y1y2= (((((D.multiply(x1).mod(PRIME_P)).multiply(x2)).mod(PRIME_P).multiply(y1)).mod(PRIME_P).multiply(y2))).mod(PRIME_P);
        BigInteger part1 = (x1.multiply(y2).mod(PRIME_P)).add(y1.multiply(x2).mod(PRIME_P)).mod(PRIME_P);
        BigInteger part2 = (BigInteger.ONE.add(dx1x2y1y2)).mod(PRIME_P);
        BigInteger part3 = (y1.multiply(y2).mod(PRIME_P)).subtract(x1.multiply(x2).mod(PRIME_P)).mod(PRIME_P);
        BigInteger part4 = (BigInteger.ONE.subtract(dx1x2y1y2)).mod(PRIME_P);



        BigInteger outX = mult(part1, part2.modInverse(PRIME_P)); // division in modular arithmetic
        BigInteger outY = mult(part3, part4.modInverse(PRIME_P));
        return new GoldilocksPoint(outX, outY);
    }




    /**
     * multiplication by scalar
     * @param s
     * @return
     */
    public GoldilocksPoint multByScalar(BigInteger s) {

        GoldilocksPoint V = new GoldilocksPoint(BigInteger.ZERO, ONE); // initialize V
        // search bits for the first s_k=1 to begin calculations with s_(k-1) ... s_0
        for (int i = s.bitLength() - 1; i >= 0; i--) { // scan over the k bits of s
            V = V.add(V);//edwardsAddition(V.x, V.y, V.x, V.y);   // invoke edwards point addition
            if (s.testBit(i)) {    // test i-th bit of s
                V = V.add(this); //edwardsAddition(V.x, V.y, P.x, P.y);    // edwards point addition formula
            }
        }
        return V;
    }
    @Override
    public String toString(){
        return "(" + this.x + ";" + this.y +")";
    }

}
