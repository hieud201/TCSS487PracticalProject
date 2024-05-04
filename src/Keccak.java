import java.util.Arrays;

/**
 * Implementation of KMACXOF256.
 * @author Tin Phu, Hieu Doan, An Ho
 * @version 1.0.0
 */
public class Keccak {
    /**
     * Round constants <br>
     * ref. <a href="https://keccak.team/keccak_specs_summary.html">https://keccak.team/keccak_specs_summary.html</a>
     */
    private static final long[] roundConstants = {
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
            0x8000000080008000L, 0x000000000000808BL, 0x0000000080000001L,
            0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
            0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
            0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
            0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
            0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
            0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };

    /**
     * Rotation offsets <br>
     * ref. <a href="https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c">https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c</a>
     */
    private static final int[] rotationOffsets = {
            1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
            27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
    };

    /**
     * The position for each word with respective to the lane shifting in the pi function. <br>
     * ref. <a href="https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c">https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c</a>
     */
    private static final int[] piLane = {
            10, 7,  11, 17, 18, 3, 5, 16, 8,  21, 24, 4,
            15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
    };

    /**
     * The Keccak Message Authentication with extensible output, ref NIST SP 800-185 sec 4.3.1
     *
     * @author Tin Phu
     * @param k the key as a string
     * @param x the input bytes
     * @param l the desired bit length
     * @param s the customization string
     * @return the message authentication code derived from the provided input
     */
    public static byte[] KMACXOF256(String k, byte[] x, int l, String s) {

        byte[] byteK = k.getBytes();
        byte[] newX = concatByteArrays(bytepad(encode_string(byteK), 136), x);
        //in case of KMACXOF256, right_encode(0) is always used.
        byte[] right_encodeZERO = {
                 (byte) 0x00, (byte) 0x01
        };
        newX = concatByteArrays(newX, right_encodeZERO);
        return cSHAKE256(newX, l,  "KMAC", s);
    }

    /**
     * cSHAKE func ref sec 3.3 NIST SP 800-185
     * skip SHAKE256 because in case of KMACXOF256 n is always "KMAC".
     *
     * @author Tin Phu
     * @param x the main input bit string
     * @param l  an integer representing the requested output length in bits.
     * @param n is a function-name bit string,
     * @param s is a customization bit string
     * @return hash value in byte[]
     */
    public static byte[] cSHAKE256(byte[] x, int l, String n, String s) {
        byte[] newX = concatByteArrays(encode_string(n.getBytes()), encode_string(s.getBytes()));
        newX = concatByteArrays(bytepad(newX, 136), x);
        return sponge(newX, l, 512); // The capacity is always 512 for cSHAKE256.
    }

    /**
     * The sponge function, produces an output of length bitLen based on the
     * keccakp permutation over in.
     * @author Tin Phu
     * @param in the input byte array
     * @param d is output length
     * @param c the capacity
     * @return a byte array of d bits produced by the keccakp
     */
    private static byte[] sponge(byte[] in, int d, int c) {
        int rate = 1600 - c;
        long[] z = {};
        //System.out.println("before pad: "+byteArrayToHexString(in));
        byte[] padded = in.length % (rate / 8) == 0 ? in : padTenStarOne(rate, in);
        //System.out.println("after pad: " + byteArrayToHexString(padded));


        //FIPS PUB 202, Algorithm 8, step 4: Let P0, … , Pn-1 be the unique sequence of strings of length r such that P = P0 || … || Pn-1.
        // byteArrayToStates's implementation  strictly follows tiny_sha3 by mjosaarinen
        // https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
        long[][] states = byteArrayToStates(padded, c); //



        long[] s = new long[25];
        //FIPS PUB 202, Algorithm 8, step 6:
        for (long[] state : states) {
            s = keccakp(xorStates(s, state), 1600, 24); //  bitLen is 1600 and 24 rounds based on section 5.2 in FIPS PUB 202
        }
        //FIPS PUB 202, Algorithm 8, step 8 9 10 loop.
        int offset = 0;
        do {
            z = Arrays.copyOf(z, offset + rate/64);
            // //FIPS PUB 202, Algorithm 8, step 8: Let Z=Z || Truncr(S).
            System.arraycopy(s, 0, z, offset, rate/64);
            offset += rate/64;
            s = keccakp(s, 1600, 24);
        } while (z.length*64 < d);

        return stateToByteArray(z, d);
    }

    /**
     * ref sec 5.1 FIPS 202
     * The implementation strictly follows https://keccak.team/keccak_bits_and_bytes.html
     * The delimited suffix of cSHAKE256: https://keccak.team/keccak_specs_summary.html
     * @author Tin Phu
     * @param x the bytes array to pad
     * @param rate  in terms of bit length
     * @return the padded byte array
     */
    private static byte[] padTenStarOne(int rate, byte[] x) {
        byte[] d = new byte[] {0x04}; // The delimited suffix of cSHAKE256
        byte[] newX = concatByteArrays(x, d );
        int bytesToPad = (rate / 8) - newX.length % (rate / 8);
        byte[] paddedX = new byte[newX.length + bytesToPad];
        for (int i = 0; i < newX.length + bytesToPad; i++) {
            if (i < newX.length) paddedX[i] = newX[i];
            else if (i==newX.length + bytesToPad - 1) paddedX[i] = (byte) 0x80; // 0x80 = 1000 0000
            else paddedX[i] = 0;
        }
        return paddedX;
    }

    /**
     * The Keccack-p permutation performs a series of Round functions on the state array (ref section 3.3 NIST FIPS 202).
     * Strictly follows https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c by mjosaarinen
     * which is provided by the professor.
     * @author Hieu Doan, Tin Phu
     * @param stateIn the input state, an array of 25 longs (ref FIPS 202 sec. 3.1.2)
     * @param bitLen fixed length of permuted string
     * @param rounds number of iterations to perform the round function
     * @return the state after the Keccak-p permutation has been applied (array of longs of length bitLength)
     */
    private static long[] keccakp(long[] stateIn, int bitLen, int rounds) {
        long[] st = stateIn;
        int l = FloorLogTwo(bitLen/25); // the binary logarithm of the lane size
        // step 2 of Algorithm 7 loop.
        for (int i = 12 + 2*l - rounds; i < 12 + 2*l; i++) {

            //theta
            long[] thetaResult = new long[25];
            long[] bc = new long[5];

            for (int j = 0; j < 5; j++) {
                bc[j] = st[j] ^ st[j + 5] ^ st[j + 10] ^ st[j + 15] ^ st[j + 20];
            }

            for (int j = 0; j < 5; j++) {
                long d = bc[(j+4) % 5] ^ rotL64(bc[(j+1) % 5], 1);

                for (int k = 0; k < 5; k++) {
                    thetaResult[j + 5*k] = st[j + 5*k] ^ d;
                }
            }

            //rhoPhi
            long[] rhoPhiResult = new long[25];
            rhoPhiResult[0] = thetaResult[0]; // first value needs to be copied
            long t = thetaResult[1], temp;
            int ind;
            for (int j = 0; j < 24; j++) {
                ind = piLane[j];
                temp = thetaResult[ind];
                rhoPhiResult[ind] = rotL64(t, rotationOffsets[j]);
                t = temp;
            }

            //chi
            long[] chiResult = new long[25];
            for (int j = 0; j < 5; j++) {
                for (int k = 0; k < 5; k++) {
                    long tmp = ~rhoPhiResult[(j+1) % 5 + 5*k] & rhoPhiResult[(j+2) % 5 + 5*k];
                    chiResult[j + 5*k] = rhoPhiResult[j + 5*k] ^ tmp;
                }
            }

            //iota
            chiResult[0] ^= roundConstants[i];

            st = chiResult;




        }
        return st;
    }


    /**
     * Pads a bit string, sec 2.3.3 NIST SP 800-185
     * @author Tin Phu
     * @param x the bit string to pad
     * @param w the desired factor of the padding
     * @return a byte array prepended by lrEncode(w) such that it's length is an even multiple of w
     */
    private static byte[] bytepad(byte[] x, int w) {
        byte[] encodedW = left_encode(w);
        int len = encodedW.length + x.length + (w - (encodedW.length + x.length) % w);
        byte[] out = Arrays.copyOf(encodedW, len);
        System.arraycopy(x, 0, out, encodedW.length, x.length);
        return out;
    }

    /**
     * The encodeString func, NIST SP 800-185 2.3.2
     * @author Tin Phu
     * @param s the bit string to encode (as a byte array)
     * @return the bit string produced by prepending the encoding of str.length to str
     */
    private static byte[] encode_string(byte[] s) {
        byte[] len = left_encode(s.length* 8L); // bitwise length encoding
        byte[] out = Arrays.copyOf(len, len.length + s.length);
        System.arraycopy(s, 0, out, len.length, s.length);
        return out;
    }

    /**
     *  left_encode func in sec. 2.3.1 NIST SP 800-185
     * @author Tin Phu
     * @param len the integer to encode
     * @return a byte array: see NIST SP 800-185 sec. 2.3.1
     */
    private static byte[] left_encode(long len) {
        int n = 1;
        while ((1 << (8 * n)) <= len) n++;  // Find  the number of bits needed to represent the length
        byte[] encoding = new byte[n + 1];
        encoding[0] = (byte) n; // The first byte is the length
        for (int i = 1; i <= n; i++) {
            encoding[i] = (byte) (len >> (8 * (n - i)));
        }
        return encoding;
    }

    /************************************************************
     *                      Helper Methods                      *
     ************************************************************/



    /**
     * Converts a byte array to series of state arrays.
     * @author Tin Phu
     * @param in the input bytes
     * @param cap the capacity
     * @return a two-dimensional array states.
     */
    private static long[][] byteArrayToStates(byte[] in, int cap) {
        long[][] states = new long[(in.length*8)/(1600-cap)][25];
        int offset = 0;
        for (int i = 0; i < states.length; i++) {
            long[] state = new long[25];

            //FIPS PUB 202, Algorithm 8, step 4: Let P0, … , Pn-1 be the unique sequence of strings of length r such that P = P0 || … || Pn-1.
            //the unique sequence of strings of length 64 bits

            for (int j = 0; j < (1600-cap)/64; j++) {
                //Converts the bytes  into a 64 bit word (long)
                long word = 0L;
                for (int b = 0; b < 8; b++) {
                    word += (((long)in[offset + b]) & 0xff)<<(8*b);
                }
                state[j] = word;
                offset += 8; // value of offset [0, 8, 16, 24, 32, 40, 48, 56]

            }
            states[i] = state;

        }
        return states;
    }

    /**
     * Converts state arrays back to a byte array
     * @author Tin Phu
     * @param state the state to convert to a byte array
     * @param bitLen the bit length of the desired output
     * @return a byte array of length bitLen/8 corresponding to bytes of the state: state[0:bitLen/8]
     */
    private static byte[] stateToByteArray(long[] state, int bitLen) {
        byte[] out = new byte[bitLen/8];
        int i = 0;
        while (i*64 < bitLen) {
            long word = state[i++];
            int fill = i*64 > bitLen ? (bitLen - (i - 1) * 64) / 8 : 8;
            for (int b = 0; b < fill; b++) {
                byte ubt = (byte) (word>>>(8*b) & 0xFF);
                out[(i - 1)*8 + b] = ubt;
            }
        }
        return out;
    }

    /**
     * Returns a concatenated byte array (b1 + b2) from the two input byte arrays.
     * @author Tin Phu
     * @param b1 the first byte array
     * @param b2 the second state array
     * @return The concatenated byte array
     */
    public static byte[] concatByteArrays(byte[] b1, byte[] b2) {
        byte[] concatArray = Arrays.copyOf(b1, b1.length + b2.length);
        System.arraycopy(b2, 0, concatArray, b1.length, b2.length);
        return concatArray;
    }

    /**
     * Performs a bit-wise XOR operation on the given state arrays of type long
     * and returns the resulted long array.
     * @author Tin Phu
     * @param s1 the first state array
     * @param s2 the second state array
     * @return The resulted long array
     */
    private static long[] xorStates(long[] s1, long[] s2) {
        long[] out = new long[25];
        for (int i = 0; i < s1.length; i++) {
            out[i] = s1[i] ^ s2[i];
        }
        return out;
    }

    /**
     * Performs a bit-wise XOR operation on the given byte arrays
     * and returns the resulted byte array.
     * @author Hieu Doan
     * @param b1 the first byte array
     * @param b2 the second byte array
     * @return The resulted byte array
     */
    public static byte[] xorBytes(byte[] b1, byte[] b2) {
        byte[] res = new byte[b1.length];
        for (int i = 0; i < b1.length; i++) {
            res[i] = (byte) (b1[i] ^ b2[i]);
        }
        return res;
    }

    /**
     * Performs a left rotation of a 64-bit long integer by a given offset.
     * Strictly follows https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c by mjosaarinen
     * //ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))
     * @author Hieu Doan
     * @param x 64-bit long integer to be rotated.
     * @param y The number of bits to rotate by. If the offset is negative, it will be treated as a positive value.
     * @return The result of left rotating the given long integer by the specified offset.
     */
    private static long rotL64(long x, int y) {
        return (x << y) | (x >>> (64 - y));
    }

    /**
     * Computes the floor of the base-2 logarithm of an integer.
     * For a KECCAK-p permutation, the binary logarithm of the lane size, FIPS 202 sec. 2.2
     * @author Hieu Doan
     * @param n The integer value for which to compute the floor logarithm.
     * @return The floor of the base-2 logarithm of the given integer.
     */
    private static int FloorLogTwo(int n) {
        if (n <= 0) {
            throw new IllegalArgumentException("Input must be a positive integer");
        }
        int exponent = 0;
        while (n > 1) {
            n >>>= 1;
            exponent++;
        }
        return exponent;
    }
}