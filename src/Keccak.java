/*
 * Implementation of the Keccak[c] function defined in NIST FIPS 202.
 * Author: Spencer Little
 * Date: 01/22/2020
 */

import java.util.Arrays;

/**
 * Implemention of KMACXOF256
 * @author
 * @version 1.0.0
 */
public class Keccak {

    /* Round constants
     *  ref. https://keccak.team/keccak_specs_summary.html
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

    /*
     * Rotation offsets
     * ref. https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
     */
    private static final int[] rotationOffsets = {
            1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
            27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
    };

    /*
     * The position for each word with respective to the lane shifting in the pi function.
     * ref. https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
     */
    private static final int[] piLane = {
            10, 7,  11, 17, 18, 3, 5, 16, 8,  21, 24, 4,
            15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
    };


    /**
     * The Keccak Message Authentication with extensible output, ref NIST SP 800-185 sec 4.3.1
     * @Author Tin Phu
     * @param k the key
     * @param x the input bytes
     * @param l the desired bit length
     * @param s the customization string
     * @return the message authentication code derived from the provided input
     */
    public static byte[] KMACXOF256(byte[] k, byte[] x, int l, String s) {
        byte[] newX = concatByteArrays(bytepad(encode_string(k), 136), x);
        //in case of KMACXOF256, right_encode(0) is always used.
        byte[] right_encodeZERO = {
                 (byte) 0x00, (byte) 0x01
        };
        newX = concatByteArrays(newX, right_encodeZERO);
        return cSHAKE256(newX, l,  "KMAC", s);
    }
    private static String byteArrayToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));

        }
        return sb.toString();
    }


    /**
     * cSHAKE func ref sec 3.3 NIST SP 800-185
     * skip SHAKE256 because in case of KMACXOF256 n is always "KMAC"
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


//    /**
//     * The SHA-3 hash function defined in NIST FIPS 202.
//     * @param in the bytes to compute the digest of
//     * @param bitLen the desired length of the output (must be 224, 256, 384, or 512)
//     * @return the message digest computed via the Keccak[bitLen*2] permutation
//     */
//    public static byte[] SHA3(byte[] in, int bitLen) {
//        if (bitLen != 224 && bitLen != 256 && bitLen != 384 && bitLen != 512)
//            throw new IllegalArgumentException("Supported output bit lengths are 224, 256, 384, and 512.");
//        byte[] uin = Arrays.copyOf(in, in.length + 1);
//        int bytesToPad = (1600 - bitLen*2) / 8 - in.length % (1600 - bitLen*2);
//        uin[in.length] = bytesToPad == 1 ? (byte) 0x86 : 0x06; // pad with suffix defined in FIPS 202 sec. 6.1
//        return sponge(uin, bitLen, bitLen*2);
//    }

    /**
     * The sponge function, produces an output of length bitLen based on the
     * keccakp permutation over in.
     * @param in the input byte array
     * @param d is output length
     * @param c the capacity
     * @return a byte array of d bits produced by the keccakp
     */
    private static byte[] sponge(byte[] in, int d, int c) {
        int rate = 1600 - c;
        long[] out = {};
        //System.out.println("before pad: "+byteArrayToHexString(in));
        byte[] padded = in.length % (rate / 8) == 0 ? in : padTenStarOne(rate, in);
        //System.out.println("after pad: " + byteArrayToHexString(padded));


        //FIPS PUB 202, Algorithm 8, step 4: Let P0, … , Pn-1 be the unique sequence of strings of length r such that P = P0 || … || Pn-1.
        // the inner array of states should already include 0 for the remaining bit as Pi||0^c (Step 6)
        long[][] states = byteArrayToStates(padded, c); // "denotes a 5-by-5-by-w array of bits that represents the state" 3.1 in FIPS PUB 202
        long[] stcml = new long[25]; //we combined 5x5 Slice into an array instead of Arr[5][5]
        for (long[] st : states) {
            stcml = keccakp(xorStates(stcml, st), 1600, 24); //  bitLen is 1600 and 24 rounds based on section 5.2 in FIPS PUB 202
        }

        int offset = 0;
        do {
            out = Arrays.copyOf(out, offset + rate/64);
            System.arraycopy(stcml, 0, out, offset, rate/64);
            offset += rate/64;
            stcml = keccakp(stcml, 1600, 24);
        } while (out.length*64 < d);

        return stateToByteArray(out, d);
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


    /************************************************************
     *                    Keccak Machinery                      *
     ************************************************************/


    /**
     * The Keccack-p permutation, ref section 3.3 NIST FIPS 202.
     * @param stateIn the input state, an array of 25 longs ref FIPS 202 sec. 3.1.2
     * @return the state after the Keccak-p permutation has been applied
     */
    private static long[] keccakp(long[] stateIn, int bitLen, int rounds) {
        long[] tempState = stateIn;
        int l = floorLog(bitLen/25);
        for (int i = 12 + 2*l - rounds; i < 12 + 2*l; i++) {
            tempState = iota(chi(rhoPhi(theta(tempState))), i); // sec 3.3 FIPS 202
        }
        return tempState;
    }

    /**
     * The theta function, ref section 3.2.1 NIST FIPS 202. xors each state bit
     * with the parities of two columns in the array.
     * Adapted from https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
     * @param stateIn the input state, an array of 25 longs ref FIPS 202 sec. 3.1.2
     * @return the state after the theta function has been applied (array of longs)
     */
    private static long[] theta(long[] stateIn) {
        long[] stateOut = new long[25];
        long[] C = new long[5];

        for (int i = 0; i < 5; i++) {
            C[i] = stateIn[i] ^ stateIn[i + 5] ^ stateIn[i + 10] ^ stateIn[i + 15] ^ stateIn[i + 20];
        }

        for (int i = 0; i < 5; i++) {
            long d = C[(i+4) % 5] ^ lRotWord(C[(i+1) % 5], 1);

            for (int j = 0; j < 5; j++) {
                stateOut[i + 5*j] = stateIn[i + 5*j] ^ d;
            }
        }

        return stateOut;
    }

    /**
     * The rho and phi function, ref section 3.2.2-3 NIST FIPS 202. Shifts and rearranges words.
     * Adapted from https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
     * @param stateIn the input state, an array of 25 longs ref FIPS 202 sec. 3.1.2
     * @return the state after applying the rho and phi function
     */
    private static long[] rhoPhi(long[] stateIn) {
        long[] stateOut = new long[25];
        stateOut[0] = stateIn[0]; // first value needs to be copied
        long t = stateIn[1], temp;
        int ind;
        for (int i = 0; i < 24; i++) {
            ind = piLane[i];
            temp = stateIn[ind];
            stateOut[ind] = lRotWord(t, rotationOffsets[i]);
            t = temp;
        }
        return stateOut;
    }

    /**
     * The chi function, ref section 3.2.4 NIST FIPS 202. xors each word with
     * a function of two other words in their row.
     * @param stateIn the input state, an array of 25 longs ref FIPS 202 sec. 3.1.2
     * @return the state after applying the chi function
     */
    private static long[] chi(long[] stateIn) {
        long[] stateOut = new long[25];
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 5; j++) {
                long tmp = ~stateIn[(i+1) % 5 + 5*j] & stateIn[(i+2) % 5 + 5*j];
                stateOut[i + 5*j] = stateIn[i + 5*j] ^ tmp;
            }
        }
        return stateOut;
    }

    /**
     * Applies the round constant to the word at stateIn[0].
     * ref. section 3.2.5 NIST FIPS 202.
     * @param stateIn the input state, an array of 25 longs ref FIPS 202 sec. 3.1.2
     * @return the state after the round constant has been xored with the first lane (st[0])
     */
    private static long[] iota(long[] stateIn, int round) {
        stateIn[0] ^= roundConstants[round];
        return stateIn;
    }


    /************************************************************
     *                    Auxiliary Methods                     *
     ************************************************************/

    /**
     * Pads a bit string, sec 2.3.3 NIST SP 800-185
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
     *  P.s: đã xào by Tin.
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


    /**
     * Converts an extended state array to an array of bytes of bit length bitLen (equivalent to Trunc_r).
     * @param state the state to convert to a byte array
     * @param bitLen the bit length of the desired output
     * @return a byte array of length bitLen/8 corresponding to bytes of the state: state[0:bitLen/8]
     */
    private static byte[] stateToByteArray(long[] state, int bitLen) {
        if (state.length*64 < bitLen) throw new IllegalArgumentException("State is of insufficient length to produced desired bit length.");
        byte[] out = new byte[bitLen/8];
        int wrdInd = 0;
        while (wrdInd*64 < bitLen) {
            long word = state[wrdInd++];
            int fill = wrdInd*64 > bitLen ? (bitLen - (wrdInd - 1) * 64) / 8 : 8;
            for (int b = 0; b < fill; b++) {
                byte ubt = (byte) (word>>>(8*b) & 0xFF);
                out[(wrdInd - 1)*8 + b] = ubt;
            }
        }

        return out;
    }

    /**
     * Converts a byte array to series of state arrays.
     * @param in the input bytes
     * @param cap the capacity
     * @return a two dimensional array in which the inner array is 5x5 slide.
     */
    private static long[][] byteArrayToStates(byte[] in, int cap) {
        long[][] states = new long[(in.length*8)/(1600-cap)][25];
        int offset = 0;
        for (int i = 0; i < states.length; i++) {
            long[] state = new long[25];
            for (int j = 0; j < (1600-cap)/64; j++) {
                long word = bytesToWord(offset, in);
                System.out.println("word:" + word);
                state[j] = word;
                offset += 8;
            }
            // remaining words will be 0 according to Algorithm 8. step 6 FIPS 202
            states[i] = state;
        }
        return states;
    }

    /**
     * Converts the bytes from in[l,r] into a 64 bit word (long)
     * @param offset the position in the array to read the eight bytes from
     * @param in the byte array to read from
     * @return a long that is the result of concatenating the eight bytes beginning at offset
     */
    private static long bytesToWord(int offset, byte[] in) {
        long word = 0L;
        for (int i = 0; i < 8; i++) {
            word += (((long)in[offset + i]) & 0xff)<<(8*i);
        }
        return word;
    }

    private static byte[] concatByteArrays(byte[] b1, byte[] b2) {
        byte[] mrg = Arrays.copyOf(b1, b1.length + b2.length);
        System.arraycopy(b2, 0, mrg, b1.length, b2.length);
        return mrg;
    }

    private static long[] xorStates(long[] s1, long[] s2) {
        long[] out = new long[25];
        for (int i = 0; i < s1.length; i++) {
            out[i] = s1[i] ^ s2[i];
        }
        return out;
    }

    private static long lRotWord(long w, int offset) {
        int ofs = offset % 64;
        return w << ofs | (w >>>(Long.SIZE - ofs));
    }

    private static int floorLog(int n) {
        int exp = -1;
        while (n > 0) {
            n = n>>>1;
            exp++;
        }
        return exp;
    }

    private static String byteArrayToBinary(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0'));
        }
        return sb.toString();
    }

}