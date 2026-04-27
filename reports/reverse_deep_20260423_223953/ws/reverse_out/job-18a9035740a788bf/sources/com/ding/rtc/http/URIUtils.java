package com.ding.rtc.http;

import java.io.UnsupportedEncodingException;
import java.util.BitSet;

/* JADX INFO: loaded from: classes.dex */
public class URIUtils {
    static final BitSet allowed_query;
    static final BitSet alpha;
    static final BitSet alphanum;
    static final BitSet digit = new BitSet(256);
    static final BitSet escaped;
    static final BitSet hex;
    static final BitSet mark;
    static final BitSet percent;
    static final BitSet reserved;
    static final BitSet unreserved;
    static final BitSet uric;

    static {
        for (int i = 48; i <= 57; i++) {
            digit.set(i);
        }
        alpha = new BitSet(256);
        for (int i2 = 97; i2 <= 122; i2++) {
            alpha.set(i2);
        }
        for (int i3 = 65; i3 <= 90; i3++) {
            alpha.set(i3);
        }
        BitSet bitSet = new BitSet(256);
        reserved = bitSet;
        bitSet.set(59);
        reserved.set(47);
        reserved.set(63);
        reserved.set(58);
        reserved.set(64);
        reserved.set(38);
        reserved.set(61);
        reserved.set(43);
        reserved.set(36);
        reserved.set(44);
        BitSet bitSet2 = new BitSet(256);
        mark = bitSet2;
        bitSet2.set(45);
        mark.set(95);
        mark.set(46);
        mark.set(33);
        mark.set(126);
        mark.set(42);
        mark.set(39);
        mark.set(40);
        mark.set(41);
        BitSet bitSet3 = new BitSet(256);
        alphanum = bitSet3;
        bitSet3.or(alpha);
        alphanum.or(digit);
        BitSet bitSet4 = new BitSet(256);
        unreserved = bitSet4;
        bitSet4.or(alphanum);
        unreserved.or(mark);
        BitSet bitSet5 = new BitSet(256);
        percent = bitSet5;
        bitSet5.set(37);
        BitSet bitSet6 = new BitSet(256);
        hex = bitSet6;
        bitSet6.or(digit);
        for (int i4 = 97; i4 <= 102; i4++) {
            hex.set(i4);
        }
        for (int i5 = 65; i5 <= 70; i5++) {
            hex.set(i5);
        }
        BitSet bitSet7 = new BitSet(256);
        escaped = bitSet7;
        bitSet7.or(percent);
        escaped.or(hex);
        BitSet bitSet8 = new BitSet(256);
        uric = bitSet8;
        bitSet8.or(reserved);
        uric.or(unreserved);
        uric.or(escaped);
        BitSet bitSet9 = new BitSet(256);
        allowed_query = bitSet9;
        bitSet9.or(uric);
        allowed_query.clear(37);
    }

    public static String encodeQuery(String unescaped, String charset) throws Exception {
        return new String(encode(unescaped, allowed_query, charset));
    }

    static char[] encode(String original, BitSet allowed, String charset) throws Exception {
        if (original == null) {
            throw new Exception("original is null");
        }
        if (allowed == null) {
            throw new Exception("null allowed characters");
        }
        try {
            byte[] octets = original.getBytes(charset);
            StringBuffer buf = new StringBuffer(octets.length);
            for (int i = 0; i < octets.length; i++) {
                char c = (char) octets[i];
                if (allowed.get(c)) {
                    buf.append(c);
                } else {
                    buf.append('%');
                    byte b = octets[i];
                    char hexadecimal = Character.forDigit((b >> 4) & 15, 16);
                    buf.append(Character.toUpperCase(hexadecimal));
                    char hexadecimal2 = Character.forDigit(b & 15, 16);
                    buf.append(Character.toUpperCase(hexadecimal2));
                }
            }
            return buf.toString().toCharArray();
        } catch (UnsupportedEncodingException error) {
            throw new Exception(error.getMessage());
        }
    }
}
