package io.openinstall.sdk;

import android.util.Pair;

/* JADX INFO: loaded from: classes3.dex */
public class dm {
    private static final byte[] a = {-96, 45, -21, -15, -5, 123, 124, -63, -29, -45, -85, -1, -119, 62, 73, 31, 37, -22, 122, -4, 57, 79, 56, 77, 57, -119, -75, 30, 40, 104, 52, 11};

    static String a(String str) {
        if (str == null) {
            return "";
        }
        try {
            byte[] bArrA = bt.d().a(str.replaceAll("\"|\n", ""));
            for (int i = 0; i < bArrA.length; i++) {
                bArrA[i] = (byte) (bArrA[i] ^ a[i % a.length]);
            }
            return new String(bArrA);
        } catch (Exception e) {
            return "";
        }
    }

    static Pair<String, String> b(String str) {
        String strA = a(str);
        String str2 = null;
        if (strA == null || strA.length() == 0) {
            return Pair.create(null, null);
        }
        int length = strA.length();
        String str3 = null;
        int i = 0;
        while (i < length) {
            while (i < length && (strA.charAt(i) == ' ' || strA.charAt(i) == '\"' || strA.charAt(i) == '\n')) {
                i++;
            }
            if (i >= length) {
                break;
            }
            int i2 = i;
            while (i2 < length && strA.charAt(i2) != '=') {
                i2++;
            }
            String strTrim = strA.substring(i, i2).trim();
            if (i2 >= length) {
                break;
            }
            int i3 = i2 + 1;
            while (i2 < length && strA.charAt(i2) != ' ' && strA.charAt(i2) != '\"' && strA.charAt(i2) != '\n') {
                i2++;
            }
            String strTrim2 = strA.substring(i3, i2).trim();
            if ("api".equalsIgnoreCase(strTrim)) {
                str2 = strTrim2;
            } else if ("stat".equalsIgnoreCase(strTrim)) {
                str3 = strTrim2;
            }
            i = i2;
        }
        return Pair.create(str2, str3);
    }
}
