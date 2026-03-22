package p476m.p477a.p478a.p479a.p481m.p482d;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

/* renamed from: m.a.a.a.m.d.b */
/* loaded from: classes3.dex */
public final class C4782b {

    /* renamed from: a */
    public static final Map<String, String> f12255a;

    static {
        HashMap hashMap = new HashMap();
        f12255a = hashMap;
        hashMap.put("iso-2022-cn", "ISO2022CN");
        hashMap.put("iso-2022-kr", "ISO2022KR");
        hashMap.put("utf-8", "UTF8");
        hashMap.put("utf8", "UTF8");
        hashMap.put("ja_jp.iso2022-7", "ISO2022JP");
        hashMap.put("ja_jp.eucjp", "EUCJIS");
        hashMap.put("euc-kr", "KSC5601");
        hashMap.put("euckr", "KSC5601");
        hashMap.put("us-ascii", "ISO-8859-1");
        hashMap.put("x-us-ascii", "ISO-8859-1");
    }

    /* renamed from: a */
    public static String m5461a(String str) {
        if (str.indexOf("=?") < 0) {
            return str;
        }
        int length = str.length();
        StringBuilder sb = new StringBuilder(str.length());
        int i2 = 0;
        boolean z = false;
        int i3 = -1;
        int i4 = -1;
        while (i2 < length) {
            if (" \t\r\n".indexOf(str.charAt(i2)) != -1) {
                int i5 = i2;
                while (true) {
                    if (i5 >= length) {
                        int i6 = i5;
                        i3 = i2;
                        i2 = i6;
                        break;
                    }
                    if (" \t\r\n".indexOf(str.charAt(i5)) == -1) {
                        i4 = i5;
                        i3 = i2;
                        i2 = i4;
                        break;
                    }
                    i5++;
                }
            } else {
                int i7 = i2;
                while (i7 < length && " \t\r\n".indexOf(str.charAt(i7)) == -1) {
                    i7++;
                }
                String substring = str.substring(i2, i7);
                if (substring.startsWith("=?")) {
                    try {
                        String m5462b = m5462b(substring);
                        if (!z && i3 != -1) {
                            sb.append(str.substring(i3, i4));
                            i3 = -1;
                        }
                        sb.append(m5462b);
                        z = true;
                        i2 = i7;
                    } catch (C4783c unused) {
                    }
                }
                if (i3 != -1) {
                    sb.append(str.substring(i3, i4));
                    i3 = -1;
                }
                sb.append(substring);
                i2 = i7;
                z = false;
            }
        }
        return sb.toString();
    }

    /* renamed from: b */
    public static String m5462b(String str) {
        if (!str.startsWith("=?")) {
            throw new C4783c(C1499a.m637w("Invalid RFC 2047 encoded-word: ", str));
        }
        int indexOf = str.indexOf(63, 2);
        if (indexOf == -1) {
            throw new C4783c(C1499a.m637w("Missing charset in RFC 2047 encoded-word: ", str));
        }
        String substring = str.substring(2, indexOf);
        Locale locale = Locale.ENGLISH;
        String lowerCase = substring.toLowerCase(locale);
        int i2 = indexOf + 1;
        int indexOf2 = str.indexOf(63, i2);
        if (indexOf2 == -1) {
            throw new C4783c(C1499a.m637w("Missing encoding in RFC 2047 encoded-word: ", str));
        }
        String substring2 = str.substring(i2, indexOf2);
        int i3 = indexOf2 + 1;
        int indexOf3 = str.indexOf("?=", i3);
        if (indexOf3 == -1) {
            throw new C4783c(C1499a.m637w("Missing encoded text in RFC 2047 encoded-word: ", str));
        }
        String substring3 = str.substring(i3, indexOf3);
        if (substring3.length() == 0) {
            return "";
        }
        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream(substring3.length());
            byte[] bytes = substring3.getBytes("US-ASCII");
            if (substring2.equals("B")) {
                C4781a.m5460a(bytes, byteArrayOutputStream);
            } else {
                if (!substring2.equals("Q")) {
                    throw new UnsupportedEncodingException("Unknown RFC 2047 encoding: " + substring2);
                }
                C2354n.m2416O(bytes, byteArrayOutputStream);
            }
            byte[] byteArray = byteArrayOutputStream.toByteArray();
            if (lowerCase == null) {
                lowerCase = null;
            } else {
                String str2 = f12255a.get(lowerCase.toLowerCase(locale));
                if (str2 != null) {
                    lowerCase = str2;
                }
            }
            return new String(byteArray, lowerCase);
        } catch (IOException unused) {
            throw new UnsupportedEncodingException("Invalid RFC 2047 encoding");
        }
    }
}
