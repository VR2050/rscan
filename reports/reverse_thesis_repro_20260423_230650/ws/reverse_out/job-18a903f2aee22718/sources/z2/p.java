package z2;

import java.util.Comparator;
import t2.w;

/* JADX INFO: Access modifiers changed from: package-private */
/* JADX INFO: loaded from: classes.dex */
public abstract class p extends o {
    public static final boolean h(String str, String str2, boolean z3) {
        t2.j.f(str, "<this>");
        t2.j.f(str2, "suffix");
        return !z3 ? str.endsWith(str2) : l(str, str.length() - str2.length(), str2, 0, str2.length(), true);
    }

    public static /* synthetic */ boolean i(String str, String str2, boolean z3, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            z3 = false;
        }
        return h(str, str2, z3);
    }

    public static boolean j(String str, String str2, boolean z3) {
        return str == null ? str2 == null : !z3 ? str.equals(str2) : str.equalsIgnoreCase(str2);
    }

    public static Comparator k(w wVar) {
        t2.j.f(wVar, "<this>");
        Comparator comparator = String.CASE_INSENSITIVE_ORDER;
        t2.j.e(comparator, "CASE_INSENSITIVE_ORDER");
        return comparator;
    }

    public static final boolean l(String str, int i3, String str2, int i4, int i5, boolean z3) {
        t2.j.f(str, "<this>");
        t2.j.f(str2, "other");
        return !z3 ? str.regionMatches(i3, str2, i4, i5) : str.regionMatches(z3, i3, str2, i4, i5);
    }

    public static String m(CharSequence charSequence, int i3) {
        t2.j.f(charSequence, "<this>");
        if (i3 < 0) {
            throw new IllegalArgumentException(("Count 'n' must be non-negative, but was " + i3 + '.').toString());
        }
        if (i3 == 0) {
            return "";
        }
        int i4 = 1;
        if (i3 == 1) {
            return charSequence.toString();
        }
        int length = charSequence.length();
        if (length == 0) {
            return "";
        }
        if (length == 1) {
            char cCharAt = charSequence.charAt(0);
            char[] cArr = new char[i3];
            for (int i5 = 0; i5 < i3; i5++) {
                cArr[i5] = cCharAt;
            }
            return new String(cArr);
        }
        StringBuilder sb = new StringBuilder(charSequence.length() * i3);
        if (1 <= i3) {
            while (true) {
                sb.append(charSequence);
                if (i4 == i3) {
                    break;
                }
                i4++;
            }
        }
        String string = sb.toString();
        t2.j.c(string);
        return string;
    }

    public static final String n(String str, char c3, char c4, boolean z3) {
        t2.j.f(str, "<this>");
        if (!z3) {
            String strReplace = str.replace(c3, c4);
            t2.j.e(strReplace, "replace(...)");
            return strReplace;
        }
        StringBuilder sb = new StringBuilder(str.length());
        for (int i3 = 0; i3 < str.length(); i3++) {
            char cCharAt = str.charAt(i3);
            if (c.d(cCharAt, c3, z3)) {
                cCharAt = c4;
            }
            sb.append(cCharAt);
        }
        String string = sb.toString();
        t2.j.e(string, "toString(...)");
        return string;
    }

    public static final String o(String str, String str2, String str3, boolean z3) {
        t2.j.f(str, "<this>");
        t2.j.f(str2, "oldValue");
        t2.j.f(str3, "newValue");
        int i3 = 0;
        int iF = q.F(str, str2, 0, z3);
        if (iF < 0) {
            return str;
        }
        int length = str2.length();
        int iC = w2.d.c(length, 1);
        int length2 = (str.length() - length) + str3.length();
        if (length2 < 0) {
            throw new OutOfMemoryError();
        }
        StringBuilder sb = new StringBuilder(length2);
        do {
            sb.append((CharSequence) str, i3, iF);
            sb.append(str3);
            i3 = iF + length;
            if (iF >= str.length()) {
                break;
            }
            iF = q.F(str, str2, iF + iC, z3);
        } while (iF > 0);
        sb.append((CharSequence) str, i3, str.length());
        String string = sb.toString();
        t2.j.e(string, "toString(...)");
        return string;
    }

    public static /* synthetic */ String p(String str, char c3, char c4, boolean z3, int i3, Object obj) {
        if ((i3 & 4) != 0) {
            z3 = false;
        }
        return n(str, c3, c4, z3);
    }

    public static /* synthetic */ String q(String str, String str2, String str3, boolean z3, int i3, Object obj) {
        if ((i3 & 4) != 0) {
            z3 = false;
        }
        return o(str, str2, str3, z3);
    }

    public static boolean r(String str, String str2, int i3, boolean z3) {
        t2.j.f(str, "<this>");
        t2.j.f(str2, "prefix");
        return !z3 ? str.startsWith(str2, i3) : l(str, i3, str2, 0, str2.length(), z3);
    }

    public static boolean s(String str, String str2, boolean z3) {
        t2.j.f(str, "<this>");
        t2.j.f(str2, "prefix");
        return !z3 ? str.startsWith(str2) : l(str, 0, str2, 0, str2.length(), z3);
    }

    public static /* synthetic */ boolean t(String str, String str2, int i3, boolean z3, int i4, Object obj) {
        if ((i4 & 4) != 0) {
            z3 = false;
        }
        return g.r(str, str2, i3, z3);
    }

    public static /* synthetic */ boolean u(String str, String str2, boolean z3, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            z3 = false;
        }
        return g.s(str, str2, z3);
    }
}
