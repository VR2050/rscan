package z2;

import h2.C0563i;
import i2.AbstractC0580h;
import i2.AbstractC0586n;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

/* JADX INFO: Access modifiers changed from: package-private */
/* JADX INFO: loaded from: classes.dex */
public abstract class q extends p {

    static final class a extends t2.k implements s2.p {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ char[] f10566c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ boolean f10567d;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        a(char[] cArr, boolean z3) {
            super(2);
            this.f10566c = cArr;
            this.f10567d = z3;
        }

        @Override // s2.p
        public /* bridge */ /* synthetic */ Object b(Object obj, Object obj2) {
            return e((CharSequence) obj, ((Number) obj2).intValue());
        }

        public final C0563i e(CharSequence charSequence, int i3) {
            t2.j.f(charSequence, "$this$$receiver");
            int iK = q.K(charSequence, this.f10566c, i3, this.f10567d);
            if (iK < 0) {
                return null;
            }
            return h2.n.a(Integer.valueOf(iK), 1);
        }
    }

    static final class b extends t2.k implements s2.p {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ List f10568c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ boolean f10569d;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        b(List list, boolean z3) {
            super(2);
            this.f10568c = list;
            this.f10569d = z3;
        }

        @Override // s2.p
        public /* bridge */ /* synthetic */ Object b(Object obj, Object obj2) {
            return e((CharSequence) obj, ((Number) obj2).intValue());
        }

        public final C0563i e(CharSequence charSequence, int i3) {
            t2.j.f(charSequence, "$this$$receiver");
            C0563i c0563iC = q.C(charSequence, this.f10568c, i3, this.f10569d, false);
            if (c0563iC != null) {
                return h2.n.a(c0563iC.c(), Integer.valueOf(((String) c0563iC.d()).length()));
            }
            return null;
        }
    }

    static final class c extends t2.k implements s2.l {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ CharSequence f10570c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        c(CharSequence charSequence) {
            super(1);
            this.f10570c = charSequence;
        }

        @Override // s2.l
        /* JADX INFO: renamed from: e, reason: merged with bridge method [inline-methods] */
        public final String d(w2.c cVar) {
            t2.j.f(cVar, "it");
            return q.k0(this.f10570c, cVar);
        }
    }

    public static final boolean A(CharSequence charSequence, CharSequence charSequence2, boolean z3) {
        t2.j.f(charSequence, "<this>");
        t2.j.f(charSequence2, "suffix");
        return (!z3 && (charSequence instanceof String) && (charSequence2 instanceof String)) ? g.i((String) charSequence, (String) charSequence2, false, 2, null) : X(charSequence, charSequence.length() - charSequence2.length(), charSequence2, 0, charSequence2.length(), z3);
    }

    public static /* synthetic */ boolean B(CharSequence charSequence, CharSequence charSequence2, boolean z3, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            z3 = false;
        }
        return A(charSequence, charSequence2, z3);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final C0563i C(CharSequence charSequence, Collection collection, int i3, boolean z3, boolean z4) {
        Object next;
        Object next2;
        if (!z3 && collection.size() == 1) {
            String str = (String) AbstractC0586n.O(collection);
            int iJ = !z4 ? g.J(charSequence, str, i3, false, 4, null) : P(charSequence, str, i3, false, 4, null);
            if (iJ < 0) {
                return null;
            }
            return h2.n.a(Integer.valueOf(iJ), str);
        }
        w2.a cVar = !z4 ? new w2.c(w2.d.c(i3, 0), charSequence.length()) : w2.d.g(w2.d.e(i3, D(charSequence)), 0);
        if (charSequence instanceof String) {
            int iA = cVar.a();
            int iB = cVar.b();
            int iC = cVar.c();
            if ((iC > 0 && iA <= iB) || (iC < 0 && iB <= iA)) {
                while (true) {
                    Iterator it = collection.iterator();
                    while (true) {
                        if (!it.hasNext()) {
                            next2 = null;
                            break;
                        }
                        next2 = it.next();
                        String str2 = (String) next2;
                        if (p.l(str2, 0, (String) charSequence, iA, str2.length(), z3)) {
                            break;
                        }
                    }
                    String str3 = (String) next2;
                    if (str3 == null) {
                        if (iA == iB) {
                            break;
                        }
                        iA += iC;
                    } else {
                        return h2.n.a(Integer.valueOf(iA), str3);
                    }
                }
            }
        } else {
            int iA2 = cVar.a();
            int iB2 = cVar.b();
            int iC2 = cVar.c();
            if ((iC2 > 0 && iA2 <= iB2) || (iC2 < 0 && iB2 <= iA2)) {
                while (true) {
                    Iterator it2 = collection.iterator();
                    while (true) {
                        if (!it2.hasNext()) {
                            next = null;
                            break;
                        }
                        next = it2.next();
                        String str4 = (String) next;
                        if (X(str4, 0, charSequence, iA2, str4.length(), z3)) {
                            break;
                        }
                    }
                    String str5 = (String) next;
                    if (str5 == null) {
                        if (iA2 == iB2) {
                            break;
                        }
                        iA2 += iC2;
                    } else {
                        return h2.n.a(Integer.valueOf(iA2), str5);
                    }
                }
            }
        }
        return null;
    }

    public static final int D(CharSequence charSequence) {
        t2.j.f(charSequence, "<this>");
        return charSequence.length() - 1;
    }

    public static final int E(CharSequence charSequence, char c3, int i3, boolean z3) {
        t2.j.f(charSequence, "<this>");
        return (z3 || !(charSequence instanceof String)) ? K(charSequence, new char[]{c3}, i3, z3) : ((String) charSequence).indexOf(c3, i3);
    }

    public static final int F(CharSequence charSequence, String str, int i3, boolean z3) {
        t2.j.f(charSequence, "<this>");
        t2.j.f(str, "string");
        return (z3 || !(charSequence instanceof String)) ? H(charSequence, str, i3, charSequence.length(), z3, false, 16, null) : ((String) charSequence).indexOf(str, i3);
    }

    private static final int G(CharSequence charSequence, CharSequence charSequence2, int i3, int i4, boolean z3, boolean z4) {
        w2.a cVar = !z4 ? new w2.c(w2.d.c(i3, 0), w2.d.e(i4, charSequence.length())) : w2.d.g(w2.d.e(i3, D(charSequence)), w2.d.c(i4, 0));
        if ((charSequence instanceof String) && (charSequence2 instanceof String)) {
            int iA = cVar.a();
            int iB = cVar.b();
            int iC = cVar.c();
            if ((iC <= 0 || iA > iB) && (iC >= 0 || iB > iA)) {
                return -1;
            }
            while (!p.l((String) charSequence2, 0, (String) charSequence, iA, charSequence2.length(), z3)) {
                if (iA == iB) {
                    return -1;
                }
                iA += iC;
            }
            return iA;
        }
        int iA2 = cVar.a();
        int iB2 = cVar.b();
        int iC2 = cVar.c();
        if ((iC2 <= 0 || iA2 > iB2) && (iC2 >= 0 || iB2 > iA2)) {
            return -1;
        }
        while (!X(charSequence2, 0, charSequence, iA2, charSequence2.length(), z3)) {
            if (iA2 == iB2) {
                return -1;
            }
            iA2 += iC2;
        }
        return iA2;
    }

    static /* synthetic */ int H(CharSequence charSequence, CharSequence charSequence2, int i3, int i4, boolean z3, boolean z4, int i5, Object obj) {
        if ((i5 & 16) != 0) {
            z4 = false;
        }
        return G(charSequence, charSequence2, i3, i4, z3, z4);
    }

    public static /* synthetic */ int I(CharSequence charSequence, char c3, int i3, boolean z3, int i4, Object obj) {
        if ((i4 & 2) != 0) {
            i3 = 0;
        }
        if ((i4 & 4) != 0) {
            z3 = false;
        }
        return E(charSequence, c3, i3, z3);
    }

    public static /* synthetic */ int J(CharSequence charSequence, String str, int i3, boolean z3, int i4, Object obj) {
        if ((i4 & 2) != 0) {
            i3 = 0;
        }
        if ((i4 & 4) != 0) {
            z3 = false;
        }
        return F(charSequence, str, i3, z3);
    }

    public static final int K(CharSequence charSequence, char[] cArr, int i3, boolean z3) {
        t2.j.f(charSequence, "<this>");
        t2.j.f(cArr, "chars");
        if (!z3 && cArr.length == 1 && (charSequence instanceof String)) {
            return ((String) charSequence).indexOf(AbstractC0580h.z(cArr), i3);
        }
        int iC = w2.d.c(i3, 0);
        int iD = D(charSequence);
        if (iC > iD) {
            return -1;
        }
        while (true) {
            char cCharAt = charSequence.charAt(iC);
            for (char c3 : cArr) {
                if (z2.c.d(c3, cCharAt, z3)) {
                    return iC;
                }
            }
            if (iC == iD) {
                return -1;
            }
            iC++;
        }
    }

    public static boolean L(CharSequence charSequence) {
        t2.j.f(charSequence, "<this>");
        for (int i3 = 0; i3 < charSequence.length(); i3++) {
            if (!z2.b.c(charSequence.charAt(i3))) {
                return false;
            }
        }
        return true;
    }

    public static final int M(CharSequence charSequence, char c3, int i3, boolean z3) {
        t2.j.f(charSequence, "<this>");
        return (z3 || !(charSequence instanceof String)) ? Q(charSequence, new char[]{c3}, i3, z3) : ((String) charSequence).lastIndexOf(c3, i3);
    }

    public static final int N(CharSequence charSequence, String str, int i3, boolean z3) {
        t2.j.f(charSequence, "<this>");
        t2.j.f(str, "string");
        return (z3 || !(charSequence instanceof String)) ? G(charSequence, str, i3, 0, z3, true) : ((String) charSequence).lastIndexOf(str, i3);
    }

    public static /* synthetic */ int O(CharSequence charSequence, char c3, int i3, boolean z3, int i4, Object obj) {
        if ((i4 & 2) != 0) {
            i3 = D(charSequence);
        }
        if ((i4 & 4) != 0) {
            z3 = false;
        }
        return M(charSequence, c3, i3, z3);
    }

    public static /* synthetic */ int P(CharSequence charSequence, String str, int i3, boolean z3, int i4, Object obj) {
        if ((i4 & 2) != 0) {
            i3 = D(charSequence);
        }
        if ((i4 & 4) != 0) {
            z3 = false;
        }
        return N(charSequence, str, i3, z3);
    }

    public static final int Q(CharSequence charSequence, char[] cArr, int i3, boolean z3) {
        t2.j.f(charSequence, "<this>");
        t2.j.f(cArr, "chars");
        if (!z3 && cArr.length == 1 && (charSequence instanceof String)) {
            return ((String) charSequence).lastIndexOf(AbstractC0580h.z(cArr), i3);
        }
        for (int iE = w2.d.e(i3, D(charSequence)); -1 < iE; iE--) {
            char cCharAt = charSequence.charAt(iE);
            for (char c3 : cArr) {
                if (z2.c.d(c3, cCharAt, z3)) {
                    return iE;
                }
            }
        }
        return -1;
    }

    public static final y2.c R(CharSequence charSequence) {
        t2.j.f(charSequence, "<this>");
        return h0(charSequence, new String[]{"\r\n", "\n", "\r"}, false, 0, 6, null);
    }

    public static final List S(CharSequence charSequence) {
        t2.j.f(charSequence, "<this>");
        return y2.d.g(R(charSequence));
    }

    private static final y2.c T(CharSequence charSequence, char[] cArr, int i3, boolean z3, int i4) {
        c0(i4);
        return new e(charSequence, i3, i4, new a(cArr, z3));
    }

    private static final y2.c U(CharSequence charSequence, String[] strArr, int i3, boolean z3, int i4) {
        c0(i4);
        return new e(charSequence, i3, i4, new b(AbstractC0580h.d(strArr), z3));
    }

    static /* synthetic */ y2.c V(CharSequence charSequence, char[] cArr, int i3, boolean z3, int i4, int i5, Object obj) {
        if ((i5 & 2) != 0) {
            i3 = 0;
        }
        if ((i5 & 4) != 0) {
            z3 = false;
        }
        if ((i5 & 8) != 0) {
            i4 = 0;
        }
        return T(charSequence, cArr, i3, z3, i4);
    }

    static /* synthetic */ y2.c W(CharSequence charSequence, String[] strArr, int i3, boolean z3, int i4, int i5, Object obj) {
        if ((i5 & 2) != 0) {
            i3 = 0;
        }
        if ((i5 & 4) != 0) {
            z3 = false;
        }
        if ((i5 & 8) != 0) {
            i4 = 0;
        }
        return U(charSequence, strArr, i3, z3, i4);
    }

    public static final boolean X(CharSequence charSequence, int i3, CharSequence charSequence2, int i4, int i5, boolean z3) {
        t2.j.f(charSequence, "<this>");
        t2.j.f(charSequence2, "other");
        if (i4 < 0 || i3 < 0 || i3 > charSequence.length() - i5 || i4 > charSequence2.length() - i5) {
            return false;
        }
        for (int i6 = 0; i6 < i5; i6++) {
            if (!z2.c.d(charSequence.charAt(i3 + i6), charSequence2.charAt(i4 + i6), z3)) {
                return false;
            }
        }
        return true;
    }

    public static String Y(String str, CharSequence charSequence) {
        t2.j.f(str, "<this>");
        t2.j.f(charSequence, "prefix");
        if (!j0(str, charSequence, false, 2, null)) {
            return str;
        }
        String strSubstring = str.substring(charSequence.length());
        t2.j.e(strSubstring, "substring(...)");
        return strSubstring;
    }

    public static String Z(String str, CharSequence charSequence) {
        t2.j.f(str, "<this>");
        t2.j.f(charSequence, "suffix");
        if (!B(str, charSequence, false, 2, null)) {
            return str;
        }
        String strSubstring = str.substring(0, str.length() - charSequence.length());
        t2.j.e(strSubstring, "substring(...)");
        return strSubstring;
    }

    public static String a0(String str, CharSequence charSequence) {
        t2.j.f(str, "<this>");
        t2.j.f(charSequence, "delimiter");
        return b0(str, charSequence, charSequence);
    }

    public static final String b0(String str, CharSequence charSequence, CharSequence charSequence2) {
        t2.j.f(str, "<this>");
        t2.j.f(charSequence, "prefix");
        t2.j.f(charSequence2, "suffix");
        if (str.length() < charSequence.length() + charSequence2.length() || !j0(str, charSequence, false, 2, null) || !B(str, charSequence2, false, 2, null)) {
            return str;
        }
        String strSubstring = str.substring(charSequence.length(), str.length() - charSequence2.length());
        t2.j.e(strSubstring, "substring(...)");
        return strSubstring;
    }

    public static final void c0(int i3) {
        if (i3 >= 0) {
            return;
        }
        throw new IllegalArgumentException(("Limit must be non-negative, but was " + i3).toString());
    }

    public static final List d0(CharSequence charSequence, char[] cArr, boolean z3, int i3) {
        t2.j.f(charSequence, "<this>");
        t2.j.f(cArr, "delimiters");
        if (cArr.length == 1) {
            return e0(charSequence, String.valueOf(cArr[0]), z3, i3);
        }
        Iterable iterableA = y2.d.a(V(charSequence, cArr, 0, z3, i3, 2, null));
        ArrayList arrayList = new ArrayList(AbstractC0586n.o(iterableA, 10));
        Iterator it = iterableA.iterator();
        while (it.hasNext()) {
            arrayList.add(k0(charSequence, (w2.c) it.next()));
        }
        return arrayList;
    }

    private static final List e0(CharSequence charSequence, String str, boolean z3, int i3) {
        c0(i3);
        int length = 0;
        int iF = F(charSequence, str, 0, z3);
        if (iF == -1 || i3 == 1) {
            return AbstractC0586n.b(charSequence.toString());
        }
        boolean z4 = i3 > 0;
        ArrayList arrayList = new ArrayList(z4 ? w2.d.e(i3, 10) : 10);
        do {
            arrayList.add(charSequence.subSequence(length, iF).toString());
            length = str.length() + iF;
            if (z4 && arrayList.size() == i3 - 1) {
                break;
            }
            iF = F(charSequence, str, length, z3);
        } while (iF != -1);
        arrayList.add(charSequence.subSequence(length, charSequence.length()).toString());
        return arrayList;
    }

    public static /* synthetic */ List f0(CharSequence charSequence, char[] cArr, boolean z3, int i3, int i4, Object obj) {
        if ((i4 & 2) != 0) {
            z3 = false;
        }
        if ((i4 & 4) != 0) {
            i3 = 0;
        }
        return d0(charSequence, cArr, z3, i3);
    }

    public static final y2.c g0(CharSequence charSequence, String[] strArr, boolean z3, int i3) {
        t2.j.f(charSequence, "<this>");
        t2.j.f(strArr, "delimiters");
        return y2.d.f(W(charSequence, strArr, 0, z3, i3, 2, null), new c(charSequence));
    }

    public static /* synthetic */ y2.c h0(CharSequence charSequence, String[] strArr, boolean z3, int i3, int i4, Object obj) {
        if ((i4 & 2) != 0) {
            z3 = false;
        }
        if ((i4 & 4) != 0) {
            i3 = 0;
        }
        return g0(charSequence, strArr, z3, i3);
    }

    public static final boolean i0(CharSequence charSequence, CharSequence charSequence2, boolean z3) {
        t2.j.f(charSequence, "<this>");
        t2.j.f(charSequence2, "prefix");
        return (!z3 && (charSequence instanceof String) && (charSequence2 instanceof String)) ? g.u((String) charSequence, (String) charSequence2, false, 2, null) : X(charSequence, 0, charSequence2, 0, charSequence2.length(), z3);
    }

    public static /* synthetic */ boolean j0(CharSequence charSequence, CharSequence charSequence2, boolean z3, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            z3 = false;
        }
        return i0(charSequence, charSequence2, z3);
    }

    public static final String k0(CharSequence charSequence, w2.c cVar) {
        t2.j.f(charSequence, "<this>");
        t2.j.f(cVar, "range");
        return charSequence.subSequence(cVar.i().intValue(), cVar.h().intValue() + 1).toString();
    }

    public static final String l0(String str, char c3, String str2) {
        t2.j.f(str, "<this>");
        t2.j.f(str2, "missingDelimiterValue");
        int iO = g.O(str, c3, 0, false, 6, null);
        if (iO == -1) {
            return str2;
        }
        String strSubstring = str.substring(iO + 1, str.length());
        t2.j.e(strSubstring, "substring(...)");
        return strSubstring;
    }

    public static /* synthetic */ String m0(String str, char c3, String str2, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            str2 = str;
        }
        return l0(str, c3, str2);
    }

    public static CharSequence n0(CharSequence charSequence) {
        t2.j.f(charSequence, "<this>");
        int length = charSequence.length() - 1;
        int i3 = 0;
        boolean z3 = false;
        while (i3 <= length) {
            boolean zC = z2.b.c(charSequence.charAt(!z3 ? i3 : length));
            if (z3) {
                if (!zC) {
                    break;
                }
                length--;
            } else if (zC) {
                i3++;
            } else {
                z3 = true;
            }
        }
        return charSequence.subSequence(i3, length + 1);
    }

    public static final boolean w(CharSequence charSequence, char c3, boolean z3) {
        t2.j.f(charSequence, "<this>");
        return g.I(charSequence, c3, 0, z3, 2, null) >= 0;
    }

    public static final boolean x(CharSequence charSequence, CharSequence charSequence2, boolean z3) {
        t2.j.f(charSequence, "<this>");
        t2.j.f(charSequence2, "other");
        if (charSequence2 instanceof String) {
            if (g.J(charSequence, (String) charSequence2, 0, z3, 2, null) < 0) {
                return false;
            }
        } else if (H(charSequence, charSequence2, 0, charSequence.length(), z3, false, 16, null) < 0) {
            return false;
        }
        return true;
    }

    public static /* synthetic */ boolean y(CharSequence charSequence, char c3, boolean z3, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            z3 = false;
        }
        return w(charSequence, c3, z3);
    }

    public static /* synthetic */ boolean z(CharSequence charSequence, CharSequence charSequence2, boolean z3, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            z3 = false;
        }
        return x(charSequence, charSequence2, z3);
    }
}
