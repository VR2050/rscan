package z2;

import i2.AbstractC0586n;
import i2.x;
import java.util.ArrayList;
import java.util.List;

/* JADX INFO: Access modifiers changed from: package-private */
/* JADX INFO: loaded from: classes.dex */
public abstract class i extends h {

    static final class a extends t2.k implements s2.l {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        public static final a f10564c = new a();

        a() {
            super(1);
        }

        @Override // s2.l
        /* JADX INFO: renamed from: e, reason: merged with bridge method [inline-methods] */
        public final String d(String str) {
            t2.j.f(str, "line");
            return str;
        }
    }

    static final class b extends t2.k implements s2.l {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ String f10565c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        b(String str) {
            super(1);
            this.f10565c = str;
        }

        @Override // s2.l
        /* JADX INFO: renamed from: e, reason: merged with bridge method [inline-methods] */
        public final String d(String str) {
            t2.j.f(str, "line");
            return this.f10565c + str;
        }
    }

    private static final s2.l b(String str) {
        return str.length() == 0 ? a.f10564c : new b(str);
    }

    public static final String c(String str, String str2, String str3) {
        int i3;
        String str4;
        t2.j.f(str, "<this>");
        t2.j.f(str2, "newIndent");
        t2.j.f(str3, "marginPrefix");
        if (g.L(str3)) {
            throw new IllegalArgumentException("marginPrefix must be non-blank string.");
        }
        List listS = q.S(str);
        int length = str.length() + (str2.length() * listS.size());
        s2.l lVarB = b(str2);
        int iH = AbstractC0586n.h(listS);
        ArrayList arrayList = new ArrayList();
        int i4 = 0;
        for (Object obj : listS) {
            int i5 = i4 + 1;
            if (i4 < 0) {
                AbstractC0586n.n();
            }
            String str5 = (String) obj;
            String strSubstring = null;
            if ((i4 == 0 || i4 == iH) && g.L(str5)) {
                str5 = null;
            } else {
                int length2 = str5.length();
                int i6 = 0;
                while (true) {
                    if (i6 >= length2) {
                        i3 = -1;
                        break;
                    }
                    if (!z2.b.c(str5.charAt(i6))) {
                        i3 = i6;
                        break;
                    }
                    i6++;
                }
                if (i3 != -1) {
                    int i7 = i3;
                    if (g.t(str5, str3, i3, false, 4, null)) {
                        int length3 = i7 + str3.length();
                        t2.j.d(str5, "null cannot be cast to non-null type java.lang.String");
                        strSubstring = str5.substring(length3);
                        t2.j.e(strSubstring, "substring(...)");
                    }
                }
                if (strSubstring != null && (str4 = (String) lVarB.d(strSubstring)) != null) {
                    str5 = str4;
                }
            }
            if (str5 != null) {
                arrayList.add(str5);
            }
            i4 = i5;
        }
        String string = ((StringBuilder) x.G(arrayList, new StringBuilder(length), (124 & 2) != 0 ? ", " : "\n", (124 & 4) != 0 ? "" : null, (124 & 8) == 0 ? null : "", (124 & 16) != 0 ? -1 : 0, (124 & 32) != 0 ? "..." : null, (124 & 64) != 0 ? null : null)).toString();
        t2.j.e(string, "toString(...)");
        return string;
    }

    public static final String d(String str, String str2) {
        t2.j.f(str, "<this>");
        t2.j.f(str2, "marginPrefix");
        return c(str, "", str2);
    }

    public static /* synthetic */ String e(String str, String str2, int i3, Object obj) {
        if ((i3 & 1) != 0) {
            str2 = "|";
        }
        return d(str, str2);
    }
}
