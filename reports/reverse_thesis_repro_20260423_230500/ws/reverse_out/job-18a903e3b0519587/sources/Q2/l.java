package Q2;

import i2.AbstractC0580h;
import java.io.Serializable;
import java.nio.charset.Charset;
import java.util.Arrays;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public class l implements Serializable, Comparable {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private transient int f2557b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private transient String f2558c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final byte[] f2559d;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    public static final a f2556f = new a(null);

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public static final l f2555e = new l(new byte[0]);

    public static final class a {
        private a() {
        }

        public static /* synthetic */ l h(a aVar, byte[] bArr, int i3, int i4, int i5, Object obj) {
            if ((i5 & 1) != 0) {
                i3 = 0;
            }
            if ((i5 & 2) != 0) {
                i4 = bArr.length;
            }
            return aVar.g(bArr, i3, i4);
        }

        public final l a(String str) {
            t2.j.f(str, "string");
            return b(str);
        }

        public final l b(String str) {
            t2.j.f(str, "$this$decodeBase64");
            byte[] bArrA = AbstractC0205a.a(str);
            if (bArrA != null) {
                return new l(bArrA);
            }
            return null;
        }

        public final l c(String str) {
            t2.j.f(str, "$this$decodeHex");
            if (!(str.length() % 2 == 0)) {
                throw new IllegalArgumentException(("Unexpected hex string: " + str).toString());
            }
            int length = str.length() / 2;
            byte[] bArr = new byte[length];
            for (int i3 = 0; i3 < length; i3++) {
                int i4 = i3 * 2;
                bArr[i3] = (byte) ((R2.b.g(str.charAt(i4)) << 4) + R2.b.g(str.charAt(i4 + 1)));
            }
            return new l(bArr);
        }

        public final l d(String str, Charset charset) {
            t2.j.f(str, "$this$encode");
            t2.j.f(charset, "charset");
            byte[] bytes = str.getBytes(charset);
            t2.j.e(bytes, "(this as java.lang.String).getBytes(charset)");
            return new l(bytes);
        }

        public final l e(String str) {
            t2.j.f(str, "$this$encodeUtf8");
            l lVar = new l(AbstractC0209e.a(str));
            lVar.s(str);
            return lVar;
        }

        public final l f(byte... bArr) {
            t2.j.f(bArr, "data");
            byte[] bArrCopyOf = Arrays.copyOf(bArr, bArr.length);
            t2.j.e(bArrCopyOf, "java.util.Arrays.copyOf(this, size)");
            return new l(bArrCopyOf);
        }

        public final l g(byte[] bArr, int i3, int i4) {
            t2.j.f(bArr, "$this$toByteString");
            AbstractC0210f.b(bArr.length, i3, i4);
            return new l(AbstractC0580h.i(bArr, i3, i4 + i3));
        }

        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    public l(byte[] bArr) {
        t2.j.f(bArr, "data");
        this.f2559d = bArr;
    }

    public static final l c(String str) {
        return f2556f.b(str);
    }

    public static final l e(String str) {
        return f2556f.e(str);
    }

    public static final l o(byte... bArr) {
        return f2556f.f(bArr);
    }

    public void A(i iVar, int i3, int i4) {
        t2.j.f(iVar, "buffer");
        R2.b.f(this, iVar, i3, i4);
    }

    public String a() {
        return AbstractC0205a.c(g(), null, 1, null);
    }

    /* JADX WARN: Code restructure failed: missing block: B:13:0x0031, code lost:
    
        if (r0 < r1) goto L9;
     */
    /* JADX WARN: Code restructure failed: missing block: B:15:0x0034, code lost:
    
        return -1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:18:?, code lost:
    
        return 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:8:0x0028, code lost:
    
        if (r7 < r8) goto L9;
     */
    @Override // java.lang.Comparable
    /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public int compareTo(Q2.l r10) {
        /*
            r9 = this;
            java.lang.String r0 = "other"
            t2.j.f(r10, r0)
            int r0 = r9.v()
            int r1 = r10.v()
            int r2 = java.lang.Math.min(r0, r1)
            r3 = 0
            r4 = r3
        L13:
            r5 = -1
            r6 = 1
            if (r4 >= r2) goto L2e
            byte r7 = r9.f(r4)
            r7 = r7 & 255(0xff, float:3.57E-43)
            byte r8 = r10.f(r4)
            r8 = r8 & 255(0xff, float:3.57E-43)
            if (r7 != r8) goto L28
            int r4 = r4 + 1
            goto L13
        L28:
            if (r7 >= r8) goto L2c
        L2a:
            r3 = r5
            goto L34
        L2c:
            r3 = r6
            goto L34
        L2e:
            if (r0 != r1) goto L31
            goto L34
        L31:
            if (r0 >= r1) goto L2c
            goto L2a
        L34:
            return r3
        */
        throw new UnsupportedOperationException("Method not decompiled: Q2.l.compareTo(Q2.l):int");
    }

    public l d(String str) {
        t2.j.f(str, "algorithm");
        return R2.b.d(this, str);
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof l) {
            l lVar = (l) obj;
            if (lVar.v() == g().length && lVar.q(0, g(), 0, g().length)) {
                return true;
            }
        }
        return false;
    }

    public final byte f(int i3) {
        return m(i3);
    }

    public final byte[] g() {
        return this.f2559d;
    }

    public final int h() {
        return this.f2557b;
    }

    public int hashCode() {
        int iH = h();
        if (iH != 0) {
            return iH;
        }
        int iHashCode = Arrays.hashCode(g());
        r(iHashCode);
        return iHashCode;
    }

    public int i() {
        return g().length;
    }

    public final String j() {
        return this.f2558c;
    }

    public String k() {
        char[] cArr = new char[g().length * 2];
        int i3 = 0;
        for (byte b3 : g()) {
            int i4 = i3 + 1;
            cArr[i3] = R2.b.h()[(b3 >> 4) & 15];
            i3 += 2;
            cArr[i4] = R2.b.h()[b3 & 15];
        }
        return new String(cArr);
    }

    public byte[] l() {
        return g();
    }

    public byte m(int i3) {
        return g()[i3];
    }

    public final l n() {
        return d("MD5");
    }

    public boolean p(int i3, l lVar, int i4, int i5) {
        t2.j.f(lVar, "other");
        return lVar.q(i4, g(), i3, i5);
    }

    public boolean q(int i3, byte[] bArr, int i4, int i5) {
        t2.j.f(bArr, "other");
        return i3 >= 0 && i3 <= g().length - i5 && i4 >= 0 && i4 <= bArr.length - i5 && AbstractC0210f.a(g(), i3, bArr, i4, i5);
    }

    public final void r(int i3) {
        this.f2557b = i3;
    }

    public final void s(String str) {
        this.f2558c = str;
    }

    public final l t() {
        return d("SHA-1");
    }

    public String toString() {
        if (g().length == 0) {
            return "[size=0]";
        }
        int iC = R2.b.c(g(), 64);
        if (iC == -1) {
            if (g().length <= 64) {
                return "[hex=" + k() + ']';
            }
            StringBuilder sb = new StringBuilder();
            sb.append("[size=");
            sb.append(g().length);
            sb.append(" hex=");
            if (64 <= g().length) {
                sb.append((64 == g().length ? this : new l(AbstractC0580h.i(g(), 0, 64))).k());
                sb.append("…]");
                return sb.toString();
            }
            throw new IllegalArgumentException(("endIndex > length(" + g().length + ')').toString());
        }
        String strZ = z();
        if (strZ == null) {
            throw new NullPointerException("null cannot be cast to non-null type java.lang.String");
        }
        String strSubstring = strZ.substring(0, iC);
        t2.j.e(strSubstring, "(this as java.lang.Strin…ing(startIndex, endIndex)");
        String strQ = z2.g.q(z2.g.q(z2.g.q(strSubstring, "\\", "\\\\", false, 4, null), "\n", "\\n", false, 4, null), "\r", "\\r", false, 4, null);
        if (iC >= strZ.length()) {
            return "[text=" + strQ + ']';
        }
        return "[size=" + g().length + " text=" + strQ + "…]";
    }

    public final l u() {
        return d("SHA-256");
    }

    public final int v() {
        return i();
    }

    public final boolean w(l lVar) {
        t2.j.f(lVar, "prefix");
        return p(0, lVar, 0, lVar.v());
    }

    public l x() {
        byte b3;
        for (int i3 = 0; i3 < g().length; i3++) {
            byte b4 = g()[i3];
            byte b5 = (byte) 65;
            if (b4 >= b5 && b4 <= (b3 = (byte) 90)) {
                byte[] bArrG = g();
                byte[] bArrCopyOf = Arrays.copyOf(bArrG, bArrG.length);
                t2.j.e(bArrCopyOf, "java.util.Arrays.copyOf(this, size)");
                bArrCopyOf[i3] = (byte) (b4 + 32);
                for (int i4 = i3 + 1; i4 < bArrCopyOf.length; i4++) {
                    byte b6 = bArrCopyOf[i4];
                    if (b6 >= b5 && b6 <= b3) {
                        bArrCopyOf[i4] = (byte) (b6 + 32);
                    }
                }
                return new l(bArrCopyOf);
            }
        }
        return this;
    }

    public byte[] y() {
        byte[] bArrG = g();
        byte[] bArrCopyOf = Arrays.copyOf(bArrG, bArrG.length);
        t2.j.e(bArrCopyOf, "java.util.Arrays.copyOf(this, size)");
        return bArrCopyOf;
    }

    public String z() {
        String strJ = j();
        if (strJ != null) {
            return strJ;
        }
        String strB = AbstractC0209e.b(l());
        s(strB);
        return strB;
    }
}
