package p005b.p199l.p258c.p265e0;

import java.io.Closeable;
import java.io.Flushable;
import java.io.IOException;
import java.io.Writer;
import java.util.Objects;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.l.c.e0.c */
/* loaded from: classes2.dex */
public class C2474c implements Closeable, Flushable {

    /* renamed from: c */
    public static final String[] f6666c = new String[128];

    /* renamed from: e */
    public static final String[] f6667e;

    /* renamed from: f */
    public final Writer f6668f;

    /* renamed from: g */
    public int[] f6669g = new int[32];

    /* renamed from: h */
    public int f6670h = 0;

    /* renamed from: i */
    public String f6671i;

    /* renamed from: j */
    public String f6672j;

    /* renamed from: k */
    public boolean f6673k;

    /* renamed from: l */
    public boolean f6674l;

    /* renamed from: m */
    public String f6675m;

    /* renamed from: n */
    public boolean f6676n;

    static {
        for (int i2 = 0; i2 <= 31; i2++) {
            f6666c[i2] = String.format("\\u%04x", Integer.valueOf(i2));
        }
        String[] strArr = f6666c;
        strArr[34] = "\\\"";
        strArr[92] = "\\\\";
        strArr[9] = "\\t";
        strArr[8] = "\\b";
        strArr[10] = "\\n";
        strArr[13] = "\\r";
        strArr[12] = "\\f";
        String[] strArr2 = (String[]) strArr.clone();
        f6667e = strArr2;
        strArr2[60] = "\\u003c";
        strArr2[62] = "\\u003e";
        strArr2[38] = "\\u0026";
        strArr2[61] = "\\u003d";
        strArr2[39] = "\\u0027";
    }

    public C2474c(Writer writer) {
        m2840D(6);
        this.f6672j = ":";
        this.f6676n = true;
        Objects.requireNonNull(writer, "out == null");
        this.f6668f = writer;
    }

    /* renamed from: C */
    public final int m2839C() {
        int i2 = this.f6670h;
        if (i2 != 0) {
            return this.f6669g[i2 - 1];
        }
        throw new IllegalStateException("JsonWriter is closed.");
    }

    /* renamed from: D */
    public final void m2840D(int i2) {
        int i3 = this.f6670h;
        int[] iArr = this.f6669g;
        if (i3 == iArr.length) {
            int[] iArr2 = new int[i3 * 2];
            System.arraycopy(iArr, 0, iArr2, 0, i3);
            this.f6669g = iArr2;
        }
        int[] iArr3 = this.f6669g;
        int i4 = this.f6670h;
        this.f6670h = i4 + 1;
        iArr3[i4] = i2;
    }

    /* renamed from: E */
    public final void m2841E(int i2) {
        this.f6669g[this.f6670h - 1] = i2;
    }

    /* JADX WARN: Removed duplicated region for block: B:11:0x0034  */
    /* renamed from: I */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void m2842I(java.lang.String r9) {
        /*
            r8 = this;
            boolean r0 = r8.f6674l
            if (r0 == 0) goto L7
            java.lang.String[] r0 = p005b.p199l.p258c.p265e0.C2474c.f6667e
            goto L9
        L7:
            java.lang.String[] r0 = p005b.p199l.p258c.p265e0.C2474c.f6666c
        L9:
            java.io.Writer r1 = r8.f6668f
            java.lang.String r2 = "\""
            r1.write(r2)
            int r1 = r9.length()
            r3 = 0
            r4 = 0
        L16:
            if (r3 >= r1) goto L45
            char r5 = r9.charAt(r3)
            r6 = 128(0x80, float:1.8E-43)
            if (r5 >= r6) goto L25
            r5 = r0[r5]
            if (r5 != 0) goto L32
            goto L42
        L25:
            r6 = 8232(0x2028, float:1.1535E-41)
            if (r5 != r6) goto L2c
            java.lang.String r5 = "\\u2028"
            goto L32
        L2c:
            r6 = 8233(0x2029, float:1.1537E-41)
            if (r5 != r6) goto L42
            java.lang.String r5 = "\\u2029"
        L32:
            if (r4 >= r3) goto L3b
            java.io.Writer r6 = r8.f6668f
            int r7 = r3 - r4
            r6.write(r9, r4, r7)
        L3b:
            java.io.Writer r4 = r8.f6668f
            r4.write(r5)
            int r4 = r3 + 1
        L42:
            int r3 = r3 + 1
            goto L16
        L45:
            if (r4 >= r1) goto L4d
            java.io.Writer r0 = r8.f6668f
            int r1 = r1 - r4
            r0.write(r9, r4, r1)
        L4d:
            java.io.Writer r9 = r8.f6668f
            r9.write(r2)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p258c.p265e0.C2474c.m2842I(java.lang.String):void");
    }

    /* renamed from: P */
    public C2474c mo2788P(long j2) {
        m2843X();
        m2844b();
        this.f6668f.write(Long.toString(j2));
        return this;
    }

    /* renamed from: S */
    public C2474c mo2789S(Boolean bool) {
        if (bool == null) {
            return mo2800v();
        }
        m2843X();
        m2844b();
        this.f6668f.write(bool.booleanValue() ? "true" : "false");
        return this;
    }

    /* renamed from: U */
    public C2474c mo2790U(Number number) {
        if (number == null) {
            return mo2800v();
        }
        m2843X();
        String obj = number.toString();
        if (this.f6673k || !(obj.equals("-Infinity") || obj.equals("Infinity") || obj.equals("NaN"))) {
            m2844b();
            this.f6668f.append((CharSequence) obj);
            return this;
        }
        throw new IllegalArgumentException("Numeric values must be finite, but was " + number);
    }

    /* renamed from: V */
    public C2474c mo2791V(String str) {
        if (str == null) {
            return mo2800v();
        }
        m2843X();
        m2844b();
        m2842I(str);
        return this;
    }

    /* renamed from: W */
    public C2474c mo2792W(boolean z) {
        m2843X();
        m2844b();
        this.f6668f.write(z ? "true" : "false");
        return this;
    }

    /* renamed from: X */
    public final void m2843X() {
        if (this.f6675m != null) {
            int m2839C = m2839C();
            if (m2839C == 5) {
                this.f6668f.write(44);
            } else if (m2839C != 3) {
                throw new IllegalStateException("Nesting problem.");
            }
            m2846t();
            m2841E(4);
            m2842I(this.f6675m);
            this.f6675m = null;
        }
    }

    /* renamed from: b */
    public final void m2844b() {
        int m2839C = m2839C();
        if (m2839C == 1) {
            m2841E(2);
            m2846t();
            return;
        }
        if (m2839C == 2) {
            this.f6668f.append(',');
            m2846t();
        } else {
            if (m2839C == 4) {
                this.f6668f.append((CharSequence) this.f6672j);
                m2841E(5);
                return;
            }
            if (m2839C != 6) {
                if (m2839C != 7) {
                    throw new IllegalStateException("Nesting problem.");
                }
                if (!this.f6673k) {
                    throw new IllegalStateException("JSON must have only one top-level value.");
                }
            }
            m2841E(7);
        }
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        this.f6668f.close();
        int i2 = this.f6670h;
        if (i2 > 1 || (i2 == 1 && this.f6669g[i2 - 1] != 7)) {
            throw new IOException("Incomplete document");
        }
        this.f6670h = 0;
    }

    /* renamed from: d */
    public C2474c mo2795d() {
        m2843X();
        m2844b();
        m2840D(1);
        this.f6668f.write("[");
        return this;
    }

    /* renamed from: e */
    public C2474c mo2796e() {
        m2843X();
        m2844b();
        m2840D(3);
        this.f6668f.write("{");
        return this;
    }

    public void flush() {
        if (this.f6670h == 0) {
            throw new IllegalStateException("JsonWriter is closed.");
        }
        this.f6668f.flush();
    }

    /* renamed from: k */
    public final C2474c m2845k(int i2, int i3, String str) {
        int m2839C = m2839C();
        if (m2839C != i3 && m2839C != i2) {
            throw new IllegalStateException("Nesting problem.");
        }
        if (this.f6675m != null) {
            StringBuilder m586H = C1499a.m586H("Dangling name: ");
            m586H.append(this.f6675m);
            throw new IllegalStateException(m586H.toString());
        }
        this.f6670h--;
        if (m2839C == i3) {
            m2846t();
        }
        this.f6668f.write(str);
        return this;
    }

    /* renamed from: o */
    public C2474c mo2797o() {
        m2845k(1, 2, "]");
        return this;
    }

    /* renamed from: q */
    public C2474c mo2798q() {
        m2845k(3, 5, "}");
        return this;
    }

    /* renamed from: s */
    public C2474c mo2799s(String str) {
        Objects.requireNonNull(str, "name == null");
        if (this.f6675m != null) {
            throw new IllegalStateException();
        }
        if (this.f6670h == 0) {
            throw new IllegalStateException("JsonWriter is closed.");
        }
        this.f6675m = str;
        return this;
    }

    /* renamed from: t */
    public final void m2846t() {
        if (this.f6671i == null) {
            return;
        }
        this.f6668f.write("\n");
        int i2 = this.f6670h;
        for (int i3 = 1; i3 < i2; i3++) {
            this.f6668f.write(this.f6671i);
        }
    }

    /* renamed from: v */
    public C2474c mo2800v() {
        if (this.f6675m != null) {
            if (!this.f6676n) {
                this.f6675m = null;
                return this;
            }
            m2843X();
        }
        m2844b();
        this.f6668f.write("null");
        return this;
    }
}
