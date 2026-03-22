package p005b.p295o.p296a.p297a.p298p;

import java.io.IOException;
import java.io.Reader;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.o.a.a.p.q */
/* loaded from: classes2.dex */
public class C2706q {

    /* renamed from: e */
    public int f7372e;

    /* renamed from: f */
    public final Reader f7373f;

    /* renamed from: a */
    public int f7368a = Integer.MIN_VALUE;

    /* renamed from: b */
    public int f7369b = Integer.MIN_VALUE;

    /* renamed from: c */
    public String f7370c = "";

    /* renamed from: d */
    public final StringBuffer f7371d = new StringBuffer();

    /* renamed from: g */
    public final int[] f7374g = new int[256];

    /* renamed from: h */
    public boolean f7375h = false;

    /* renamed from: i */
    public char f7376i = 0;

    public C2706q(Reader reader) {
        char c2 = 0;
        this.f7373f = reader;
        while (true) {
            int[] iArr = this.f7374g;
            if (c2 >= iArr.length) {
                m3235a();
                return;
            }
            if (('A' <= c2 && c2 <= 'Z') || (('a' <= c2 && c2 <= 'z') || c2 == '-')) {
                iArr[c2] = -3;
            } else if ('0' <= c2 && c2 <= '9') {
                iArr[c2] = -2;
            } else if (c2 < 0 || c2 > ' ') {
                iArr[c2] = c2;
            } else {
                iArr[c2] = -5;
            }
            c2 = (char) (c2 + 1);
        }
    }

    /* renamed from: a */
    public int m3235a() {
        int read;
        int i2;
        char c2;
        boolean z;
        boolean z2;
        int i3;
        if (this.f7375h) {
            this.f7375h = false;
            return this.f7368a;
        }
        this.f7368a = this.f7372e;
        do {
            boolean z3 = false;
            do {
                read = this.f7373f.read();
                if (read != -1) {
                    i2 = this.f7374g[read];
                } else {
                    if (this.f7376i != 0) {
                        throw new IOException("Unterminated quote");
                    }
                    i2 = -1;
                }
                c2 = this.f7376i;
                z = c2 == 0 && i2 == -5;
                z3 = z3 || z;
            } while (z);
            if (i2 == 39 || i2 == 34) {
                if (c2 == 0) {
                    this.f7376i = (char) i2;
                } else if (c2 == i2) {
                    this.f7376i = (char) 0;
                }
            }
            char c3 = this.f7376i;
            if (c3 != 0) {
                i2 = c3;
            }
            z2 = z3 || !(((i3 = this.f7368a) < -1 || i3 == 39 || i3 == 34) && i3 == i2);
            if (z2) {
                int i4 = this.f7368a;
                if (i4 == -3) {
                    this.f7370c = this.f7371d.toString();
                    this.f7371d.setLength(0);
                } else if (i4 == -2) {
                    this.f7369b = Integer.parseInt(this.f7371d.toString());
                    this.f7371d.setLength(0);
                } else if (i4 == 34 || i4 == 39) {
                    this.f7370c = this.f7371d.toString().substring(1, this.f7371d.length() - 1);
                    this.f7371d.setLength(0);
                }
                if (i2 != -5) {
                    this.f7372e = i2 == -6 ? read : i2;
                }
            }
            if (i2 == -3 || i2 == -2 || i2 == 34 || i2 == 39) {
                this.f7371d.append((char) read);
            }
        } while (!z2);
        return this.f7368a;
    }

    public String toString() {
        int i2 = this.f7368a;
        if (i2 != -3) {
            if (i2 == -2) {
                return Integer.toString(this.f7369b);
            }
            if (i2 == -1) {
                return "(EOF)";
            }
            if (i2 != 34) {
                if (i2 == 39) {
                    return C1499a.m582D(C1499a.m586H("'"), this.f7370c, "'");
                }
                StringBuilder m586H = C1499a.m586H("'");
                m586H.append((char) this.f7368a);
                m586H.append("'");
                return m586H.toString();
            }
        }
        return C1499a.m582D(C1499a.m586H("\""), this.f7370c, "\"");
    }
}
