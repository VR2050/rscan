package p005b.p199l.p266d.p286z.p287d;

import java.util.Formatter;

/* renamed from: b.l.d.z.d.g */
/* loaded from: classes2.dex */
public class C2624g {

    /* renamed from: a */
    public final C2620c f7159a;

    /* renamed from: b */
    public final C2621d[] f7160b;

    public C2624g(C2620c c2620c) {
        this.f7159a = new C2620c(c2620c);
        this.f7160b = new C2621d[(c2620c.f7146i - c2620c.f7145h) + 1];
    }

    /* renamed from: a */
    public final C2621d m3072a(int i2) {
        C2621d c2621d;
        C2621d c2621d2;
        C2621d c2621d3 = this.f7160b[i2 - this.f7159a.f7145h];
        if (c2621d3 != null) {
            return c2621d3;
        }
        for (int i3 = 1; i3 < 5; i3++) {
            int i4 = i2 - this.f7159a.f7145h;
            int i5 = i4 - i3;
            if (i5 >= 0 && (c2621d2 = this.f7160b[i5]) != null) {
                return c2621d2;
            }
            int i6 = i4 + i3;
            C2621d[] c2621dArr = this.f7160b;
            if (i6 < c2621dArr.length && (c2621d = c2621dArr[i6]) != null) {
                return c2621d;
            }
        }
        return null;
    }

    /* renamed from: b */
    public final int m3073b(int i2) {
        return i2 - this.f7159a.f7145h;
    }

    public String toString() {
        Formatter formatter = new Formatter();
        try {
            int i2 = 0;
            for (C2621d c2621d : this.f7160b) {
                if (c2621d == null) {
                    formatter.format("%3d:    |   %n", Integer.valueOf(i2));
                    i2++;
                } else {
                    formatter.format("%3d: %3d|%3d%n", Integer.valueOf(i2), Integer.valueOf(c2621d.f7151e), Integer.valueOf(c2621d.f7150d));
                    i2++;
                }
            }
            String formatter2 = formatter.toString();
            formatter.close();
            return formatter2;
        } catch (Throwable th) {
            try {
                throw th;
            } catch (Throwable th2) {
                try {
                    formatter.close();
                } catch (Throwable th3) {
                    th.addSuppressed(th3);
                }
                throw th2;
            }
        }
    }
}
