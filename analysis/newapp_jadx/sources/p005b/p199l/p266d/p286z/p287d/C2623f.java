package p005b.p199l.p266d.p286z.p287d;

import java.util.Formatter;
import p005b.p199l.p266d.C2536r;

/* renamed from: b.l.d.z.d.f */
/* loaded from: classes2.dex */
public final class C2623f {

    /* renamed from: a */
    public final C2618a f7155a;

    /* renamed from: b */
    public final C2624g[] f7156b;

    /* renamed from: c */
    public C2620c f7157c;

    /* renamed from: d */
    public final int f7158d;

    public C2623f(C2618a c2618a, C2620c c2620c) {
        this.f7155a = c2618a;
        int i2 = c2618a.f7132a;
        this.f7158d = i2;
        this.f7157c = c2620c;
        this.f7156b = new C2624g[i2 + 2];
    }

    /* renamed from: b */
    public static int m3070b(int i2, int i3, C2621d c2621d) {
        if (c2621d.m3065a()) {
            return i3;
        }
        if (!(i2 != -1 && c2621d.f7149c == (i2 % 3) * 3)) {
            return i3 + 1;
        }
        c2621d.f7151e = i2;
        return 0;
    }

    /* renamed from: a */
    public final void m3071a(C2624g c2624g) {
        int i2;
        if (c2624g != null) {
            C2625h c2625h = (C2625h) c2624g;
            C2618a c2618a = this.f7155a;
            C2621d[] c2621dArr = c2625h.f7160b;
            for (C2621d c2621d : c2621dArr) {
                if (c2621d != null) {
                    c2621d.m3066b();
                }
            }
            c2625h.m3075d(c2621dArr, c2618a);
            C2620c c2620c = c2625h.f7159a;
            boolean z = c2625h.f7161c;
            C2536r c2536r = z ? c2620c.f7139b : c2620c.f7141d;
            C2536r c2536r2 = z ? c2620c.f7140c : c2620c.f7142e;
            int m3073b = c2625h.m3073b((int) c2536r.f6872b);
            int m3073b2 = c2625h.m3073b((int) c2536r2.f6872b);
            int i3 = -1;
            int i4 = 0;
            int i5 = 1;
            while (m3073b < m3073b2) {
                if (c2621dArr[m3073b] != null) {
                    C2621d c2621d2 = c2621dArr[m3073b];
                    int i6 = c2621d2.f7151e;
                    int i7 = i6 - i3;
                    if (i7 == 0) {
                        i4++;
                    } else {
                        if (i7 == 1) {
                            int max = Math.max(i5, i4);
                            i2 = c2621d2.f7151e;
                            i5 = max;
                        } else if (i7 < 0 || i6 >= c2618a.f7136e || i7 > m3073b) {
                            c2621dArr[m3073b] = null;
                        } else {
                            if (i5 > 2) {
                                i7 *= i5 - 2;
                            }
                            boolean z2 = i7 >= m3073b;
                            for (int i8 = 1; i8 <= i7 && !z2; i8++) {
                                z2 = c2621dArr[m3073b - i8] != null;
                            }
                            if (z2) {
                                c2621dArr[m3073b] = null;
                            } else {
                                i2 = c2621d2.f7151e;
                            }
                        }
                        i3 = i2;
                        i4 = 1;
                    }
                }
                m3073b++;
            }
        }
    }

    public String toString() {
        C2624g[] c2624gArr = this.f7156b;
        C2624g c2624g = c2624gArr[0];
        if (c2624g == null) {
            c2624g = c2624gArr[this.f7158d + 1];
        }
        Formatter formatter = new Formatter();
        for (int i2 = 0; i2 < c2624g.f7160b.length; i2++) {
            try {
                formatter.format("CW %3d:", Integer.valueOf(i2));
                for (int i3 = 0; i3 < this.f7158d + 2; i3++) {
                    C2624g[] c2624gArr2 = this.f7156b;
                    if (c2624gArr2[i3] == null) {
                        formatter.format("    |   ", new Object[0]);
                    } else {
                        C2621d c2621d = c2624gArr2[i3].f7160b[i2];
                        if (c2621d == null) {
                            formatter.format("    |   ", new Object[0]);
                        } else {
                            formatter.format(" %3d|%3d", Integer.valueOf(c2621d.f7151e), Integer.valueOf(c2621d.f7150d));
                        }
                    }
                }
                formatter.format("%n", new Object[0]);
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
        String formatter2 = formatter.toString();
        formatter.close();
        return formatter2;
    }
}
