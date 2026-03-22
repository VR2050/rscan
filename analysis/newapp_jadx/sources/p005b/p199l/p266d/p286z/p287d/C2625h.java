package p005b.p199l.p266d.p286z.p287d;

/* renamed from: b.l.d.z.d.h */
/* loaded from: classes2.dex */
public final class C2625h extends C2624g {

    /* renamed from: c */
    public final boolean f7161c;

    public C2625h(C2620c c2620c, boolean z) {
        super(c2620c);
        this.f7161c = z;
    }

    /* renamed from: c */
    public C2618a m3074c() {
        C2621d[] c2621dArr = this.f7160b;
        C2619b c2619b = new C2619b();
        C2619b c2619b2 = new C2619b();
        C2619b c2619b3 = new C2619b();
        C2619b c2619b4 = new C2619b();
        for (C2621d c2621d : c2621dArr) {
            if (c2621d != null) {
                c2621d.m3066b();
                int i2 = c2621d.f7150d % 30;
                int i3 = c2621d.f7151e;
                if (!this.f7161c) {
                    i3 += 2;
                }
                int i4 = i3 % 3;
                if (i4 == 0) {
                    c2619b2.m3064b((i2 * 3) + 1);
                } else if (i4 == 1) {
                    c2619b4.m3064b(i2 / 3);
                    c2619b3.m3064b(i2 % 3);
                } else if (i4 == 2) {
                    c2619b.m3064b(i2 + 1);
                }
            }
        }
        if (c2619b.m3063a().length == 0 || c2619b2.m3063a().length == 0 || c2619b3.m3063a().length == 0 || c2619b4.m3063a().length == 0 || c2619b.m3063a()[0] <= 0 || c2619b2.m3063a()[0] + c2619b3.m3063a()[0] < 3 || c2619b2.m3063a()[0] + c2619b3.m3063a()[0] > 90) {
            return null;
        }
        C2618a c2618a = new C2618a(c2619b.m3063a()[0], c2619b2.m3063a()[0], c2619b3.m3063a()[0], c2619b4.m3063a()[0]);
        m3075d(c2621dArr, c2618a);
        return c2618a;
    }

    /* renamed from: d */
    public final void m3075d(C2621d[] c2621dArr, C2618a c2618a) {
        for (int i2 = 0; i2 < c2621dArr.length; i2++) {
            C2621d c2621d = c2621dArr[i2];
            if (c2621dArr[i2] != null) {
                int i3 = c2621d.f7150d % 30;
                int i4 = c2621d.f7151e;
                if (i4 > c2618a.f7136e) {
                    c2621dArr[i2] = null;
                } else {
                    if (!this.f7161c) {
                        i4 += 2;
                    }
                    int i5 = i4 % 3;
                    if (i5 != 0) {
                        if (i5 != 1) {
                            if (i5 == 2 && i3 + 1 != c2618a.f7132a) {
                                c2621dArr[i2] = null;
                            }
                        } else if (i3 / 3 != c2618a.f7133b || i3 % 3 != c2618a.f7135d) {
                            c2621dArr[i2] = null;
                        }
                    } else if ((i3 * 3) + 1 != c2618a.f7134c) {
                        c2621dArr[i2] = null;
                    }
                }
            }
        }
    }

    @Override // p005b.p199l.p266d.p286z.p287d.C2624g
    public String toString() {
        return "IsLeft: " + this.f7161c + '\n' + super.toString();
    }
}
