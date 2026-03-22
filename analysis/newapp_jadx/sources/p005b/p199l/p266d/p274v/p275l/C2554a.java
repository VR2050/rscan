package p005b.p199l.p266d.p274v.p275l;

import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p199l.p266d.C2529k;
import p005b.p199l.p266d.C2536r;
import p005b.p199l.p266d.p274v.C2544b;

/* renamed from: b.l.d.v.l.a */
/* loaded from: classes2.dex */
public final class C2554a {

    /* renamed from: a */
    public final C2544b f6958a;

    /* renamed from: b */
    public final int f6959b;

    /* renamed from: c */
    public final int f6960c;

    /* renamed from: d */
    public final int f6961d;

    /* renamed from: e */
    public final int f6962e;

    /* renamed from: f */
    public final int f6963f;

    /* renamed from: g */
    public final int f6964g;

    public C2554a(C2544b c2544b, int i2, int i3, int i4) {
        this.f6958a = c2544b;
        int i5 = c2544b.f6894e;
        this.f6959b = i5;
        int i6 = c2544b.f6893c;
        this.f6960c = i6;
        int i7 = i2 / 2;
        int i8 = i3 - i7;
        this.f6961d = i8;
        int i9 = i3 + i7;
        this.f6962e = i9;
        int i10 = i4 - i7;
        this.f6964g = i10;
        int i11 = i4 + i7;
        this.f6963f = i11;
        if (i10 < 0 || i8 < 0 || i11 >= i5 || i9 >= i6) {
            throw C2529k.f6843f;
        }
    }

    /* renamed from: a */
    public final boolean m2972a(int i2, int i3, int i4, boolean z) {
        if (z) {
            while (i2 <= i3) {
                if (this.f6958a.m2958c(i2, i4)) {
                    return true;
                }
                i2++;
            }
            return false;
        }
        while (i2 <= i3) {
            if (this.f6958a.m2958c(i4, i2)) {
                return true;
            }
            i2++;
        }
        return false;
    }

    /* renamed from: b */
    public C2536r[] m2973b() {
        boolean z;
        int i2 = this.f6961d;
        int i3 = this.f6962e;
        int i4 = this.f6964g;
        int i5 = this.f6963f;
        boolean z2 = true;
        boolean z3 = false;
        boolean z4 = false;
        boolean z5 = false;
        boolean z6 = false;
        while (z2) {
            boolean z7 = true;
            boolean z8 = false;
            while (true) {
                if ((z7 || !z3) && i3 < this.f6960c) {
                    z7 = m2972a(i4, i5, i3, false);
                    if (z7) {
                        i3++;
                        z3 = true;
                        z8 = true;
                    } else if (!z3) {
                        i3++;
                    }
                }
            }
            if (i3 < this.f6960c) {
                boolean z9 = true;
                while (true) {
                    if ((z9 || !z4) && i5 < this.f6959b) {
                        z9 = m2972a(i2, i3, i5, true);
                        if (z9) {
                            i5++;
                            z4 = true;
                            z8 = true;
                        } else if (!z4) {
                            i5++;
                        }
                    }
                }
                if (i5 < this.f6959b) {
                    boolean z10 = true;
                    while (true) {
                        if ((z10 || !z5) && i2 >= 0) {
                            z10 = m2972a(i4, i5, i2, false);
                            if (z10) {
                                i2--;
                                z5 = true;
                                z8 = true;
                            } else if (!z5) {
                                i2--;
                            }
                        }
                    }
                    if (i2 >= 0) {
                        z2 = z8;
                        boolean z11 = true;
                        while (true) {
                            if ((z11 || !z6) && i4 >= 0) {
                                z11 = m2972a(i2, i3, i4, true);
                                if (z11) {
                                    i4--;
                                    z2 = true;
                                    z6 = true;
                                } else if (!z6) {
                                    i4--;
                                }
                            }
                        }
                        if (i4 < 0) {
                        }
                    }
                }
            }
            z = true;
            break;
        }
        z = false;
        if (z) {
            throw C2529k.f6843f;
        }
        int i6 = i3 - i2;
        C2536r c2536r = null;
        C2536r c2536r2 = null;
        for (int i7 = 1; c2536r2 == null && i7 < i6; i7++) {
            c2536r2 = m2974c(i2, i5 - i7, i2 + i7, i5);
        }
        if (c2536r2 == null) {
            throw C2529k.f6843f;
        }
        C2536r c2536r3 = null;
        for (int i8 = 1; c2536r3 == null && i8 < i6; i8++) {
            c2536r3 = m2974c(i2, i4 + i8, i2 + i8, i4);
        }
        if (c2536r3 == null) {
            throw C2529k.f6843f;
        }
        C2536r c2536r4 = null;
        for (int i9 = 1; c2536r4 == null && i9 < i6; i9++) {
            c2536r4 = m2974c(i3, i4 + i9, i3 - i9, i4);
        }
        if (c2536r4 == null) {
            throw C2529k.f6843f;
        }
        for (int i10 = 1; c2536r == null && i10 < i6; i10++) {
            c2536r = m2974c(i3, i5 - i10, i3 - i10, i5);
        }
        if (c2536r == null) {
            throw C2529k.f6843f;
        }
        float f2 = c2536r.f6871a;
        float f3 = c2536r.f6872b;
        float f4 = c2536r2.f6871a;
        float f5 = c2536r2.f6872b;
        float f6 = c2536r4.f6871a;
        float f7 = c2536r4.f6872b;
        float f8 = c2536r3.f6871a;
        float f9 = c2536r3.f6872b;
        return f2 < ((float) this.f6960c) / 2.0f ? new C2536r[]{new C2536r(f8 - 1.0f, f9 + 1.0f), new C2536r(f4 + 1.0f, f5 + 1.0f), new C2536r(f6 - 1.0f, f7 - 1.0f), new C2536r(f2 + 1.0f, f3 - 1.0f)} : new C2536r[]{new C2536r(f8 + 1.0f, f9 + 1.0f), new C2536r(f4 + 1.0f, f5 - 1.0f), new C2536r(f6 - 1.0f, f7 + 1.0f), new C2536r(f2 - 1.0f, f3 - 1.0f)};
    }

    /* renamed from: c */
    public final C2536r m2974c(float f2, float f3, float f4, float f5) {
        int m2520u1 = C2354n.m2520u1(C2354n.m2428S(f2, f3, f4, f5));
        float f6 = m2520u1;
        float f7 = (f4 - f2) / f6;
        float f8 = (f5 - f3) / f6;
        for (int i2 = 0; i2 < m2520u1; i2++) {
            float f9 = i2;
            int m2520u12 = C2354n.m2520u1((f9 * f7) + f2);
            int m2520u13 = C2354n.m2520u1((f9 * f8) + f3);
            if (this.f6958a.m2958c(m2520u12, m2520u13)) {
                return new C2536r(m2520u12, m2520u13);
            }
        }
        return null;
    }
}
