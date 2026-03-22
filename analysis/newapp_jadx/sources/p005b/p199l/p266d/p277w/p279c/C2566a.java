package p005b.p199l.p266d.p277w.p279c;

import p005b.p199l.p266d.C2536r;
import p005b.p199l.p266d.p274v.C2544b;
import p005b.p199l.p266d.p274v.p275l.C2554a;

/* renamed from: b.l.d.w.c.a */
/* loaded from: classes2.dex */
public final class C2566a {

    /* renamed from: a */
    public final C2544b f7010a;

    /* renamed from: b */
    public final C2554a f7011b;

    public C2566a(C2544b c2544b) {
        this.f7010a = c2544b;
        this.f7011b = new C2554a(c2544b, 10, c2544b.f6893c / 2, c2544b.f6894e / 2);
    }

    /* renamed from: b */
    public static C2536r m2992b(C2536r c2536r, float f2, float f3) {
        float f4 = c2536r.f6871a;
        float f5 = c2536r.f6872b;
        return new C2536r(f4 < f2 ? f4 - 1.0f : f4 + 1.0f, f5 < f3 ? f5 - 1.0f : f5 + 1.0f);
    }

    /* renamed from: c */
    public static C2536r m2993c(C2536r c2536r, C2536r c2536r2, int i2) {
        float f2 = c2536r2.f6871a;
        float f3 = c2536r.f6871a;
        float f4 = i2 + 1;
        float f5 = c2536r2.f6872b;
        float f6 = c2536r.f6872b;
        return new C2536r(f3 + ((f2 - f3) / f4), f6 + ((f5 - f6) / f4));
    }

    /* renamed from: a */
    public final boolean m2994a(C2536r c2536r) {
        float f2 = c2536r.f6871a;
        if (f2 < 0.0f) {
            return false;
        }
        C2544b c2544b = this.f7010a;
        if (f2 >= c2544b.f6893c) {
            return false;
        }
        float f3 = c2536r.f6872b;
        return f3 > 0.0f && f3 < ((float) c2544b.f6894e);
    }

    /* renamed from: d */
    public final int m2995d(C2536r c2536r, C2536r c2536r2) {
        int i2 = (int) c2536r.f6871a;
        int i3 = (int) c2536r.f6872b;
        int i4 = (int) c2536r2.f6871a;
        int i5 = (int) c2536r2.f6872b;
        int i6 = 0;
        boolean z = Math.abs(i5 - i3) > Math.abs(i4 - i2);
        if (z) {
            i2 = i3;
            i3 = i2;
            i4 = i5;
            i5 = i4;
        }
        int abs = Math.abs(i4 - i2);
        int abs2 = Math.abs(i5 - i3);
        int i7 = (-abs) / 2;
        int i8 = i3 < i5 ? 1 : -1;
        int i9 = i2 >= i4 ? -1 : 1;
        boolean m2958c = this.f7010a.m2958c(z ? i3 : i2, z ? i2 : i3);
        while (i2 != i4) {
            boolean m2958c2 = this.f7010a.m2958c(z ? i3 : i2, z ? i2 : i3);
            if (m2958c2 != m2958c) {
                i6++;
                m2958c = m2958c2;
            }
            i7 += abs2;
            if (i7 > 0) {
                if (i3 == i5) {
                    break;
                }
                i3 += i8;
                i7 -= abs;
            }
            i2 += i9;
        }
        return i6;
    }
}
