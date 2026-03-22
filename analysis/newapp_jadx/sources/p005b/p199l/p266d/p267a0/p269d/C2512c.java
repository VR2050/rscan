package p005b.p199l.p266d.p267a0.p269d;

import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p199l.p266d.C2529k;
import p005b.p199l.p266d.C2536r;
import p005b.p199l.p266d.InterfaceC2537s;
import p005b.p199l.p266d.p274v.C2544b;

/* renamed from: b.l.d.a0.d.c */
/* loaded from: classes2.dex */
public class C2512c {

    /* renamed from: a */
    public final C2544b f6784a;

    /* renamed from: b */
    public InterfaceC2537s f6785b;

    public C2512c(C2544b c2544b) {
        this.f6784a = c2544b;
    }

    /* renamed from: a */
    public final float m2895a(C2536r c2536r, C2536r c2536r2) {
        float m2898d = m2898d((int) c2536r.f6871a, (int) c2536r.f6872b, (int) c2536r2.f6871a, (int) c2536r2.f6872b);
        float m2898d2 = m2898d((int) c2536r2.f6871a, (int) c2536r2.f6872b, (int) c2536r.f6871a, (int) c2536r.f6872b);
        return Float.isNaN(m2898d) ? m2898d2 / 7.0f : Float.isNaN(m2898d2) ? m2898d / 7.0f : (m2898d + m2898d2) / 14.0f;
    }

    /* renamed from: b */
    public final C2510a m2896b(float f2, int i2, int i3, float f3) {
        C2510a m2894c;
        C2510a m2894c2;
        int i4 = (int) (f3 * f2);
        int max = Math.max(0, i2 - i4);
        int min = Math.min(this.f6784a.f6893c - 1, i2 + i4) - max;
        float f4 = 3.0f * f2;
        if (min < f4) {
            throw C2529k.f6843f;
        }
        int max2 = Math.max(0, i3 - i4);
        int min2 = Math.min(this.f6784a.f6894e - 1, i3 + i4) - max2;
        if (min2 < f4) {
            throw C2529k.f6843f;
        }
        C2511b c2511b = new C2511b(this.f6784a, max, max2, min, min2, f2, this.f6785b);
        int i5 = c2511b.f6777c;
        int i6 = c2511b.f6780f;
        int i7 = c2511b.f6779e + i5;
        int i8 = (i6 / 2) + c2511b.f6778d;
        int[] iArr = new int[3];
        for (int i9 = 0; i9 < i6; i9++) {
            int i10 = ((i9 & 1) == 0 ? (i9 + 1) / 2 : -((i9 + 1) / 2)) + i8;
            iArr[0] = 0;
            iArr[1] = 0;
            iArr[2] = 0;
            int i11 = i5;
            while (i11 < i7 && !c2511b.f6775a.m2958c(i11, i10)) {
                i11++;
            }
            int i12 = 0;
            while (i11 < i7) {
                if (!c2511b.f6775a.m2958c(i11, i10)) {
                    if (i12 == 1) {
                        i12++;
                    }
                    iArr[i12] = iArr[i12] + 1;
                } else if (i12 == 1) {
                    iArr[1] = iArr[1] + 1;
                } else if (i12 != 2) {
                    i12++;
                    iArr[i12] = iArr[i12] + 1;
                } else {
                    if (c2511b.m2893b(iArr) && (m2894c2 = c2511b.m2894c(iArr, i10, i11)) != null) {
                        return m2894c2;
                    }
                    iArr[0] = iArr[2];
                    iArr[1] = 1;
                    iArr[2] = 0;
                    i12 = 1;
                }
                i11++;
            }
            if (c2511b.m2893b(iArr) && (m2894c = c2511b.m2894c(iArr, i10, i7)) != null) {
                return m2894c;
            }
        }
        if (c2511b.f6776b.isEmpty()) {
            throw C2529k.f6843f;
        }
        return c2511b.f6776b.get(0);
    }

    /* renamed from: c */
    public final float m2897c(int i2, int i3, int i4, int i5) {
        int i6;
        int i7;
        int i8;
        int i9;
        int i10;
        C2512c c2512c;
        boolean z;
        boolean z2;
        int i11 = 1;
        boolean z3 = Math.abs(i5 - i3) > Math.abs(i4 - i2);
        if (z3) {
            i7 = i2;
            i6 = i3;
            i9 = i4;
            i8 = i5;
        } else {
            i6 = i2;
            i7 = i3;
            i8 = i4;
            i9 = i5;
        }
        int abs = Math.abs(i8 - i6);
        int abs2 = Math.abs(i9 - i7);
        int i12 = (-abs) / 2;
        int i13 = i6 < i8 ? 1 : -1;
        int i14 = i7 < i9 ? 1 : -1;
        int i15 = i8 + i13;
        int i16 = i6;
        int i17 = i7;
        int i18 = 0;
        while (true) {
            if (i16 == i15) {
                i10 = i15;
                break;
            }
            int i19 = z3 ? i17 : i16;
            int i20 = z3 ? i16 : i17;
            if (i18 == i11) {
                c2512c = this;
                z = z3;
                i10 = i15;
                z2 = true;
            } else {
                c2512c = this;
                z = z3;
                i10 = i15;
                z2 = false;
            }
            if (z2 == c2512c.f6784a.m2958c(i19, i20)) {
                if (i18 == 2) {
                    return C2354n.m2431T(i16, i17, i6, i7);
                }
                i18++;
            }
            i12 += abs2;
            if (i12 > 0) {
                if (i17 == i9) {
                    break;
                }
                i17 += i14;
                i12 -= abs;
            }
            i16 += i13;
            i15 = i10;
            z3 = z;
            i11 = 1;
        }
        if (i18 == 2) {
            return C2354n.m2431T(i10, i9, i6, i7);
        }
        return Float.NaN;
    }

    /* renamed from: d */
    public final float m2898d(int i2, int i3, int i4, int i5) {
        float f2;
        float f3;
        float m2897c = m2897c(i2, i3, i4, i5);
        int i6 = i2 - (i4 - i2);
        int i7 = 0;
        if (i6 < 0) {
            f2 = i2 / (i2 - i6);
            i6 = 0;
        } else {
            int i8 = this.f6784a.f6893c;
            if (i6 >= i8) {
                float f4 = ((i8 - 1) - i2) / (i6 - i2);
                int i9 = i8 - 1;
                f2 = f4;
                i6 = i9;
            } else {
                f2 = 1.0f;
            }
        }
        float f5 = i3;
        int i10 = (int) (f5 - ((i5 - i3) * f2));
        if (i10 < 0) {
            f3 = f5 / (i3 - i10);
        } else {
            int i11 = this.f6784a.f6894e;
            if (i10 >= i11) {
                f3 = ((i11 - 1) - i3) / (i10 - i3);
                i7 = i11 - 1;
            } else {
                i7 = i10;
                f3 = 1.0f;
            }
        }
        return (m2897c(i2, i3, (int) (((i6 - i2) * f3) + i2), i7) + m2897c) - 1.0f;
    }
}
