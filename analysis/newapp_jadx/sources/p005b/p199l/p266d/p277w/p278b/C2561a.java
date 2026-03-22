package p005b.p199l.p266d.p277w.p278b;

import p005b.p199l.p266d.C2525g;
import p005b.p199l.p266d.p274v.C2544b;

/* renamed from: b.l.d.w.b.a */
/* loaded from: classes2.dex */
public final class C2561a {

    /* renamed from: a */
    public final C2544b f6987a;

    /* renamed from: b */
    public final C2544b f6988b;

    /* renamed from: c */
    public final C2565e f6989c;

    public C2561a(C2544b c2544b) {
        int i2;
        int i3 = c2544b.f6894e;
        if (i3 < 8 || i3 > 144 || (i3 & 1) != 0) {
            throw C2525g.m2925a();
        }
        int i4 = c2544b.f6893c;
        C2565e[] c2565eArr = C2565e.f6998a;
        if ((i3 & 1) != 0 || (i4 & 1) != 0) {
            throw C2525g.m2925a();
        }
        for (C2565e c2565e : C2565e.f6998a) {
            int i5 = c2565e.f7000c;
            if (i5 == i3 && (i2 = c2565e.f7001d) == i4) {
                this.f6989c = c2565e;
                if (c2544b.f6894e != i5) {
                    throw new IllegalArgumentException("Dimension of bitMatrix must match the version size");
                }
                int i6 = c2565e.f7002e;
                int i7 = c2565e.f7003f;
                int i8 = i5 / i6;
                int i9 = i2 / i7;
                C2544b c2544b2 = new C2544b(i9 * i7, i8 * i6);
                for (int i10 = 0; i10 < i8; i10++) {
                    int i11 = i10 * i6;
                    for (int i12 = 0; i12 < i9; i12++) {
                        int i13 = i12 * i7;
                        for (int i14 = 0; i14 < i6; i14++) {
                            int i15 = ((i6 + 2) * i10) + 1 + i14;
                            int i16 = i11 + i14;
                            for (int i17 = 0; i17 < i7; i17++) {
                                if (c2544b.m2958c(((i7 + 2) * i12) + 1 + i17, i15)) {
                                    c2544b2.m2962h(i13 + i17, i16);
                                }
                            }
                        }
                    }
                }
                this.f6987a = c2544b2;
                this.f6988b = new C2544b(c2544b2.f6893c, c2544b2.f6894e);
                return;
            }
        }
        throw C2525g.m2925a();
    }

    /* renamed from: a */
    public final boolean m2987a(int i2, int i3, int i4, int i5) {
        if (i2 < 0) {
            i2 += i4;
            i3 += 4 - ((i4 + 4) & 7);
        }
        if (i3 < 0) {
            i3 += i5;
            i2 += 4 - ((i5 + 4) & 7);
        }
        this.f6988b.m2962h(i3, i2);
        return this.f6987a.m2958c(i3, i2);
    }

    /* renamed from: b */
    public final int m2988b(int i2, int i3, int i4, int i5) {
        int i6 = i2 - 2;
        int i7 = i3 - 2;
        int i8 = (m2987a(i6, i7, i4, i5) ? 1 : 0) << 1;
        int i9 = i3 - 1;
        if (m2987a(i6, i9, i4, i5)) {
            i8 |= 1;
        }
        int i10 = i8 << 1;
        int i11 = i2 - 1;
        if (m2987a(i11, i7, i4, i5)) {
            i10 |= 1;
        }
        int i12 = i10 << 1;
        if (m2987a(i11, i9, i4, i5)) {
            i12 |= 1;
        }
        int i13 = i12 << 1;
        if (m2987a(i11, i3, i4, i5)) {
            i13 |= 1;
        }
        int i14 = i13 << 1;
        if (m2987a(i2, i7, i4, i5)) {
            i14 |= 1;
        }
        int i15 = i14 << 1;
        if (m2987a(i2, i9, i4, i5)) {
            i15 |= 1;
        }
        int i16 = i15 << 1;
        return m2987a(i2, i3, i4, i5) ? i16 | 1 : i16;
    }
}
