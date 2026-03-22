package p005b.p199l.p266d.p267a0.p268c;

import p005b.p199l.p266d.C2525g;
import p005b.p199l.p266d.p274v.C2544b;

/* renamed from: b.l.d.a0.c.a */
/* loaded from: classes2.dex */
public final class C2500a {

    /* renamed from: a */
    public final C2544b f6723a;

    /* renamed from: b */
    public C2509j f6724b;

    /* renamed from: c */
    public C2506g f6725c;

    /* renamed from: d */
    public boolean f6726d;

    public C2500a(C2544b c2544b) {
        int i2 = c2544b.f6894e;
        if (i2 < 21 || (i2 & 3) != 1) {
            throw C2525g.m2925a();
        }
        this.f6723a = c2544b;
    }

    /* renamed from: a */
    public final int m2869a(int i2, int i3, int i4) {
        return this.f6726d ? this.f6723a.m2958c(i3, i2) : this.f6723a.m2958c(i2, i3) ? (i4 << 1) | 1 : i4 << 1;
    }

    /* renamed from: b */
    public void m2870b() {
        int i2 = 0;
        while (i2 < this.f6723a.f6893c) {
            int i3 = i2 + 1;
            int i4 = i3;
            while (true) {
                C2544b c2544b = this.f6723a;
                if (i4 < c2544b.f6894e) {
                    if (c2544b.m2958c(i2, i4) != this.f6723a.m2958c(i4, i2)) {
                        this.f6723a.m2957a(i4, i2);
                        this.f6723a.m2957a(i2, i4);
                    }
                    i4++;
                }
            }
            i2 = i3;
        }
    }

    /* renamed from: c */
    public C2506g m2871c() {
        C2506g c2506g = this.f6725c;
        if (c2506g != null) {
            return c2506g;
        }
        int i2 = 0;
        int i3 = 0;
        for (int i4 = 0; i4 < 6; i4++) {
            i3 = m2869a(i4, 8, i3);
        }
        int m2869a = m2869a(8, 7, m2869a(8, 8, m2869a(7, 8, i3)));
        for (int i5 = 5; i5 >= 0; i5--) {
            m2869a = m2869a(8, i5, m2869a);
        }
        int i6 = this.f6723a.f6894e;
        int i7 = i6 - 7;
        for (int i8 = i6 - 1; i8 >= i7; i8--) {
            i2 = m2869a(8, i8, i2);
        }
        for (int i9 = i6 - 8; i9 < i6; i9++) {
            i2 = m2869a(i9, 8, i2);
        }
        C2506g m2884a = C2506g.m2884a(m2869a, i2);
        if (m2884a == null) {
            m2884a = C2506g.m2884a(m2869a ^ 21522, i2 ^ 21522);
        }
        this.f6725c = m2884a;
        if (m2884a != null) {
            return m2884a;
        }
        throw C2525g.m2925a();
    }

    /* renamed from: d */
    public C2509j m2872d() {
        C2509j c2509j = this.f6724b;
        if (c2509j != null) {
            return c2509j;
        }
        int i2 = this.f6723a.f6894e;
        int i3 = (i2 - 17) / 4;
        if (i3 <= 6) {
            return C2509j.m2889d(i3);
        }
        int i4 = i2 - 11;
        int i5 = 0;
        int i6 = 0;
        for (int i7 = 5; i7 >= 0; i7--) {
            for (int i8 = i2 - 9; i8 >= i4; i8--) {
                i6 = m2869a(i8, i7, i6);
            }
        }
        C2509j m2888b = C2509j.m2888b(i6);
        if (m2888b != null && m2888b.m2890c() == i2) {
            this.f6724b = m2888b;
            return m2888b;
        }
        for (int i9 = 5; i9 >= 0; i9--) {
            for (int i10 = i2 - 9; i10 >= i4; i10--) {
                i5 = m2869a(i9, i10, i5);
            }
        }
        C2509j m2888b2 = C2509j.m2888b(i5);
        if (m2888b2 == null || m2888b2.m2890c() != i2) {
            throw C2525g.m2925a();
        }
        this.f6724b = m2888b2;
        return m2888b2;
    }

    /* renamed from: e */
    public void m2873e() {
        if (this.f6725c == null) {
            return;
        }
        EnumC2502c enumC2502c = EnumC2502c.values()[this.f6725c.f6749c];
        C2544b c2544b = this.f6723a;
        enumC2502c.m2875b(c2544b, c2544b.f6894e);
    }
}
