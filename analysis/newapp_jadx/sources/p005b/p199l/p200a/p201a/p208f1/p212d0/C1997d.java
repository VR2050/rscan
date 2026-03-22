package p005b.p199l.p200a.p201a.p208f1.p212d0;

import java.util.Arrays;
import p005b.p199l.p200a.p201a.p208f1.C2003e;
import p005b.p199l.p200a.p201a.p250p1.C2360t;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.f1.d0.d */
/* loaded from: classes.dex */
public final class C1997d {

    /* renamed from: a */
    public final C1998e f3747a = new C1998e();

    /* renamed from: b */
    public final C2360t f3748b = new C2360t(new byte[65025], 0);

    /* renamed from: c */
    public int f3749c = -1;

    /* renamed from: d */
    public int f3750d;

    /* renamed from: e */
    public boolean f3751e;

    /* renamed from: a */
    public final int m1554a(int i2) {
        int i3;
        int i4 = 0;
        this.f3750d = 0;
        do {
            int i5 = this.f3750d;
            int i6 = i2 + i5;
            C1998e c1998e = this.f3747a;
            if (i6 >= c1998e.f3755d) {
                break;
            }
            int[] iArr = c1998e.f3758g;
            this.f3750d = i5 + 1;
            i3 = iArr[i5 + i2];
            i4 += i3;
        } while (i3 == 255);
        return i4;
    }

    /* renamed from: b */
    public boolean m1555b(C2003e c2003e) {
        int i2;
        C4195m.m4771I(c2003e != null);
        if (this.f3751e) {
            this.f3751e = false;
            this.f3748b.m2592x();
        }
        while (!this.f3751e) {
            if (this.f3749c < 0) {
                if (!this.f3747a.m1556a(c2003e, true)) {
                    return false;
                }
                C1998e c1998e = this.f3747a;
                int i3 = c1998e.f3756e;
                if ((c1998e.f3753b & 1) == 1 && this.f3748b.f6135c == 0) {
                    i3 += m1554a(0);
                    i2 = this.f3750d + 0;
                } else {
                    i2 = 0;
                }
                c2003e.m1569i(i3);
                this.f3749c = i2;
            }
            int m1554a = m1554a(this.f3749c);
            int i4 = this.f3749c + this.f3750d;
            if (m1554a > 0) {
                C2360t c2360t = this.f3748b;
                byte[] bArr = c2360t.f6133a;
                int length = bArr.length;
                int i5 = c2360t.f6135c;
                if (length < i5 + m1554a) {
                    c2360t.f6133a = Arrays.copyOf(bArr, i5 + m1554a);
                }
                C2360t c2360t2 = this.f3748b;
                c2003e.m1568h(c2360t2.f6133a, c2360t2.f6135c, m1554a, false);
                C2360t c2360t3 = this.f3748b;
                c2360t3.m2566B(c2360t3.f6135c + m1554a);
                this.f3751e = this.f3747a.f3758g[i4 + (-1)] != 255;
            }
            if (i4 == this.f3747a.f3755d) {
                i4 = -1;
            }
            this.f3749c = i4;
        }
        return true;
    }
}
