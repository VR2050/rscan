package p005b.p199l.p200a.p201a.p208f1.p209a0;

import p005b.p199l.p200a.p201a.p208f1.C2003e;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.f1.a0.e */
/* loaded from: classes.dex */
public final class C1970e {

    /* renamed from: a */
    public final C2360t f3541a = new C2360t(8);

    /* renamed from: b */
    public int f3542b;

    /* renamed from: a */
    public final long m1496a(C2003e c2003e) {
        int i2 = 0;
        c2003e.m1565e(this.f3541a.f6133a, 0, 1, false);
        int i3 = this.f3541a.f6133a[0] & 255;
        if (i3 == 0) {
            return Long.MIN_VALUE;
        }
        int i4 = 128;
        int i5 = 0;
        while ((i3 & i4) == 0) {
            i4 >>= 1;
            i5++;
        }
        int i6 = i3 & (~i4);
        c2003e.m1565e(this.f3541a.f6133a, 1, i5, false);
        while (i2 < i5) {
            i2++;
            i6 = (this.f3541a.f6133a[i2] & 255) + (i6 << 8);
        }
        this.f3542b = i5 + 1 + this.f3542b;
        return i6;
    }
}
