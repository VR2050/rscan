package p005b.p199l.p200a.p201a.p227k1.p229k0;

import p005b.p199l.p200a.p201a.p208f1.C2036g;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s;
import p005b.p199l.p200a.p201a.p227k1.C2105d0;
import p005b.p199l.p200a.p201a.p227k1.p229k0.C2123e;

/* renamed from: b.l.a.a.k1.k0.c */
/* loaded from: classes.dex */
public final class C2121c implements C2123e.b {

    /* renamed from: a */
    public final int[] f4621a;

    /* renamed from: b */
    public final C2105d0[] f4622b;

    public C2121c(int[] iArr, C2105d0[] c2105d0Arr) {
        this.f4621a = iArr;
        this.f4622b = c2105d0Arr;
    }

    /* renamed from: a */
    public void m1839a(long j2) {
        for (C2105d0 c2105d0 : this.f4622b) {
            if (c2105d0 != null && c2105d0.f4542C != j2) {
                c2105d0.f4542C = j2;
                c2105d0.f4540A = true;
            }
        }
    }

    /* renamed from: b */
    public InterfaceC2052s m1840b(int i2, int i3) {
        int i4 = 0;
        while (true) {
            int[] iArr = this.f4621a;
            if (i4 >= iArr.length) {
                return new C2036g();
            }
            if (i3 == iArr[i4]) {
                return this.f4622b[i4];
            }
            i4++;
        }
    }
}
