package p005b.p199l.p200a.p201a;

import androidx.annotation.Nullable;
import com.google.android.exoplayer2.source.TrackGroupArray;
import p005b.p199l.p200a.p201a.p227k1.C2193p;
import p005b.p199l.p200a.p201a.p227k1.C2197t;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2107e0;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y;
import p005b.p199l.p200a.p201a.p245m1.AbstractC2259h;
import p005b.p199l.p200a.p201a.p245m1.C2258g;
import p005b.p199l.p200a.p201a.p245m1.C2260i;
import p005b.p199l.p200a.p201a.p245m1.InterfaceC2257f;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2288e;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.i0 */
/* loaded from: classes.dex */
public final class C2091i0 {

    /* renamed from: a */
    public final InterfaceC2201x f4398a;

    /* renamed from: b */
    public final Object f4399b;

    /* renamed from: c */
    public final InterfaceC2107e0[] f4400c;

    /* renamed from: d */
    public boolean f4401d;

    /* renamed from: e */
    public boolean f4402e;

    /* renamed from: f */
    public C2094j0 f4403f;

    /* renamed from: g */
    public final boolean[] f4404g;

    /* renamed from: h */
    public final AbstractC2397u[] f4405h;

    /* renamed from: i */
    public final AbstractC2259h f4406i;

    /* renamed from: j */
    public final InterfaceC2202y f4407j;

    /* renamed from: k */
    @Nullable
    public C2091i0 f4408k;

    /* renamed from: l */
    public TrackGroupArray f4409l;

    /* renamed from: m */
    public C2260i f4410m;

    /* renamed from: n */
    public long f4411n;

    public C2091i0(AbstractC2397u[] abstractC2397uArr, long j2, AbstractC2259h abstractC2259h, InterfaceC2288e interfaceC2288e, InterfaceC2202y interfaceC2202y, C2094j0 c2094j0, C2260i c2260i) {
        this.f4405h = abstractC2397uArr;
        this.f4411n = j2;
        this.f4406i = abstractC2259h;
        this.f4407j = interfaceC2202y;
        InterfaceC2202y.a aVar = c2094j0.f4415a;
        this.f4399b = aVar.f5247a;
        this.f4403f = c2094j0;
        this.f4409l = TrackGroupArray.f9396c;
        this.f4410m = c2260i;
        this.f4400c = new InterfaceC2107e0[abstractC2397uArr.length];
        this.f4404g = new boolean[abstractC2397uArr.length];
        long j3 = c2094j0.f4416b;
        long j4 = c2094j0.f4418d;
        InterfaceC2201x mo1789a = interfaceC2202y.mo1789a(aVar, interfaceC2288e, j3);
        if (j4 != -9223372036854775807L && j4 != Long.MIN_VALUE) {
            mo1789a = new C2193p(mo1789a, true, 0L, j4);
        }
        this.f4398a = mo1789a;
    }

    /* renamed from: a */
    public long m1735a(C2260i c2260i, long j2, boolean z, boolean[] zArr) {
        int i2 = 0;
        while (true) {
            boolean z2 = true;
            if (i2 >= c2260i.f5663a) {
                break;
            }
            boolean[] zArr2 = this.f4404g;
            if (z || !c2260i.m2165a(this.f4410m, i2)) {
                z2 = false;
            }
            zArr2[i2] = z2;
            i2++;
        }
        InterfaceC2107e0[] interfaceC2107e0Arr = this.f4400c;
        int i3 = 0;
        while (true) {
            AbstractC2397u[] abstractC2397uArr = this.f4405h;
            if (i3 >= abstractC2397uArr.length) {
                break;
            }
            if (abstractC2397uArr[i3].f6314c == 6) {
                interfaceC2107e0Arr[i3] = null;
            }
            i3++;
        }
        m1736b();
        this.f4410m = c2260i;
        m1737c();
        C2258g c2258g = c2260i.f5665c;
        long mo1767j = this.f4398a.mo1767j(c2258g.m2164a(), this.f4404g, this.f4400c, zArr, j2);
        InterfaceC2107e0[] interfaceC2107e0Arr2 = this.f4400c;
        int i4 = 0;
        while (true) {
            AbstractC2397u[] abstractC2397uArr2 = this.f4405h;
            if (i4 >= abstractC2397uArr2.length) {
                break;
            }
            if (abstractC2397uArr2[i4].f6314c == 6 && this.f4410m.m2166b(i4)) {
                interfaceC2107e0Arr2[i4] = new C2197t();
            }
            i4++;
        }
        this.f4402e = false;
        int i5 = 0;
        while (true) {
            InterfaceC2107e0[] interfaceC2107e0Arr3 = this.f4400c;
            if (i5 >= interfaceC2107e0Arr3.length) {
                return mo1767j;
            }
            if (interfaceC2107e0Arr3[i5] != null) {
                C4195m.m4771I(c2260i.m2166b(i5));
                if (this.f4405h[i5].f6314c != 6) {
                    this.f4402e = true;
                }
            } else {
                C4195m.m4771I(c2258g.f5660b[i5] == null);
            }
            i5++;
        }
    }

    /* renamed from: b */
    public final void m1736b() {
        if (!m1740f()) {
            return;
        }
        int i2 = 0;
        while (true) {
            C2260i c2260i = this.f4410m;
            if (i2 >= c2260i.f5663a) {
                return;
            }
            boolean m2166b = c2260i.m2166b(i2);
            InterfaceC2257f interfaceC2257f = this.f4410m.f5665c.f5660b[i2];
            if (m2166b && interfaceC2257f != null) {
                interfaceC2257f.mo2151d();
            }
            i2++;
        }
    }

    /* renamed from: c */
    public final void m1737c() {
        if (!m1740f()) {
            return;
        }
        int i2 = 0;
        while (true) {
            C2260i c2260i = this.f4410m;
            if (i2 >= c2260i.f5663a) {
                return;
            }
            boolean m2166b = c2260i.m2166b(i2);
            InterfaceC2257f interfaceC2257f = this.f4410m.f5665c.f5660b[i2];
            if (m2166b && interfaceC2257f != null) {
                interfaceC2257f.mo2145f();
            }
            i2++;
        }
    }

    /* renamed from: d */
    public long m1738d() {
        if (!this.f4401d) {
            return this.f4403f.f4416b;
        }
        long mo1763f = this.f4402e ? this.f4398a.mo1763f() : Long.MIN_VALUE;
        return mo1763f == Long.MIN_VALUE ? this.f4403f.f4419e : mo1763f;
    }

    /* renamed from: e */
    public boolean m1739e() {
        return this.f4401d && (!this.f4402e || this.f4398a.mo1763f() == Long.MIN_VALUE);
    }

    /* renamed from: f */
    public final boolean m1740f() {
        return this.f4408k == null;
    }

    /* renamed from: g */
    public void m1741g() {
        m1736b();
        long j2 = this.f4403f.f4418d;
        InterfaceC2202y interfaceC2202y = this.f4407j;
        InterfaceC2201x interfaceC2201x = this.f4398a;
        try {
            if (j2 == -9223372036854775807L || j2 == Long.MIN_VALUE) {
                interfaceC2202y.mo1791g(interfaceC2201x);
            } else {
                interfaceC2202y.mo1791g(((C2193p) interfaceC2201x).f5214c);
            }
        } catch (RuntimeException unused) {
        }
    }

    /* renamed from: h */
    public C2260i m1742h(float f2, AbstractC2404x0 abstractC2404x0) {
        C2260i mo2161b = this.f4406i.mo2161b(this.f4405h, this.f4409l, this.f4403f.f4415a, abstractC2404x0);
        for (InterfaceC2257f interfaceC2257f : mo2161b.f5665c.m2164a()) {
            if (interfaceC2257f != null) {
                interfaceC2257f.mo2147n(f2);
            }
        }
        return mo2161b;
    }
}
