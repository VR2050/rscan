package p005b.p199l.p200a.p201a;

import android.util.Pair;
import androidx.annotation.Nullable;
import java.util.Objects;
import p005b.p199l.p200a.p201a.AbstractC2404x0;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y;
import p005b.p199l.p200a.p201a.p227k1.p228j0.C2117a;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.k0 */
/* loaded from: classes.dex */
public final class C2097k0 {

    /* renamed from: c */
    public long f4425c;

    /* renamed from: e */
    public int f4427e;

    /* renamed from: f */
    public boolean f4428f;

    /* renamed from: g */
    @Nullable
    public C2091i0 f4429g;

    /* renamed from: h */
    @Nullable
    public C2091i0 f4430h;

    /* renamed from: i */
    @Nullable
    public C2091i0 f4431i;

    /* renamed from: j */
    public int f4432j;

    /* renamed from: k */
    @Nullable
    public Object f4433k;

    /* renamed from: l */
    public long f4434l;

    /* renamed from: a */
    public final AbstractC2404x0.b f4423a = new AbstractC2404x0.b();

    /* renamed from: b */
    public final AbstractC2404x0.c f4424b = new AbstractC2404x0.c();

    /* renamed from: d */
    public AbstractC2404x0 f4426d = AbstractC2404x0.f6366a;

    @Nullable
    /* renamed from: a */
    public C2091i0 m1743a() {
        C2091i0 c2091i0 = this.f4429g;
        if (c2091i0 == null) {
            return null;
        }
        if (c2091i0 == this.f4430h) {
            this.f4430h = c2091i0.f4408k;
        }
        c2091i0.m1741g();
        int i2 = this.f4432j - 1;
        this.f4432j = i2;
        if (i2 == 0) {
            this.f4431i = null;
            C2091i0 c2091i02 = this.f4429g;
            this.f4433k = c2091i02.f4399b;
            this.f4434l = c2091i02.f4403f.f4415a.f5250d;
        }
        C2091i0 c2091i03 = this.f4429g.f4408k;
        this.f4429g = c2091i03;
        return c2091i03;
    }

    /* renamed from: b */
    public void m1744b(boolean z) {
        C2091i0 c2091i0 = this.f4429g;
        if (c2091i0 != null) {
            this.f4433k = z ? c2091i0.f4399b : null;
            this.f4434l = c2091i0.f4403f.f4415a.f5250d;
            m1752j(c2091i0);
            c2091i0.m1741g();
        } else if (!z) {
            this.f4433k = null;
        }
        this.f4429g = null;
        this.f4431i = null;
        this.f4430h = null;
        this.f4432j = 0;
    }

    @Nullable
    /* renamed from: c */
    public final C2094j0 m1745c(C2091i0 c2091i0, long j2) {
        long j3;
        Object obj;
        long j4;
        long j5;
        long j6;
        C2094j0 c2094j0 = c2091i0.f4403f;
        long j7 = (c2091i0.f4411n + c2094j0.f4419e) - j2;
        long j8 = 0;
        if (c2094j0.f4420f) {
            int m2686d = this.f4426d.m2686d(this.f4426d.mo1831b(c2094j0.f4415a.f5247a), this.f4423a, this.f4424b, this.f4427e, this.f4428f);
            if (m2686d == -1) {
                return null;
            }
            int i2 = this.f4426d.mo1832g(m2686d, this.f4423a, true).f6368b;
            Object obj2 = this.f4423a.f6367a;
            long j9 = c2094j0.f4415a.f5250d;
            if (this.f4426d.m2690n(i2, this.f4424b).f6378g == m2686d) {
                Pair<Object, Long> m2689k = this.f4426d.m2689k(this.f4424b, this.f4423a, i2, -9223372036854775807L, Math.max(0L, j7));
                if (m2689k == null) {
                    return null;
                }
                Object obj3 = m2689k.first;
                long longValue = ((Long) m2689k.second).longValue();
                C2091i0 c2091i02 = c2091i0.f4408k;
                if (c2091i02 == null || !c2091i02.f4399b.equals(obj3)) {
                    j6 = this.f4425c;
                    this.f4425c = 1 + j6;
                } else {
                    j6 = c2091i02.f4403f.f4415a.f5250d;
                }
                j5 = longValue;
                j8 = -9223372036854775807L;
                j4 = j6;
                obj = obj3;
            } else {
                obj = obj2;
                j4 = j9;
                j5 = 0;
            }
            return m1746d(m1754l(obj, j5, j4), j8, j5);
        }
        InterfaceC2202y.a aVar = c2094j0.f4415a;
        this.f4426d.mo1929h(aVar.f5247a, this.f4423a);
        if (!aVar.m2024a()) {
            int m2694c = this.f4423a.m2694c(c2094j0.f4418d);
            if (m2694c == -1) {
                return m1748f(aVar.f5247a, c2094j0.f4419e, aVar.f5250d);
            }
            int m2696e = this.f4423a.m2696e(m2694c);
            if (this.f4423a.m2697f(m2694c, m2696e)) {
                return m1747e(aVar.f5247a, m2694c, m2696e, c2094j0.f4419e, aVar.f5250d);
            }
            return null;
        }
        int i3 = aVar.f5248b;
        C2117a.a[] aVarArr = this.f4423a.f6371e.f4609d;
        int i4 = aVarArr[i3].f4611a;
        if (i4 == -1) {
            return null;
        }
        int m1837a = aVarArr[i3].m1837a(aVar.f5249c);
        if (m1837a < i4) {
            if (this.f4423a.m2697f(i3, m1837a)) {
                return m1747e(aVar.f5247a, i3, m1837a, c2094j0.f4417c, aVar.f5250d);
            }
            return null;
        }
        long j10 = c2094j0.f4417c;
        if (j10 == -9223372036854775807L) {
            AbstractC2404x0 abstractC2404x0 = this.f4426d;
            AbstractC2404x0.c cVar = this.f4424b;
            AbstractC2404x0.b bVar = this.f4423a;
            Pair<Object, Long> m2689k2 = abstractC2404x0.m2689k(cVar, bVar, bVar.f6368b, -9223372036854775807L, Math.max(0L, j7));
            if (m2689k2 == null) {
                return null;
            }
            j3 = ((Long) m2689k2.second).longValue();
        } else {
            j3 = j10;
        }
        return m1748f(aVar.f5247a, j3, aVar.f5250d);
    }

    /* renamed from: d */
    public final C2094j0 m1746d(InterfaceC2202y.a aVar, long j2, long j3) {
        this.f4426d.mo1929h(aVar.f5247a, this.f4423a);
        if (!aVar.m2024a()) {
            return m1748f(aVar.f5247a, j3, aVar.f5250d);
        }
        if (this.f4423a.m2697f(aVar.f5248b, aVar.f5249c)) {
            return m1747e(aVar.f5247a, aVar.f5248b, aVar.f5249c, j2, aVar.f5250d);
        }
        return null;
    }

    /* renamed from: e */
    public final C2094j0 m1747e(Object obj, int i2, int i3, long j2, long j3) {
        InterfaceC2202y.a aVar = new InterfaceC2202y.a(obj, i2, i3, j3);
        long m2692a = this.f4426d.mo1929h(obj, this.f4423a).m2692a(i2, i3);
        if (i3 == this.f4423a.f6371e.f4609d[i2].m1837a(-1)) {
            Objects.requireNonNull(this.f4423a.f6371e);
        }
        return new C2094j0(aVar, 0L, j2, -9223372036854775807L, m2692a, false, false);
    }

    /* renamed from: f */
    public final C2094j0 m1748f(Object obj, long j2, long j3) {
        int m2693b = this.f4423a.m2693b(j2);
        InterfaceC2202y.a aVar = new InterfaceC2202y.a(obj, j3, m2693b);
        boolean z = !aVar.m2024a() && m2693b == -1;
        boolean m1750h = m1750h(aVar, z);
        long m2695d = m2693b != -1 ? this.f4423a.m2695d(m2693b) : -9223372036854775807L;
        return new C2094j0(aVar, j2, -9223372036854775807L, m2695d, (m2695d == -9223372036854775807L || m2695d == Long.MIN_VALUE) ? this.f4423a.f6369c : m2695d, z, m1750h);
    }

    /* renamed from: g */
    public C2094j0 m1749g(C2094j0 c2094j0) {
        long j2;
        InterfaceC2202y.a aVar = c2094j0.f4415a;
        boolean z = !aVar.m2024a() && aVar.f5251e == -1;
        boolean m1750h = m1750h(aVar, z);
        this.f4426d.mo1929h(c2094j0.f4415a.f5247a, this.f4423a);
        if (aVar.m2024a()) {
            j2 = this.f4423a.m2692a(aVar.f5248b, aVar.f5249c);
        } else {
            j2 = c2094j0.f4418d;
            if (j2 == -9223372036854775807L || j2 == Long.MIN_VALUE) {
                j2 = this.f4423a.f6369c;
            }
        }
        return new C2094j0(aVar, c2094j0.f4416b, c2094j0.f4417c, c2094j0.f4418d, j2, z, m1750h);
    }

    /* renamed from: h */
    public final boolean m1750h(InterfaceC2202y.a aVar, boolean z) {
        int mo1831b = this.f4426d.mo1831b(aVar.f5247a);
        if (this.f4426d.m2690n(this.f4426d.m2687f(mo1831b, this.f4423a).f6368b, this.f4424b).f6377f) {
            return false;
        }
        return (this.f4426d.m2686d(mo1831b, this.f4423a, this.f4424b, this.f4427e, this.f4428f) == -1) && z;
    }

    /* renamed from: i */
    public void m1751i(long j2) {
        C2091i0 c2091i0 = this.f4431i;
        if (c2091i0 != null) {
            C4195m.m4771I(c2091i0.m1740f());
            if (c2091i0.f4401d) {
                c2091i0.f4398a.mo1764g(j2 - c2091i0.f4411n);
            }
        }
    }

    /* renamed from: j */
    public boolean m1752j(C2091i0 c2091i0) {
        boolean z = false;
        C4195m.m4771I(c2091i0 != null);
        this.f4431i = c2091i0;
        while (true) {
            c2091i0 = c2091i0.f4408k;
            if (c2091i0 == null) {
                break;
            }
            if (c2091i0 == this.f4430h) {
                this.f4430h = this.f4429g;
                z = true;
            }
            c2091i0.m1741g();
            this.f4432j--;
        }
        C2091i0 c2091i02 = this.f4431i;
        if (c2091i02.f4408k != null) {
            c2091i02.m1736b();
            c2091i02.f4408k = null;
            c2091i02.m1737c();
        }
        return z;
    }

    /* renamed from: k */
    public InterfaceC2202y.a m1753k(Object obj, long j2) {
        long j3;
        int mo1831b;
        int i2 = this.f4426d.mo1929h(obj, this.f4423a).f6368b;
        Object obj2 = this.f4433k;
        if (obj2 == null || (mo1831b = this.f4426d.mo1831b(obj2)) == -1 || this.f4426d.m2687f(mo1831b, this.f4423a).f6368b != i2) {
            C2091i0 c2091i0 = this.f4429g;
            while (true) {
                if (c2091i0 == null) {
                    C2091i0 c2091i02 = this.f4429g;
                    while (true) {
                        if (c2091i02 != null) {
                            int mo1831b2 = this.f4426d.mo1831b(c2091i02.f4399b);
                            if (mo1831b2 != -1 && this.f4426d.m2687f(mo1831b2, this.f4423a).f6368b == i2) {
                                j3 = c2091i02.f4403f.f4415a.f5250d;
                                break;
                            }
                            c2091i02 = c2091i02.f4408k;
                        } else {
                            j3 = this.f4425c;
                            this.f4425c = 1 + j3;
                            if (this.f4429g == null) {
                                this.f4433k = obj;
                                this.f4434l = j3;
                            }
                        }
                    }
                } else {
                    if (c2091i0.f4399b.equals(obj)) {
                        j3 = c2091i0.f4403f.f4415a.f5250d;
                        break;
                    }
                    c2091i0 = c2091i0.f4408k;
                }
            }
        } else {
            j3 = this.f4434l;
        }
        return m1754l(obj, j2, j3);
    }

    /* renamed from: l */
    public final InterfaceC2202y.a m1754l(Object obj, long j2, long j3) {
        this.f4426d.mo1929h(obj, this.f4423a);
        int m2694c = this.f4423a.m2694c(j2);
        return m2694c == -1 ? new InterfaceC2202y.a(obj, j3, this.f4423a.m2693b(j2)) : new InterfaceC2202y.a(obj, m2694c, this.f4423a.m2696e(m2694c), j3);
    }

    /* renamed from: m */
    public final boolean m1755m() {
        C2091i0 c2091i0;
        C2091i0 c2091i02 = this.f4429g;
        if (c2091i02 == null) {
            return true;
        }
        int mo1831b = this.f4426d.mo1831b(c2091i02.f4399b);
        while (true) {
            mo1831b = this.f4426d.m2686d(mo1831b, this.f4423a, this.f4424b, this.f4427e, this.f4428f);
            while (true) {
                c2091i0 = c2091i02.f4408k;
                if (c2091i0 == null || c2091i02.f4403f.f4420f) {
                    break;
                }
                c2091i02 = c2091i0;
            }
            if (mo1831b == -1 || c2091i0 == null || this.f4426d.mo1831b(c2091i0.f4399b) != mo1831b) {
                break;
            }
            c2091i02 = c2091i0;
        }
        boolean m1752j = m1752j(c2091i02);
        c2091i02.f4403f = m1749g(c2091i02.f4403f);
        return !m1752j;
    }
}
