package p005b.p199l.p200a.p201a.p227k1.p230l0;

import android.os.SystemClock;
import androidx.annotation.CheckResult;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.source.dash.DashMediaSource;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.C2399v;
import p005b.p199l.p200a.p201a.C2400v0;
import p005b.p199l.p200a.p201a.p208f1.C1980c;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s;
import p005b.p199l.p200a.p201a.p208f1.p209a0.C1969d;
import p005b.p199l.p200a.p201a.p208f1.p211c0.C1984d;
import p005b.p199l.p200a.p201a.p208f1.p213e0.C2004a;
import p005b.p199l.p200a.p201a.p227k1.C2192o;
import p005b.p199l.p200a.p201a.p227k1.p229k0.AbstractC2120b;
import p005b.p199l.p200a.p201a.p227k1.p229k0.AbstractC2122d;
import p005b.p199l.p200a.p201a.p227k1.p229k0.AbstractC2130l;
import p005b.p199l.p200a.p201a.p227k1.p229k0.C2123e;
import p005b.p199l.p200a.p201a.p227k1.p229k0.C2124f;
import p005b.p199l.p200a.p201a.p227k1.p229k0.C2127i;
import p005b.p199l.p200a.p201a.p227k1.p229k0.C2129k;
import p005b.p199l.p200a.p201a.p227k1.p229k0.C2132n;
import p005b.p199l.p200a.p201a.p227k1.p229k0.InterfaceC2131m;
import p005b.p199l.p200a.p201a.p227k1.p230l0.C2143j;
import p005b.p199l.p200a.p201a.p227k1.p230l0.InterfaceC2136c;
import p005b.p199l.p200a.p201a.p227k1.p230l0.p231k.AbstractC2152i;
import p005b.p199l.p200a.p201a.p227k1.p230l0.p231k.C2144a;
import p005b.p199l.p200a.p201a.p227k1.p230l0.p231k.C2145b;
import p005b.p199l.p200a.p201a.p227k1.p230l0.p231k.C2151h;
import p005b.p199l.p200a.p201a.p245m1.InterfaceC2257f;
import p005b.p199l.p200a.p201a.p248o1.C2324p;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2283b0;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2291f0;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.C2357q;

/* renamed from: b.l.a.a.k1.l0.h */
/* loaded from: classes.dex */
public class C2141h implements InterfaceC2136c {

    /* renamed from: a */
    public final InterfaceC2283b0 f4731a;

    /* renamed from: b */
    public final int[] f4732b;

    /* renamed from: c */
    public final int f4733c;

    /* renamed from: d */
    public final InterfaceC2321m f4734d;

    /* renamed from: e */
    public final long f4735e;

    /* renamed from: f */
    @Nullable
    public final C2143j.c f4736f;

    /* renamed from: g */
    public final b[] f4737g;

    /* renamed from: h */
    public InterfaceC2257f f4738h;

    /* renamed from: i */
    public C2145b f4739i;

    /* renamed from: j */
    public int f4740j;

    /* renamed from: k */
    public IOException f4741k;

    /* renamed from: l */
    public boolean f4742l;

    /* renamed from: m */
    public long f4743m;

    /* renamed from: b.l.a.a.k1.l0.h$a */
    public static final class a implements InterfaceC2136c.a {

        /* renamed from: a */
        public final InterfaceC2321m.a f4744a;

        public a(InterfaceC2321m.a aVar) {
            this.f4744a = aVar;
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.p230l0.InterfaceC2136c.a
        /* renamed from: a */
        public InterfaceC2136c mo1864a(InterfaceC2283b0 interfaceC2283b0, C2145b c2145b, int i2, int[] iArr, InterfaceC2257f interfaceC2257f, int i3, long j2, boolean z, List<Format> list, @Nullable C2143j.c cVar, @Nullable InterfaceC2291f0 interfaceC2291f0) {
            InterfaceC2321m createDataSource = this.f4744a.createDataSource();
            if (interfaceC2291f0 != null) {
                createDataSource.addTransferListener(interfaceC2291f0);
            }
            return new C2141h(interfaceC2283b0, c2145b, i2, iArr, interfaceC2257f, i3, createDataSource, j2, 1, z, list, cVar);
        }
    }

    /* renamed from: b.l.a.a.k1.l0.h$c */
    public static final class c extends AbstractC2120b {
        public c(b bVar, long j2, long j3) {
            super(j2, j3);
        }
    }

    public C2141h(InterfaceC2283b0 interfaceC2283b0, C2145b c2145b, int i2, int[] iArr, InterfaceC2257f interfaceC2257f, int i3, InterfaceC2321m interfaceC2321m, long j2, int i4, boolean z, List<Format> list, @Nullable C2143j.c cVar) {
        this.f4731a = interfaceC2283b0;
        this.f4739i = c2145b;
        this.f4732b = iArr;
        this.f4738h = interfaceC2257f;
        this.f4733c = i3;
        this.f4734d = interfaceC2321m;
        this.f4740j = i2;
        this.f4735e = j2;
        this.f4736f = cVar;
        long m2668a = C2399v.m2668a(c2145b.m1889c(i2));
        this.f4743m = -9223372036854775807L;
        ArrayList<AbstractC2152i> m1874j = m1874j();
        this.f4737g = new b[interfaceC2257f.length()];
        for (int i5 = 0; i5 < this.f4737g.length; i5++) {
            this.f4737g[i5] = new b(m2668a, i3, m1874j.get(interfaceC2257f.mo2153g(i5)), z, list, cVar);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.p229k0.InterfaceC2126h
    /* renamed from: a */
    public void mo1854a() {
        IOException iOException = this.f4741k;
        if (iOException != null) {
            throw iOException;
        }
        this.f4731a.mo2180a();
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.p230l0.InterfaceC2136c
    /* renamed from: b */
    public void mo1862b(InterfaceC2257f interfaceC2257f) {
        this.f4738h = interfaceC2257f;
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x0035 A[RETURN] */
    @Override // p005b.p199l.p200a.p201a.p227k1.p229k0.InterfaceC2126h
    /* renamed from: d */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean mo1855d(p005b.p199l.p200a.p201a.p227k1.p229k0.AbstractC2122d r10, boolean r11, java.lang.Exception r12, long r13) {
        /*
            r9 = this;
            r0 = 0
            if (r11 != 0) goto L4
            return r0
        L4:
            b.l.a.a.k1.l0.j$c r11 = r9.f4736f
            r1 = -9223372036854775807(0x8000000000000001, double:-4.9E-324)
            r3 = 1
            if (r11 == 0) goto L36
            b.l.a.a.k1.l0.j r11 = p005b.p199l.p200a.p201a.p227k1.p230l0.C2143j.this
            b.l.a.a.k1.l0.k.b r4 = r11.f4763i
            boolean r4 = r4.f4783d
            if (r4 != 0) goto L17
            goto L32
        L17:
            boolean r4 = r11.f4767m
            if (r4 == 0) goto L1c
            goto L30
        L1c:
            long r4 = r11.f4765k
            int r6 = (r4 > r1 ? 1 : (r4 == r1 ? 0 : -1))
            if (r6 == 0) goto L2a
            long r6 = r10.f4628f
            int r8 = (r4 > r6 ? 1 : (r4 == r6 ? 0 : -1))
            if (r8 >= 0) goto L2a
            r4 = 1
            goto L2b
        L2a:
            r4 = 0
        L2b:
            if (r4 == 0) goto L32
            r11.m1886a()
        L30:
            r11 = 1
            goto L33
        L32:
            r11 = 0
        L33:
            if (r11 == 0) goto L36
            return r3
        L36:
            b.l.a.a.k1.l0.k.b r11 = r9.f4739i
            boolean r11 = r11.f4783d
            if (r11 != 0) goto L78
            boolean r11 = r10 instanceof p005b.p199l.p200a.p201a.p227k1.p229k0.AbstractC2130l
            if (r11 == 0) goto L78
            boolean r11 = r12 instanceof p005b.p199l.p200a.p201a.p248o1.InterfaceC2333y.d
            if (r11 == 0) goto L78
            b.l.a.a.o1.y$d r12 = (p005b.p199l.p200a.p201a.p248o1.InterfaceC2333y.d) r12
            int r11 = r12.f6016c
            r12 = 404(0x194, float:5.66E-43)
            if (r11 != r12) goto L78
            b.l.a.a.k1.l0.h$b[] r11 = r9.f4737g
            b.l.a.a.m1.f r12 = r9.f4738h
            com.google.android.exoplayer2.Format r4 = r10.f4625c
            int r12 = r12.mo2154i(r4)
            r11 = r11[r12]
            int r12 = r11.m1880e()
            r4 = -1
            if (r12 == r4) goto L78
            if (r12 == 0) goto L78
            long r4 = r11.m1878c()
            long r11 = (long) r12
            long r4 = r4 + r11
            r11 = 1
            long r4 = r4 - r11
            r11 = r10
            b.l.a.a.k1.k0.l r11 = (p005b.p199l.p200a.p201a.p227k1.p229k0.AbstractC2130l) r11
            long r11 = r11.mo1860c()
            int r6 = (r11 > r4 ? 1 : (r11 == r4 ? 0 : -1))
            if (r6 <= 0) goto L78
            r9.f4742l = r3
            return r3
        L78:
            int r11 = (r13 > r1 ? 1 : (r13 == r1 ? 0 : -1))
            if (r11 == 0) goto L8b
            b.l.a.a.m1.f r11 = r9.f4738h
            com.google.android.exoplayer2.Format r10 = r10.f4625c
            int r10 = r11.mo2154i(r10)
            boolean r10 = r11.mo2150c(r10, r13)
            if (r10 == 0) goto L8b
            r0 = 1
        L8b:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p227k1.p230l0.C2141h.mo1855d(b.l.a.a.k1.k0.d, boolean, java.lang.Exception, long):boolean");
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.p229k0.InterfaceC2126h
    /* renamed from: e */
    public long mo1856e(long j2, C2400v0 c2400v0) {
        for (b bVar : this.f4737g) {
            InterfaceC2139f interfaceC2139f = bVar.f4747c;
            if (interfaceC2139f != null) {
                long mo1870d = interfaceC2139f.mo1870d(j2, bVar.f4748d) + bVar.f4749e;
                long m1883h = bVar.m1883h(mo1870d);
                return C2344d0.m2313E(j2, c2400v0, m1883h, (m1883h >= j2 || mo1870d >= ((long) (bVar.m1880e() + (-1)))) ? m1883h : bVar.m1883h(mo1870d + 1));
            }
        }
        return j2;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.p230l0.InterfaceC2136c
    /* renamed from: f */
    public void mo1863f(C2145b c2145b, int i2) {
        try {
            this.f4739i = c2145b;
            this.f4740j = i2;
            long m1890d = c2145b.m1890d(i2);
            ArrayList<AbstractC2152i> m1874j = m1874j();
            for (int i3 = 0; i3 < this.f4737g.length; i3++) {
                AbstractC2152i abstractC2152i = m1874j.get(this.f4738h.mo2153g(i3));
                b[] bVarArr = this.f4737g;
                bVarArr[i3] = bVarArr[i3].m1876a(m1890d, abstractC2152i);
            }
        } catch (C2192o e2) {
            this.f4741k = e2;
        }
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.p229k0.InterfaceC2126h
    /* renamed from: g */
    public int mo1857g(long j2, List<? extends AbstractC2130l> list) {
        return (this.f4741k != null || this.f4738h.length() < 2) ? list.size() : this.f4738h.mo2146h(j2, list);
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.p229k0.InterfaceC2126h
    /* renamed from: h */
    public void mo1858h(AbstractC2122d abstractC2122d) {
        C2123e c2123e;
        InterfaceC2050q interfaceC2050q;
        if (abstractC2122d instanceof C2129k) {
            int mo2154i = this.f4738h.mo2154i(((C2129k) abstractC2122d).f4625c);
            b[] bVarArr = this.f4737g;
            b bVar = bVarArr[mo2154i];
            if (bVar.f4747c == null && (interfaceC2050q = (c2123e = bVar.f4745a).f4638k) != null) {
                AbstractC2152i abstractC2152i = bVar.f4746b;
                bVarArr[mo2154i] = new b(bVar.f4748d, abstractC2152i, c2123e, bVar.f4749e, new C2140g((C1980c) interfaceC2050q, abstractC2152i.f4825c));
            }
        }
        C2143j.c cVar = this.f4736f;
        if (cVar != null) {
            C2143j c2143j = C2143j.this;
            long j2 = c2143j.f4765k;
            if (j2 != -9223372036854775807L || abstractC2122d.f4629g > j2) {
                c2143j.f4765k = abstractC2122d.f4629g;
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.p229k0.InterfaceC2126h
    /* renamed from: i */
    public void mo1859i(long j2, long j3, List<? extends AbstractC2130l> list, C2124f c2124f) {
        AbstractC2122d c2127i;
        C2124f c2124f2;
        InterfaceC2131m[] interfaceC2131mArr;
        int i2;
        int i3;
        long j4;
        boolean z;
        boolean z2;
        if (this.f4741k != null) {
            return;
        }
        long j5 = j3 - j2;
        C2145b c2145b = this.f4739i;
        long j6 = c2145b.f4783d && (this.f4743m > (-9223372036854775807L) ? 1 : (this.f4743m == (-9223372036854775807L) ? 0 : -1)) != 0 ? this.f4743m - j2 : -9223372036854775807L;
        long m2668a = C2399v.m2668a(this.f4739i.m1887a(this.f4740j).f4811b) + C2399v.m2668a(c2145b.f4780a) + j3;
        C2143j.c cVar = this.f4736f;
        if (cVar != null) {
            C2143j c2143j = C2143j.this;
            C2145b c2145b2 = c2143j.f4763i;
            if (!c2145b2.f4783d) {
                z2 = false;
            } else if (c2143j.f4767m) {
                z2 = true;
            } else {
                Map.Entry<Long, Long> ceilingEntry = c2143j.f4762h.ceilingEntry(Long.valueOf(c2145b2.f4787h));
                if (ceilingEntry == null || ceilingEntry.getValue().longValue() >= m2668a) {
                    z = false;
                } else {
                    long longValue = ceilingEntry.getKey().longValue();
                    c2143j.f4764j = longValue;
                    DashMediaSource dashMediaSource = DashMediaSource.this;
                    long j7 = dashMediaSource.f9413N;
                    if (j7 == -9223372036854775807L || j7 < longValue) {
                        dashMediaSource.f9413N = longValue;
                    }
                    z = true;
                }
                if (z) {
                    c2143j.m1886a();
                }
                z2 = z;
            }
            if (z2) {
                return;
            }
        }
        long elapsedRealtime = (this.f4735e != 0 ? SystemClock.elapsedRealtime() + this.f4735e : System.currentTimeMillis()) * 1000;
        AbstractC2130l abstractC2130l = list.isEmpty() ? null : (AbstractC2130l) C1499a.m611d(list, 1);
        int length = this.f4738h.length();
        InterfaceC2131m[] interfaceC2131mArr2 = new InterfaceC2131m[length];
        int i4 = 0;
        while (i4 < length) {
            b bVar = this.f4737g[i4];
            if (bVar.f4747c == null) {
                interfaceC2131mArr2[i4] = InterfaceC2131m.f4691a;
                interfaceC2131mArr = interfaceC2131mArr2;
                i2 = i4;
                i3 = length;
                j4 = elapsedRealtime;
            } else {
                long m1877b = bVar.m1877b(this.f4739i, this.f4740j, elapsedRealtime);
                long m1879d = bVar.m1879d(this.f4739i, this.f4740j, elapsedRealtime);
                interfaceC2131mArr = interfaceC2131mArr2;
                i2 = i4;
                i3 = length;
                j4 = elapsedRealtime;
                long m1875k = m1875k(bVar, abstractC2130l, j3, m1877b, m1879d);
                if (m1875k < m1877b) {
                    interfaceC2131mArr[i2] = InterfaceC2131m.f4691a;
                } else {
                    interfaceC2131mArr[i2] = new c(bVar, m1875k, m1879d);
                }
            }
            i4 = i2 + 1;
            interfaceC2131mArr2 = interfaceC2131mArr;
            length = i3;
            elapsedRealtime = j4;
        }
        long j8 = elapsedRealtime;
        this.f4738h.mo1942j(j2, j5, j6, list, interfaceC2131mArr2);
        b bVar2 = this.f4737g[this.f4738h.mo1941b()];
        C2123e c2123e = bVar2.f4745a;
        if (c2123e != null) {
            AbstractC2152i abstractC2152i = bVar2.f4746b;
            C2151h c2151h = c2123e.f4639l == null ? abstractC2152i.f4827e : null;
            C2151h mo1919j = bVar2.f4747c == null ? abstractC2152i.mo1919j() : null;
            if (c2151h != null || mo1919j != null) {
                InterfaceC2321m interfaceC2321m = this.f4734d;
                Format mo2156l = this.f4738h.mo2156l();
                int mo1943m = this.f4738h.mo1943m();
                Object mo1944o = this.f4738h.mo1944o();
                String str = bVar2.f4746b.f4824b;
                if (c2151h == null || (mo1919j = c2151h.m1915a(mo1919j, str)) != null) {
                    c2151h = mo1919j;
                }
                c2124f.f4647a = new C2129k(interfaceC2321m, new C2324p(c2151h.m1916b(str), c2151h.f4819a, c2151h.f4820b, bVar2.f4746b.mo1917h()), mo2156l, mo1943m, mo1944o, bVar2.f4745a);
                return;
            }
        }
        long j9 = bVar2.f4748d;
        boolean z3 = j9 != -9223372036854775807L;
        if (bVar2.m1880e() == 0) {
            c2124f.f4648b = z3;
            return;
        }
        long m1877b2 = bVar2.m1877b(this.f4739i, this.f4740j, j8);
        long m1879d2 = bVar2.m1879d(this.f4739i, this.f4740j, j8);
        this.f4743m = this.f4739i.f4783d ? bVar2.m1881f(m1879d2) : -9223372036854775807L;
        long m1875k2 = m1875k(bVar2, abstractC2130l, j3, m1877b2, m1879d2);
        if (m1875k2 < m1877b2) {
            this.f4741k = new C2192o();
            return;
        }
        if (m1875k2 > m1879d2 || (this.f4742l && m1875k2 >= m1879d2)) {
            c2124f.f4648b = z3;
            return;
        }
        if (z3 && bVar2.m1883h(m1875k2) >= j9) {
            c2124f.f4648b = true;
            return;
        }
        int min = (int) Math.min(1, (m1879d2 - m1875k2) + 1);
        if (j9 != -9223372036854775807L) {
            while (min > 1 && bVar2.m1883h((min + m1875k2) - 1) >= j9) {
                min--;
            }
        }
        long j10 = list.isEmpty() ? j3 : -9223372036854775807L;
        InterfaceC2321m interfaceC2321m2 = this.f4734d;
        int i5 = this.f4733c;
        Format mo2156l2 = this.f4738h.mo2156l();
        int mo1943m2 = this.f4738h.mo1943m();
        Object mo1944o2 = this.f4738h.mo1944o();
        AbstractC2152i abstractC2152i2 = bVar2.f4746b;
        long mo1867a = bVar2.f4747c.mo1867a(m1875k2 - bVar2.f4749e);
        C2151h mo1869c = bVar2.f4747c.mo1869c(m1875k2 - bVar2.f4749e);
        String str2 = abstractC2152i2.f4824b;
        if (bVar2.f4745a == null) {
            c2127i = new C2132n(interfaceC2321m2, new C2324p(mo1869c.m1916b(str2), mo1869c.f4819a, mo1869c.f4820b, abstractC2152i2.mo1917h()), mo2156l2, mo1943m2, mo1944o2, mo1867a, bVar2.m1881f(m1875k2), m1875k2, i5, mo2156l2);
            c2124f2 = c2124f;
        } else {
            int i6 = 1;
            C2151h c2151h2 = mo1869c;
            int i7 = 1;
            while (i7 < min) {
                C2151h m1915a = c2151h2.m1915a(bVar2.f4747c.mo1869c((i7 + m1875k2) - bVar2.f4749e), str2);
                if (m1915a == null) {
                    break;
                }
                i6++;
                i7++;
                c2151h2 = m1915a;
            }
            long m1881f = bVar2.m1881f((i6 + m1875k2) - 1);
            long j11 = bVar2.f4748d;
            c2127i = new C2127i(interfaceC2321m2, new C2324p(c2151h2.m1916b(str2), c2151h2.f4819a, c2151h2.f4820b, abstractC2152i2.mo1917h()), mo2156l2, mo1943m2, mo1944o2, mo1867a, m1881f, j10, (j11 == -9223372036854775807L || j11 > m1881f) ? -9223372036854775807L : j11, m1875k2, i6, -abstractC2152i2.f4825c, bVar2.f4745a);
            c2124f2 = c2124f;
        }
        c2124f2.f4647a = c2127i;
    }

    /* renamed from: j */
    public final ArrayList<AbstractC2152i> m1874j() {
        List<C2144a> list = this.f4739i.m1887a(this.f4740j).f4812c;
        ArrayList<AbstractC2152i> arrayList = new ArrayList<>();
        for (int i2 : this.f4732b) {
            arrayList.addAll(list.get(i2).f4777c);
        }
        return arrayList;
    }

    /* renamed from: k */
    public final long m1875k(b bVar, @Nullable AbstractC2130l abstractC2130l, long j2, long j3, long j4) {
        return abstractC2130l != null ? abstractC2130l.mo1860c() : C2344d0.m2330h(bVar.f4747c.mo1870d(j2, bVar.f4748d) + bVar.f4749e, j3, j4);
    }

    /* renamed from: b.l.a.a.k1.l0.h$b */
    public static final class b {

        /* renamed from: a */
        @Nullable
        public final C2123e f4745a;

        /* renamed from: b */
        public final AbstractC2152i f4746b;

        /* renamed from: c */
        @Nullable
        public final InterfaceC2139f f4747c;

        /* renamed from: d */
        public final long f4748d;

        /* renamed from: e */
        public final long f4749e;

        public b(long j2, AbstractC2152i abstractC2152i, @Nullable C2123e c2123e, long j3, @Nullable InterfaceC2139f interfaceC2139f) {
            this.f4748d = j2;
            this.f4746b = abstractC2152i;
            this.f4749e = j3;
            this.f4745a = c2123e;
            this.f4747c = interfaceC2139f;
        }

        @CheckResult
        /* renamed from: a */
        public b m1876a(long j2, AbstractC2152i abstractC2152i) {
            long mo1870d;
            InterfaceC2139f mo1918i = this.f4746b.mo1918i();
            InterfaceC2139f mo1918i2 = abstractC2152i.mo1918i();
            if (mo1918i == null) {
                return new b(j2, abstractC2152i, this.f4745a, this.f4749e, mo1918i);
            }
            if (!mo1918i.mo1871e()) {
                return new b(j2, abstractC2152i, this.f4745a, this.f4749e, mo1918i2);
            }
            int mo1873g = mo1918i.mo1873g(j2);
            if (mo1873g == 0) {
                return new b(j2, abstractC2152i, this.f4745a, this.f4749e, mo1918i2);
            }
            long mo1872f = mo1918i.mo1872f();
            long mo1867a = mo1918i.mo1867a(mo1872f);
            long j3 = (mo1873g + mo1872f) - 1;
            long mo1868b = mo1918i.mo1868b(j3, j2) + mo1918i.mo1867a(j3);
            long mo1872f2 = mo1918i2.mo1872f();
            long mo1867a2 = mo1918i2.mo1867a(mo1872f2);
            long j4 = this.f4749e;
            if (mo1868b == mo1867a2) {
                mo1870d = ((j3 + 1) - mo1872f2) + j4;
            } else {
                if (mo1868b < mo1867a2) {
                    throw new C2192o();
                }
                mo1870d = mo1867a2 < mo1867a ? j4 - (mo1918i2.mo1870d(mo1867a, j2) - mo1872f) : (mo1918i.mo1870d(mo1867a2, j2) - mo1872f2) + j4;
            }
            return new b(j2, abstractC2152i, this.f4745a, mo1870d, mo1918i2);
        }

        /* renamed from: b */
        public long m1877b(C2145b c2145b, int i2, long j2) {
            if (m1880e() != -1 || c2145b.f4785f == -9223372036854775807L) {
                return m1878c();
            }
            return Math.max(m1878c(), m1882g(((j2 - C2399v.m2668a(c2145b.f4780a)) - C2399v.m2668a(c2145b.f4791l.get(i2).f4811b)) - C2399v.m2668a(c2145b.f4785f)));
        }

        /* renamed from: c */
        public long m1878c() {
            return this.f4747c.mo1872f() + this.f4749e;
        }

        /* renamed from: d */
        public long m1879d(C2145b c2145b, int i2, long j2) {
            int m1880e = m1880e();
            return (m1880e == -1 ? m1882g((j2 - C2399v.m2668a(c2145b.f4780a)) - C2399v.m2668a(c2145b.f4791l.get(i2).f4811b)) : m1878c() + m1880e) - 1;
        }

        /* renamed from: e */
        public int m1880e() {
            return this.f4747c.mo1873g(this.f4748d);
        }

        /* renamed from: f */
        public long m1881f(long j2) {
            return this.f4747c.mo1868b(j2 - this.f4749e, this.f4748d) + this.f4747c.mo1867a(j2 - this.f4749e);
        }

        /* renamed from: g */
        public long m1882g(long j2) {
            return this.f4747c.mo1870d(j2, this.f4748d) + this.f4749e;
        }

        /* renamed from: h */
        public long m1883h(long j2) {
            return this.f4747c.mo1867a(j2 - this.f4749e);
        }

        public b(long j2, int i2, AbstractC2152i abstractC2152i, boolean z, List<Format> list, @Nullable InterfaceC2052s interfaceC2052s) {
            InterfaceC2041h c1984d;
            C2123e c2123e;
            String str = abstractC2152i.f4823a.f9244k;
            if (C2357q.m2546i(str) || "application/ttml+xml".equals(str)) {
                c2123e = null;
            } else {
                if ("application/x-rawcc".equals(str)) {
                    c1984d = new C2004a(abstractC2152i.f4823a);
                } else {
                    if (str.startsWith("video/webm") || str.startsWith("audio/webm") || str.startsWith("application/webm")) {
                        c1984d = new C1969d(1);
                    } else {
                        c1984d = new C1984d(z ? 4 : 0, null, null, list, interfaceC2052s);
                    }
                }
                c2123e = new C2123e(c1984d, i2, abstractC2152i.f4823a);
            }
            InterfaceC2139f mo1918i = abstractC2152i.mo1918i();
            this.f4748d = j2;
            this.f4746b = abstractC2152i;
            this.f4749e = 0L;
            this.f4745a = c2123e;
            this.f4747c = mo1918i;
        }
    }
}
