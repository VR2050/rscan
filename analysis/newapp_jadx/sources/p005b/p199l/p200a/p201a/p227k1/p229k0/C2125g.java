package p005b.p199l.p200a.p201a.p227k1.p229k0;

import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import p005b.p199l.p200a.p201a.C1964f0;
import p005b.p199l.p200a.p201a.p204c1.C1945e;
import p005b.p199l.p200a.p201a.p205d1.InterfaceC1954e;
import p005b.p199l.p200a.p201a.p227k1.C2105d0;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2107e0;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z;
import p005b.p199l.p200a.p201a.p227k1.p229k0.InterfaceC2126h;
import p005b.p199l.p200a.p201a.p227k1.p230l0.C2138e;
import p005b.p199l.p200a.p201a.p227k1.p230l0.C2143j;
import p005b.p199l.p200a.p201a.p248o1.C2281a0;
import p005b.p199l.p200a.p201a.p248o1.C2287d0;
import p005b.p199l.p200a.p201a.p248o1.C2324p;
import p005b.p199l.p200a.p201a.p248o1.C2331w;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2288e;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2334z;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.k1.k0.g */
/* loaded from: classes.dex */
public class C2125g<T extends InterfaceC2126h> implements InterfaceC2107e0, InterfaceC2109f0, C2281a0.b<AbstractC2122d>, C2281a0.f {

    /* renamed from: c */
    public final int f4649c;

    /* renamed from: e */
    @Nullable
    public final int[] f4650e;

    /* renamed from: f */
    @Nullable
    public final Format[] f4651f;

    /* renamed from: g */
    public final boolean[] f4652g;

    /* renamed from: h */
    public final T f4653h;

    /* renamed from: i */
    public final InterfaceC2109f0.a<C2125g<T>> f4654i;

    /* renamed from: j */
    public final InterfaceC2203z.a f4655j;

    /* renamed from: k */
    public final InterfaceC2334z f4656k;

    /* renamed from: l */
    public final C2281a0 f4657l = new C2281a0("Loader:ChunkSampleStream");

    /* renamed from: m */
    public final C2124f f4658m = new C2124f();

    /* renamed from: n */
    public final ArrayList<AbstractC2119a> f4659n;

    /* renamed from: o */
    public final List<AbstractC2119a> f4660o;

    /* renamed from: p */
    public final C2105d0 f4661p;

    /* renamed from: q */
    public final C2105d0[] f4662q;

    /* renamed from: r */
    public final C2121c f4663r;

    /* renamed from: s */
    public Format f4664s;

    /* renamed from: t */
    @Nullable
    public b<T> f4665t;

    /* renamed from: u */
    public long f4666u;

    /* renamed from: v */
    public long f4667v;

    /* renamed from: w */
    public int f4668w;

    /* renamed from: x */
    public long f4669x;

    /* renamed from: y */
    public boolean f4670y;

    /* renamed from: b.l.a.a.k1.k0.g$a */
    public final class a implements InterfaceC2107e0 {

        /* renamed from: c */
        public final C2125g<T> f4671c;

        /* renamed from: e */
        public final C2105d0 f4672e;

        /* renamed from: f */
        public final int f4673f;

        /* renamed from: g */
        public boolean f4674g;

        public a(C2125g<T> c2125g, C2105d0 c2105d0, int i2) {
            this.f4671c = c2125g;
            this.f4672e = c2105d0;
            this.f4673f = i2;
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2107e0
        /* renamed from: a */
        public void mo1786a() {
        }

        /* renamed from: b */
        public final void m1852b() {
            if (this.f4674g) {
                return;
            }
            C2125g c2125g = C2125g.this;
            InterfaceC2203z.a aVar = c2125g.f4655j;
            int[] iArr = c2125g.f4650e;
            int i2 = this.f4673f;
            aVar.m2026b(iArr[i2], c2125g.f4651f[i2], 0, null, c2125g.f4667v);
            this.f4674g = true;
        }

        /* renamed from: c */
        public void m1853c() {
            C4195m.m4771I(C2125g.this.f4652g[this.f4673f]);
            C2125g.this.f4652g[this.f4673f] = false;
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2107e0
        /* renamed from: i */
        public int mo1787i(C1964f0 c1964f0, C1945e c1945e, boolean z) {
            if (C2125g.this.m1849x()) {
                return -3;
            }
            m1852b();
            C2105d0 c2105d0 = this.f4672e;
            C2125g c2125g = C2125g.this;
            return c2105d0.m1803A(c1964f0, c1945e, z, c2125g.f4670y, c2125g.f4669x);
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2107e0
        public boolean isReady() {
            return !C2125g.this.m1849x() && this.f4672e.m1825u(C2125g.this.f4670y);
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2107e0
        /* renamed from: o */
        public int mo1788o(long j2) {
            if (C2125g.this.m1849x()) {
                return 0;
            }
            m1852b();
            return (!C2125g.this.f4670y || j2 <= this.f4672e.m1818n()) ? this.f4672e.m1809e(j2) : this.f4672e.m1810f();
        }
    }

    /* renamed from: b.l.a.a.k1.k0.g$b */
    public interface b<T extends InterfaceC2126h> {
    }

    public C2125g(int i2, @Nullable int[] iArr, @Nullable Format[] formatArr, T t, InterfaceC2109f0.a<C2125g<T>> aVar, InterfaceC2288e interfaceC2288e, long j2, InterfaceC1954e<?> interfaceC1954e, InterfaceC2334z interfaceC2334z, InterfaceC2203z.a aVar2) {
        this.f4649c = i2;
        this.f4650e = iArr;
        this.f4651f = formatArr;
        this.f4653h = t;
        this.f4654i = aVar;
        this.f4655j = aVar2;
        this.f4656k = interfaceC2334z;
        ArrayList<AbstractC2119a> arrayList = new ArrayList<>();
        this.f4659n = arrayList;
        this.f4660o = Collections.unmodifiableList(arrayList);
        int i3 = 0;
        int length = iArr == null ? 0 : iArr.length;
        this.f4662q = new C2105d0[length];
        this.f4652g = new boolean[length];
        int i4 = length + 1;
        int[] iArr2 = new int[i4];
        C2105d0[] c2105d0Arr = new C2105d0[i4];
        C2105d0 c2105d0 = new C2105d0(interfaceC2288e, interfaceC1954e);
        this.f4661p = c2105d0;
        iArr2[0] = i2;
        c2105d0Arr[0] = c2105d0;
        while (i3 < length) {
            C2105d0 c2105d02 = new C2105d0(interfaceC2288e, InterfaceC1954e.f3383a);
            this.f4662q[i3] = c2105d02;
            int i5 = i3 + 1;
            c2105d0Arr[i5] = c2105d02;
            iArr2[i5] = iArr[i3];
            i3 = i5;
        }
        this.f4663r = new C2121c(iArr2, c2105d0Arr);
        this.f4666u = j2;
        this.f4667v = j2;
    }

    /* renamed from: A */
    public void m1843A(@Nullable b<T> bVar) {
        this.f4665t = bVar;
        this.f4661p.m1830z();
        for (C2105d0 c2105d0 : this.f4662q) {
            c2105d0.m1830z();
        }
        this.f4657l.m2185g(this);
    }

    /* renamed from: B */
    public void m1844B(long j2) {
        AbstractC2119a abstractC2119a;
        boolean m1807E;
        this.f4667v = j2;
        if (m1849x()) {
            this.f4666u = j2;
            return;
        }
        for (int i2 = 0; i2 < this.f4659n.size(); i2++) {
            abstractC2119a = this.f4659n.get(i2);
            long j3 = abstractC2119a.f4628f;
            if (j3 == j2 && abstractC2119a.f4616j == -9223372036854775807L) {
                break;
            } else {
                if (j3 > j2) {
                    break;
                }
            }
        }
        abstractC2119a = null;
        if (abstractC2119a != null) {
            C2105d0 c2105d0 = this.f4661p;
            int i3 = abstractC2119a.f4619m[0];
            synchronized (c2105d0) {
                c2105d0.m1806D();
                int i4 = c2105d0.f4559p;
                if (i3 >= i4 && i3 <= c2105d0.f4558o + i4) {
                    c2105d0.f4561r = i3 - i4;
                    m1807E = true;
                }
                m1807E = false;
            }
            this.f4669x = 0L;
        } else {
            m1807E = this.f4661p.m1807E(j2, j2 < mo1759b());
            this.f4669x = this.f4667v;
        }
        if (m1807E) {
            this.f4668w = m1851z(this.f4661p.m1820p(), 0);
            for (C2105d0 c2105d02 : this.f4662q) {
                c2105d02.m1807E(j2, true);
            }
            return;
        }
        this.f4666u = j2;
        this.f4670y = false;
        this.f4659n.clear();
        this.f4668w = 0;
        if (this.f4657l.m2183e()) {
            this.f4657l.m2181b();
            return;
        }
        this.f4657l.f5771e = null;
        this.f4661p.m1805C(false);
        for (C2105d0 c2105d03 : this.f4662q) {
            c2105d03.m1805C(false);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2107e0
    /* renamed from: a */
    public void mo1786a() {
        this.f4657l.m2184f(Integer.MIN_VALUE);
        this.f4661p.m1827w();
        if (this.f4657l.m2183e()) {
            return;
        }
        this.f4653h.mo1854a();
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0
    /* renamed from: b */
    public long mo1759b() {
        if (m1849x()) {
            return this.f4666u;
        }
        if (this.f4670y) {
            return Long.MIN_VALUE;
        }
        return m1847v().f4629g;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0
    /* renamed from: c */
    public boolean mo1760c(long j2) {
        List<AbstractC2119a> list;
        long j3;
        int i2 = 0;
        if (this.f4670y || this.f4657l.m2183e() || this.f4657l.m2182d()) {
            return false;
        }
        boolean m1849x = m1849x();
        if (m1849x) {
            list = Collections.emptyList();
            j3 = this.f4666u;
        } else {
            list = this.f4660o;
            j3 = m1847v().f4629g;
        }
        this.f4653h.mo1859i(j2, j3, list, this.f4658m);
        C2124f c2124f = this.f4658m;
        boolean z = c2124f.f4648b;
        AbstractC2122d abstractC2122d = c2124f.f4647a;
        c2124f.f4647a = null;
        c2124f.f4648b = false;
        if (z) {
            this.f4666u = -9223372036854775807L;
            this.f4670y = true;
            return true;
        }
        if (abstractC2122d == null) {
            return false;
        }
        if (abstractC2122d instanceof AbstractC2119a) {
            AbstractC2119a abstractC2119a = (AbstractC2119a) abstractC2122d;
            if (m1849x) {
                long j4 = abstractC2119a.f4628f;
                long j5 = this.f4666u;
                if (j4 == j5) {
                    j5 = 0;
                }
                this.f4669x = j5;
                this.f4666u = -9223372036854775807L;
            }
            C2121c c2121c = this.f4663r;
            abstractC2119a.f4618l = c2121c;
            int[] iArr = new int[c2121c.f4622b.length];
            while (true) {
                C2105d0[] c2105d0Arr = c2121c.f4622b;
                if (i2 >= c2105d0Arr.length) {
                    break;
                }
                if (c2105d0Arr[i2] != null) {
                    iArr[i2] = c2105d0Arr[i2].m1823s();
                }
                i2++;
            }
            abstractC2119a.f4619m = iArr;
            this.f4659n.add(abstractC2119a);
        } else if (abstractC2122d instanceof C2129k) {
            ((C2129k) abstractC2122d).f4687k = this.f4663r;
        }
        this.f4655j.m2038n(abstractC2122d.f4623a, abstractC2122d.f4624b, this.f4649c, abstractC2122d.f4625c, abstractC2122d.f4626d, abstractC2122d.f4627e, abstractC2122d.f4628f, abstractC2122d.f4629g, this.f4657l.m2186h(abstractC2122d, this, ((C2331w) this.f4656k).m2280b(abstractC2122d.f4624b)));
        return true;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0
    /* renamed from: d */
    public boolean mo1761d() {
        return this.f4657l.m2183e();
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0
    /* renamed from: f */
    public long mo1763f() {
        if (this.f4670y) {
            return Long.MIN_VALUE;
        }
        if (m1849x()) {
            return this.f4666u;
        }
        long j2 = this.f4667v;
        AbstractC2119a m1847v = m1847v();
        if (!m1847v.mo1861d()) {
            if (this.f4659n.size() > 1) {
                m1847v = this.f4659n.get(r2.size() - 2);
            } else {
                m1847v = null;
            }
        }
        if (m1847v != null) {
            j2 = Math.max(j2, m1847v.f4629g);
        }
        return Math.max(j2, this.f4661p.m1818n());
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0
    /* renamed from: g */
    public void mo1764g(long j2) {
        int size;
        int mo1857g;
        if (this.f4657l.m2183e() || this.f4657l.m2182d() || m1849x() || (size = this.f4659n.size()) <= (mo1857g = this.f4653h.mo1857g(j2, this.f4660o))) {
            return;
        }
        while (true) {
            if (mo1857g >= size) {
                mo1857g = size;
                break;
            } else if (!m1848w(mo1857g)) {
                break;
            } else {
                mo1857g++;
            }
        }
        if (mo1857g == size) {
            return;
        }
        long j3 = m1847v().f4629g;
        AbstractC2119a m1845t = m1845t(mo1857g);
        if (this.f4659n.isEmpty()) {
            this.f4666u = this.f4667v;
        }
        this.f4670y = false;
        InterfaceC2203z.a aVar = this.f4655j;
        aVar.m2044t(new InterfaceC2203z.c(1, this.f4649c, null, 3, null, aVar.m2025a(m1845t.f4628f), aVar.m2025a(j3)));
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.C2281a0.f
    /* renamed from: h */
    public void mo1765h() {
        this.f4661p.m1804B();
        for (C2105d0 c2105d0 : this.f4662q) {
            c2105d0.m1804B();
        }
        b<T> bVar = this.f4665t;
        if (bVar != null) {
            C2138e c2138e = (C2138e) bVar;
            synchronized (c2138e) {
                C2143j.c remove = c2138e.f4712q.remove(this);
                if (remove != null) {
                    remove.f4771a.m1804B();
                }
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2107e0
    /* renamed from: i */
    public int mo1787i(C1964f0 c1964f0, C1945e c1945e, boolean z) {
        if (m1849x()) {
            return -3;
        }
        m1850y();
        return this.f4661p.m1803A(c1964f0, c1945e, z, this.f4670y, this.f4669x);
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2107e0
    public boolean isReady() {
        return !m1849x() && this.f4661p.m1825u(this.f4670y);
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.C2281a0.b
    /* renamed from: k */
    public void mo1768k(AbstractC2122d abstractC2122d, long j2, long j3, boolean z) {
        AbstractC2122d abstractC2122d2 = abstractC2122d;
        InterfaceC2203z.a aVar = this.f4655j;
        C2324p c2324p = abstractC2122d2.f4623a;
        C2287d0 c2287d0 = abstractC2122d2.f4630h;
        aVar.m2029e(c2324p, c2287d0.f5798c, c2287d0.f5799d, abstractC2122d2.f4624b, this.f4649c, abstractC2122d2.f4625c, abstractC2122d2.f4626d, abstractC2122d2.f4627e, abstractC2122d2.f4628f, abstractC2122d2.f4629g, j2, j3, c2287d0.f5797b);
        if (z) {
            return;
        }
        this.f4661p.m1805C(false);
        for (C2105d0 c2105d0 : this.f4662q) {
            c2105d0.m1805C(false);
        }
        this.f4654i.mo1421i(this);
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.C2281a0.b
    /* renamed from: l */
    public void mo1769l(AbstractC2122d abstractC2122d, long j2, long j3) {
        AbstractC2122d abstractC2122d2 = abstractC2122d;
        this.f4653h.mo1858h(abstractC2122d2);
        InterfaceC2203z.a aVar = this.f4655j;
        C2324p c2324p = abstractC2122d2.f4623a;
        C2287d0 c2287d0 = abstractC2122d2.f4630h;
        aVar.m2032h(c2324p, c2287d0.f5798c, c2287d0.f5799d, abstractC2122d2.f4624b, this.f4649c, abstractC2122d2.f4625c, abstractC2122d2.f4626d, abstractC2122d2.f4627e, abstractC2122d2.f4628f, abstractC2122d2.f4629g, j2, j3, c2287d0.f5797b);
        this.f4654i.mo1421i(this);
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2107e0
    /* renamed from: o */
    public int mo1788o(long j2) {
        if (m1849x()) {
            return 0;
        }
        int m1809e = (!this.f4670y || j2 <= this.f4661p.m1818n()) ? this.f4661p.m1809e(j2) : this.f4661p.m1810f();
        m1850y();
        return m1809e;
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.C2281a0.b
    /* renamed from: s */
    public C2281a0.c mo1775s(AbstractC2122d abstractC2122d, long j2, long j3, IOException iOException, int i2) {
        AbstractC2122d abstractC2122d2 = abstractC2122d;
        long j4 = abstractC2122d2.f4630h.f5797b;
        boolean z = abstractC2122d2 instanceof AbstractC2119a;
        int size = this.f4659n.size() - 1;
        boolean z2 = (j4 != 0 && z && m1848w(size)) ? false : true;
        C2281a0.c cVar = null;
        if (this.f4653h.mo1855d(abstractC2122d2, z2, iOException, z2 ? ((C2331w) this.f4656k).m2279a(abstractC2122d2.f4624b, j3, iOException, i2) : -9223372036854775807L) && z2) {
            cVar = C2281a0.f5767a;
            if (z) {
                C4195m.m4771I(m1845t(size) == abstractC2122d2);
                if (this.f4659n.isEmpty()) {
                    this.f4666u = this.f4667v;
                }
            }
        }
        if (cVar == null) {
            long m2281c = ((C2331w) this.f4656k).m2281c(abstractC2122d2.f4624b, j3, iOException, i2);
            cVar = m2281c != -9223372036854775807L ? C2281a0.m2179c(false, m2281c) : C2281a0.f5768b;
        }
        C2281a0.c cVar2 = cVar;
        boolean z3 = !cVar2.m2187a();
        InterfaceC2203z.a aVar = this.f4655j;
        C2324p c2324p = abstractC2122d2.f4623a;
        C2287d0 c2287d0 = abstractC2122d2.f4630h;
        aVar.m2035k(c2324p, c2287d0.f5798c, c2287d0.f5799d, abstractC2122d2.f4624b, this.f4649c, abstractC2122d2.f4625c, abstractC2122d2.f4626d, abstractC2122d2.f4627e, abstractC2122d2.f4628f, abstractC2122d2.f4629g, j2, j3, j4, iOException, z3);
        if (z3) {
            this.f4654i.mo1421i(this);
        }
        return cVar2;
    }

    /* renamed from: t */
    public final AbstractC2119a m1845t(int i2) {
        AbstractC2119a abstractC2119a = this.f4659n.get(i2);
        ArrayList<AbstractC2119a> arrayList = this.f4659n;
        C2344d0.m2312D(arrayList, i2, arrayList.size());
        this.f4668w = Math.max(this.f4668w, this.f4659n.size());
        int i3 = 0;
        this.f4661p.m1815k(abstractC2119a.f4619m[0]);
        while (true) {
            C2105d0[] c2105d0Arr = this.f4662q;
            if (i3 >= c2105d0Arr.length) {
                return abstractC2119a;
            }
            C2105d0 c2105d0 = c2105d0Arr[i3];
            i3++;
            c2105d0.m1815k(abstractC2119a.f4619m[i3]);
        }
    }

    /* renamed from: u */
    public void m1846u(long j2, boolean z) {
        long j3;
        if (m1849x()) {
            return;
        }
        C2105d0 c2105d0 = this.f4661p;
        int i2 = c2105d0.f4559p;
        c2105d0.m1812h(j2, z, true);
        C2105d0 c2105d02 = this.f4661p;
        int i3 = c2105d02.f4559p;
        if (i3 > i2) {
            synchronized (c2105d02) {
                j3 = c2105d02.f4558o == 0 ? Long.MIN_VALUE : c2105d02.f4555l[c2105d02.f4560q];
            }
            int i4 = 0;
            while (true) {
                C2105d0[] c2105d0Arr = this.f4662q;
                if (i4 >= c2105d0Arr.length) {
                    break;
                }
                c2105d0Arr[i4].m1812h(j3, z, this.f4652g[i4]);
                i4++;
            }
        }
        int min = Math.min(m1851z(i3, 0), this.f4668w);
        if (min > 0) {
            C2344d0.m2312D(this.f4659n, 0, min);
            this.f4668w -= min;
        }
    }

    /* renamed from: v */
    public final AbstractC2119a m1847v() {
        return this.f4659n.get(r0.size() - 1);
    }

    /* renamed from: w */
    public final boolean m1848w(int i2) {
        int m1820p;
        AbstractC2119a abstractC2119a = this.f4659n.get(i2);
        if (this.f4661p.m1820p() > abstractC2119a.f4619m[0]) {
            return true;
        }
        int i3 = 0;
        do {
            C2105d0[] c2105d0Arr = this.f4662q;
            if (i3 >= c2105d0Arr.length) {
                return false;
            }
            m1820p = c2105d0Arr[i3].m1820p();
            i3++;
        } while (m1820p <= abstractC2119a.f4619m[i3]);
        return true;
    }

    /* renamed from: x */
    public boolean m1849x() {
        return this.f4666u != -9223372036854775807L;
    }

    /* renamed from: y */
    public final void m1850y() {
        int m1851z = m1851z(this.f4661p.m1820p(), this.f4668w - 1);
        while (true) {
            int i2 = this.f4668w;
            if (i2 > m1851z) {
                return;
            }
            this.f4668w = i2 + 1;
            AbstractC2119a abstractC2119a = this.f4659n.get(i2);
            Format format = abstractC2119a.f4625c;
            if (!format.equals(this.f4664s)) {
                this.f4655j.m2026b(this.f4649c, format, abstractC2119a.f4626d, abstractC2119a.f4627e, abstractC2119a.f4628f);
            }
            this.f4664s = format;
        }
    }

    /* renamed from: z */
    public final int m1851z(int i2, int i3) {
        do {
            i3++;
            if (i3 >= this.f4659n.size()) {
                return this.f4659n.size() - 1;
            }
        } while (this.f4659n.get(i3).f4619m[0] <= i2);
        return i3 - 1;
    }
}
