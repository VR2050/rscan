package p005b.p199l.p200a.p201a.p227k1;

import android.os.Looper;
import androidx.annotation.CallSuper;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.drm.DrmInitData;
import java.io.EOFException;
import java.util.Objects;
import p005b.p199l.p200a.p201a.C1964f0;
import p005b.p199l.p200a.p201a.p205d1.InterfaceC1952c;
import p005b.p199l.p200a.p201a.p205d1.InterfaceC1954e;
import p005b.p199l.p200a.p201a.p208f1.C2003e;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s;
import p005b.p199l.p200a.p201a.p227k1.C2103c0;
import p005b.p199l.p200a.p201a.p248o1.C2325q;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2288e;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.C2357q;
import p005b.p199l.p200a.p201a.p250p1.C2360t;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.k1.d0 */
/* loaded from: classes.dex */
public class C2105d0 implements InterfaceC2052s {

    /* renamed from: A */
    public boolean f4540A;

    /* renamed from: B */
    public Format f4541B;

    /* renamed from: C */
    public long f4542C;

    /* renamed from: D */
    public boolean f4543D;

    /* renamed from: a */
    public final C2103c0 f4544a;

    /* renamed from: c */
    public final InterfaceC1954e<?> f4546c;

    /* renamed from: d */
    public b f4547d;

    /* renamed from: e */
    @Nullable
    public Format f4548e;

    /* renamed from: f */
    @Nullable
    public InterfaceC1952c<?> f4549f;

    /* renamed from: o */
    public int f4558o;

    /* renamed from: p */
    public int f4559p;

    /* renamed from: q */
    public int f4560q;

    /* renamed from: r */
    public int f4561r;

    /* renamed from: u */
    public boolean f4564u;

    /* renamed from: x */
    public Format f4567x;

    /* renamed from: y */
    public Format f4568y;

    /* renamed from: z */
    public int f4569z;

    /* renamed from: b */
    public final a f4545b = new a();

    /* renamed from: g */
    public int f4550g = 1000;

    /* renamed from: h */
    public int[] f4551h = new int[1000];

    /* renamed from: i */
    public long[] f4552i = new long[1000];

    /* renamed from: l */
    public long[] f4555l = new long[1000];

    /* renamed from: k */
    public int[] f4554k = new int[1000];

    /* renamed from: j */
    public int[] f4553j = new int[1000];

    /* renamed from: m */
    public InterfaceC2052s.a[] f4556m = new InterfaceC2052s.a[1000];

    /* renamed from: n */
    public Format[] f4557n = new Format[1000];

    /* renamed from: s */
    public long f4562s = Long.MIN_VALUE;

    /* renamed from: t */
    public long f4563t = Long.MIN_VALUE;

    /* renamed from: w */
    public boolean f4566w = true;

    /* renamed from: v */
    public boolean f4565v = true;

    /* renamed from: b.l.a.a.k1.d0$a */
    public static final class a {

        /* renamed from: a */
        public int f4570a;

        /* renamed from: b */
        public long f4571b;

        /* renamed from: c */
        public InterfaceC2052s.a f4572c;
    }

    /* renamed from: b.l.a.a.k1.d0$b */
    public interface b {
        /* renamed from: i */
        void mo1766i(Format format);
    }

    public C2105d0(InterfaceC2288e interfaceC2288e, InterfaceC1954e<?> interfaceC1954e) {
        this.f4544a = new C2103c0(interfaceC2288e);
        this.f4546c = interfaceC1954e;
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:22:0x0070 A[Catch: all -> 0x0264, LOOP:0: B:4:0x000b->B:22:0x0070, LOOP_END, TRY_ENTER, TryCatch #0 {, blocks: (B:5:0x000b, B:7:0x0014, B:9:0x0022, B:22:0x0070, B:27:0x007d, B:30:0x0082, B:33:0x0088, B:35:0x008c, B:98:0x0093, B:102:0x009a, B:105:0x00a3, B:108:0x00ab, B:110:0x00bc, B:111:0x00c1, B:113:0x00c5, B:118:0x00d0, B:121:0x00ea), top: B:4:0x000b }] */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0076 A[SYNTHETIC] */
    @androidx.annotation.CallSuper
    /* renamed from: A */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public int m1803A(p005b.p199l.p200a.p201a.C1964f0 r17, p005b.p199l.p200a.p201a.p204c1.C1945e r18, boolean r19, boolean r20, long r21) {
        /*
            Method dump skipped, instructions count: 634
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p227k1.C2105d0.m1803A(b.l.a.a.f0, b.l.a.a.c1.e, boolean, boolean, long):int");
    }

    @CallSuper
    /* renamed from: B */
    public void m1804B() {
        m1805C(true);
        InterfaceC1952c<?> interfaceC1952c = this.f4549f;
        if (interfaceC1952c != null) {
            interfaceC1952c.release();
            this.f4549f = null;
            this.f4548e = null;
        }
    }

    @CallSuper
    /* renamed from: C */
    public void m1805C(boolean z) {
        C2103c0 c2103c0 = this.f4544a;
        c2103c0.m1796a(c2103c0.f4525d);
        C2103c0.a aVar = new C2103c0.a(0L, c2103c0.f4523b);
        c2103c0.f4525d = aVar;
        c2103c0.f4526e = aVar;
        c2103c0.f4527f = aVar;
        c2103c0.f4528g = 0L;
        ((C2325q) c2103c0.f4522a).m2272c();
        this.f4558o = 0;
        this.f4559p = 0;
        this.f4560q = 0;
        this.f4561r = 0;
        this.f4565v = true;
        this.f4562s = Long.MIN_VALUE;
        this.f4563t = Long.MIN_VALUE;
        this.f4564u = false;
        this.f4568y = null;
        if (z) {
            this.f4541B = null;
            this.f4567x = null;
            this.f4566w = true;
        }
    }

    /* renamed from: D */
    public final synchronized void m1806D() {
        this.f4561r = 0;
        C2103c0 c2103c0 = this.f4544a;
        c2103c0.f4526e = c2103c0.f4525d;
    }

    /* renamed from: E */
    public final synchronized boolean m1807E(long j2, boolean z) {
        m1806D();
        int m1821q = m1821q(this.f4561r);
        if (m1824t() && j2 >= this.f4555l[m1821q] && (j2 <= this.f4563t || z)) {
            int m1816l = m1816l(m1821q, this.f4558o - this.f4561r, j2, true);
            if (m1816l == -1) {
                return false;
            }
            this.f4561r += m1816l;
            return true;
        }
        return false;
    }

    /* renamed from: F */
    public final void m1808F(long j2) {
        if (this.f4542C != j2) {
            this.f4542C = j2;
            this.f4540A = true;
        }
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s
    /* renamed from: a */
    public final int mo1612a(C2003e c2003e, int i2, boolean z) {
        C2103c0 c2103c0 = this.f4544a;
        int m1799d = c2103c0.m1799d(i2);
        C2103c0.a aVar = c2103c0.f4527f;
        int m1566f = c2003e.m1566f(aVar.f4532d.f5794a, aVar.m1802a(c2103c0.f4528g), m1799d);
        if (m1566f != -1) {
            c2103c0.m1798c(m1566f);
            return m1566f;
        }
        if (z) {
            return -1;
        }
        throw new EOFException();
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s
    /* renamed from: b */
    public final void mo1613b(C2360t c2360t, int i2) {
        C2103c0 c2103c0 = this.f4544a;
        Objects.requireNonNull(c2103c0);
        while (i2 > 0) {
            int m1799d = c2103c0.m1799d(i2);
            C2103c0.a aVar = c2103c0.f4527f;
            c2360t.m2572d(aVar.f4532d.f5794a, aVar.m1802a(c2103c0.f4528g), m1799d);
            i2 -= m1799d;
            c2103c0.m1798c(m1799d);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s
    /* renamed from: c */
    public final void mo1614c(long j2, int i2, int i3, int i4, @Nullable InterfaceC2052s.a aVar) {
        boolean z;
        if (this.f4540A) {
            mo1615d(this.f4541B);
        }
        long j3 = j2 + this.f4542C;
        if (this.f4543D) {
            if ((i2 & 1) == 0) {
                return;
            }
            synchronized (this) {
                if (this.f4558o == 0) {
                    z = j3 > this.f4562s;
                } else if (Math.max(this.f4562s, m1819o(this.f4561r)) >= j3) {
                    z = false;
                } else {
                    int i5 = this.f4558o;
                    int m1821q = m1821q(i5 - 1);
                    while (i5 > this.f4561r && this.f4555l[m1821q] >= j3) {
                        i5--;
                        m1821q--;
                        if (m1821q == -1) {
                            m1821q = this.f4550g - 1;
                        }
                    }
                    m1814j(this.f4559p + i5);
                    z = true;
                }
            }
            if (!z) {
                return;
            } else {
                this.f4543D = false;
            }
        }
        long j4 = (this.f4544a.f4528g - i3) - i4;
        synchronized (this) {
            if (this.f4565v) {
                if ((i2 & 1) == 0) {
                    return;
                } else {
                    this.f4565v = false;
                }
            }
            C4195m.m4771I(!this.f4566w);
            this.f4564u = (536870912 & i2) != 0;
            this.f4563t = Math.max(this.f4563t, j3);
            int m1821q2 = m1821q(this.f4558o);
            this.f4555l[m1821q2] = j3;
            long[] jArr = this.f4552i;
            jArr[m1821q2] = j4;
            this.f4553j[m1821q2] = i3;
            this.f4554k[m1821q2] = i2;
            this.f4556m[m1821q2] = aVar;
            Format[] formatArr = this.f4557n;
            Format format = this.f4567x;
            formatArr[m1821q2] = format;
            this.f4551h[m1821q2] = this.f4569z;
            this.f4568y = format;
            int i6 = this.f4558o + 1;
            this.f4558o = i6;
            int i7 = this.f4550g;
            if (i6 == i7) {
                int i8 = i7 + 1000;
                int[] iArr = new int[i8];
                long[] jArr2 = new long[i8];
                long[] jArr3 = new long[i8];
                int[] iArr2 = new int[i8];
                int[] iArr3 = new int[i8];
                InterfaceC2052s.a[] aVarArr = new InterfaceC2052s.a[i8];
                Format[] formatArr2 = new Format[i8];
                int i9 = this.f4560q;
                int i10 = i7 - i9;
                System.arraycopy(jArr, i9, jArr2, 0, i10);
                System.arraycopy(this.f4555l, this.f4560q, jArr3, 0, i10);
                System.arraycopy(this.f4554k, this.f4560q, iArr2, 0, i10);
                System.arraycopy(this.f4553j, this.f4560q, iArr3, 0, i10);
                System.arraycopy(this.f4556m, this.f4560q, aVarArr, 0, i10);
                System.arraycopy(this.f4557n, this.f4560q, formatArr2, 0, i10);
                System.arraycopy(this.f4551h, this.f4560q, iArr, 0, i10);
                int i11 = this.f4560q;
                System.arraycopy(this.f4552i, 0, jArr2, i10, i11);
                System.arraycopy(this.f4555l, 0, jArr3, i10, i11);
                System.arraycopy(this.f4554k, 0, iArr2, i10, i11);
                System.arraycopy(this.f4553j, 0, iArr3, i10, i11);
                System.arraycopy(this.f4556m, 0, aVarArr, i10, i11);
                System.arraycopy(this.f4557n, 0, formatArr2, i10, i11);
                System.arraycopy(this.f4551h, 0, iArr, i10, i11);
                this.f4552i = jArr2;
                this.f4555l = jArr3;
                this.f4554k = iArr2;
                this.f4553j = iArr3;
                this.f4556m = aVarArr;
                this.f4557n = formatArr2;
                this.f4551h = iArr;
                this.f4560q = 0;
                this.f4550g = i8;
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s
    /* renamed from: d */
    public final void mo1615d(Format format) {
        Format mo1817m = mo1817m(format);
        boolean z = false;
        this.f4540A = false;
        this.f4541B = format;
        synchronized (this) {
            if (mo1817m == null) {
                this.f4566w = true;
            } else {
                this.f4566w = false;
                if (!C2344d0.m2323a(mo1817m, this.f4567x)) {
                    if (C2344d0.m2323a(mo1817m, this.f4568y)) {
                        this.f4567x = this.f4568y;
                    } else {
                        this.f4567x = mo1817m;
                    }
                    z = true;
                }
            }
        }
        b bVar = this.f4547d;
        if (bVar == null || !z) {
            return;
        }
        bVar.mo1766i(mo1817m);
    }

    /* renamed from: e */
    public final synchronized int m1809e(long j2) {
        int m1821q = m1821q(this.f4561r);
        if (m1824t() && j2 >= this.f4555l[m1821q]) {
            int m1816l = m1816l(m1821q, this.f4558o - this.f4561r, j2, true);
            if (m1816l == -1) {
                return 0;
            }
            this.f4561r += m1816l;
            return m1816l;
        }
        return 0;
    }

    /* renamed from: f */
    public final synchronized int m1810f() {
        int i2;
        int i3 = this.f4558o;
        i2 = i3 - this.f4561r;
        this.f4561r = i3;
        return i2;
    }

    /* renamed from: g */
    public final long m1811g(int i2) {
        this.f4562s = Math.max(this.f4562s, m1819o(i2));
        int i3 = this.f4558o - i2;
        this.f4558o = i3;
        this.f4559p += i2;
        int i4 = this.f4560q + i2;
        this.f4560q = i4;
        int i5 = this.f4550g;
        if (i4 >= i5) {
            this.f4560q = i4 - i5;
        }
        int i6 = this.f4561r - i2;
        this.f4561r = i6;
        if (i6 < 0) {
            this.f4561r = 0;
        }
        if (i3 != 0) {
            return this.f4552i[this.f4560q];
        }
        int i7 = this.f4560q;
        if (i7 != 0) {
            i5 = i7;
        }
        return this.f4552i[i5 - 1] + this.f4553j[r2];
    }

    /* renamed from: h */
    public final void m1812h(long j2, boolean z, boolean z2) {
        long j3;
        int i2;
        C2103c0 c2103c0 = this.f4544a;
        synchronized (this) {
            int i3 = this.f4558o;
            j3 = -1;
            if (i3 != 0) {
                long[] jArr = this.f4555l;
                int i4 = this.f4560q;
                if (j2 >= jArr[i4]) {
                    if (z2 && (i2 = this.f4561r) != i3) {
                        i3 = i2 + 1;
                    }
                    int m1816l = m1816l(i4, i3, j2, z);
                    if (m1816l != -1) {
                        j3 = m1811g(m1816l);
                    }
                }
            }
        }
        c2103c0.m1797b(j3);
    }

    /* renamed from: i */
    public final void m1813i() {
        long m1811g;
        C2103c0 c2103c0 = this.f4544a;
        synchronized (this) {
            int i2 = this.f4558o;
            m1811g = i2 == 0 ? -1L : m1811g(i2);
        }
        c2103c0.m1797b(m1811g);
    }

    /* renamed from: j */
    public final long m1814j(int i2) {
        int m1823s = m1823s() - i2;
        boolean z = false;
        C4195m.m4765F(m1823s >= 0 && m1823s <= this.f4558o - this.f4561r);
        int i3 = this.f4558o - m1823s;
        this.f4558o = i3;
        this.f4563t = Math.max(this.f4562s, m1819o(i3));
        if (m1823s == 0 && this.f4564u) {
            z = true;
        }
        this.f4564u = z;
        int i4 = this.f4558o;
        if (i4 == 0) {
            return 0L;
        }
        return this.f4552i[m1821q(i4 - 1)] + this.f4553j[r8];
    }

    /* renamed from: k */
    public final void m1815k(int i2) {
        C2103c0 c2103c0 = this.f4544a;
        long m1814j = m1814j(i2);
        c2103c0.f4528g = m1814j;
        if (m1814j != 0) {
            C2103c0.a aVar = c2103c0.f4525d;
            if (m1814j != aVar.f4529a) {
                while (c2103c0.f4528g > aVar.f4530b) {
                    aVar = aVar.f4533e;
                }
                C2103c0.a aVar2 = aVar.f4533e;
                c2103c0.m1796a(aVar2);
                C2103c0.a aVar3 = new C2103c0.a(aVar.f4530b, c2103c0.f4523b);
                aVar.f4533e = aVar3;
                if (c2103c0.f4528g == aVar.f4530b) {
                    aVar = aVar3;
                }
                c2103c0.f4527f = aVar;
                if (c2103c0.f4526e == aVar2) {
                    c2103c0.f4526e = aVar3;
                    return;
                }
                return;
            }
        }
        c2103c0.m1796a(c2103c0.f4525d);
        C2103c0.a aVar4 = new C2103c0.a(c2103c0.f4528g, c2103c0.f4523b);
        c2103c0.f4525d = aVar4;
        c2103c0.f4526e = aVar4;
        c2103c0.f4527f = aVar4;
    }

    /* renamed from: l */
    public final int m1816l(int i2, int i3, long j2, boolean z) {
        int i4 = -1;
        for (int i5 = 0; i5 < i3 && this.f4555l[i2] <= j2; i5++) {
            if (!z || (this.f4554k[i2] & 1) != 0) {
                i4 = i5;
            }
            i2++;
            if (i2 == this.f4550g) {
                i2 = 0;
            }
        }
        return i4;
    }

    @CallSuper
    /* renamed from: m */
    public Format mo1817m(Format format) {
        long j2 = this.f4542C;
        if (j2 == 0) {
            return format;
        }
        long j3 = format.f9249p;
        return j3 != Long.MAX_VALUE ? format.m4047w(j3 + j2) : format;
    }

    /* renamed from: n */
    public final synchronized long m1818n() {
        return this.f4563t;
    }

    /* renamed from: o */
    public final long m1819o(int i2) {
        long j2 = Long.MIN_VALUE;
        if (i2 == 0) {
            return Long.MIN_VALUE;
        }
        int m1821q = m1821q(i2 - 1);
        for (int i3 = 0; i3 < i2; i3++) {
            j2 = Math.max(j2, this.f4555l[m1821q]);
            if ((this.f4554k[m1821q] & 1) != 0) {
                break;
            }
            m1821q--;
            if (m1821q == -1) {
                m1821q = this.f4550g - 1;
            }
        }
        return j2;
    }

    /* renamed from: p */
    public final int m1820p() {
        return this.f4559p + this.f4561r;
    }

    /* renamed from: q */
    public final int m1821q(int i2) {
        int i3 = this.f4560q + i2;
        int i4 = this.f4550g;
        return i3 < i4 ? i3 : i3 - i4;
    }

    /* renamed from: r */
    public final synchronized Format m1822r() {
        return this.f4566w ? null : this.f4567x;
    }

    /* renamed from: s */
    public final int m1823s() {
        return this.f4559p + this.f4558o;
    }

    /* renamed from: t */
    public final boolean m1824t() {
        return this.f4561r != this.f4558o;
    }

    @CallSuper
    /* renamed from: u */
    public synchronized boolean m1825u(boolean z) {
        Format format;
        boolean z2 = true;
        if (m1824t()) {
            int m1821q = m1821q(this.f4561r);
            if (this.f4557n[m1821q] != this.f4548e) {
                return true;
            }
            return m1826v(m1821q);
        }
        if (!z && !this.f4564u && ((format = this.f4567x) == null || format == this.f4548e)) {
            z2 = false;
        }
        return z2;
    }

    /* renamed from: v */
    public final boolean m1826v(int i2) {
        InterfaceC1952c<?> interfaceC1952c;
        if (this.f4546c == InterfaceC1954e.f3383a || (interfaceC1952c = this.f4549f) == null || interfaceC1952c.getState() == 4) {
            return true;
        }
        return (this.f4554k[i2] & 1073741824) == 0 && this.f4549f.mo1448a();
    }

    @CallSuper
    /* renamed from: w */
    public void m1827w() {
        InterfaceC1952c<?> interfaceC1952c = this.f4549f;
        if (interfaceC1952c == null || interfaceC1952c.getState() != 1) {
            return;
        }
        InterfaceC1952c.a mo1450c = this.f4549f.mo1450c();
        Objects.requireNonNull(mo1450c);
        throw mo1450c;
    }

    /* renamed from: x */
    public final void m1828x(Format format, C1964f0 c1964f0) {
        c1964f0.f3394c = format;
        Format format2 = this.f4548e;
        boolean z = format2 == null;
        DrmInitData drmInitData = z ? null : format2.f9248o;
        this.f4548e = format;
        if (this.f4546c == InterfaceC1954e.f3383a) {
            return;
        }
        DrmInitData drmInitData2 = format.f9248o;
        c1964f0.f3392a = true;
        c1964f0.f3393b = this.f4549f;
        if (z || !C2344d0.m2323a(drmInitData, drmInitData2)) {
            InterfaceC1952c<?> interfaceC1952c = this.f4549f;
            Looper myLooper = Looper.myLooper();
            Objects.requireNonNull(myLooper);
            InterfaceC1952c<?> mo1445d = drmInitData2 != null ? this.f4546c.mo1445d(myLooper, drmInitData2) : this.f4546c.mo1444c(myLooper, C2357q.m2543f(format.f9245l));
            this.f4549f = mo1445d;
            c1964f0.f3393b = mo1445d;
            if (interfaceC1952c != null) {
                interfaceC1952c.release();
            }
        }
    }

    /* renamed from: y */
    public final synchronized int m1829y() {
        return m1824t() ? this.f4551h[m1821q(this.f4561r)] : this.f4569z;
    }

    @CallSuper
    /* renamed from: z */
    public void m1830z() {
        m1813i();
        InterfaceC1952c<?> interfaceC1952c = this.f4549f;
        if (interfaceC1952c != null) {
            interfaceC1952c.release();
            this.f4549f = null;
            this.f4548e = null;
        }
    }
}
