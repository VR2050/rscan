package p005b.p199l.p200a.p201a;

import android.util.Pair;
import androidx.annotation.Nullable;
import java.util.Objects;
import p005b.p199l.p200a.p201a.p227k1.p228j0.C2117a;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.x0 */
/* loaded from: classes.dex */
public abstract class AbstractC2404x0 {

    /* renamed from: a */
    public static final AbstractC2404x0 f6366a = new a();

    /* renamed from: b.l.a.a.x0$a */
    public static class a extends AbstractC2404x0 {
        @Override // p005b.p199l.p200a.p201a.AbstractC2404x0
        /* renamed from: b */
        public int mo1831b(Object obj) {
            return -1;
        }

        @Override // p005b.p199l.p200a.p201a.AbstractC2404x0
        /* renamed from: g */
        public b mo1832g(int i2, b bVar, boolean z) {
            throw new IndexOutOfBoundsException();
        }

        @Override // p005b.p199l.p200a.p201a.AbstractC2404x0
        /* renamed from: i */
        public int mo1833i() {
            return 0;
        }

        @Override // p005b.p199l.p200a.p201a.AbstractC2404x0
        /* renamed from: m */
        public Object mo1834m(int i2) {
            throw new IndexOutOfBoundsException();
        }

        @Override // p005b.p199l.p200a.p201a.AbstractC2404x0
        /* renamed from: o */
        public c mo1835o(int i2, c cVar, long j2) {
            throw new IndexOutOfBoundsException();
        }

        @Override // p005b.p199l.p200a.p201a.AbstractC2404x0
        /* renamed from: p */
        public int mo1836p() {
            return 0;
        }
    }

    /* renamed from: b.l.a.a.x0$b */
    public static final class b {

        /* renamed from: a */
        @Nullable
        public Object f6367a;

        /* renamed from: b */
        public int f6368b;

        /* renamed from: c */
        public long f6369c;

        /* renamed from: d */
        public long f6370d;

        /* renamed from: e */
        public C2117a f6371e = C2117a.f4606a;

        /* renamed from: a */
        public long m2692a(int i2, int i3) {
            C2117a.a aVar = this.f6371e.f4609d[i2];
            if (aVar.f4611a != -1) {
                return aVar.f4614d[i3];
            }
            return -9223372036854775807L;
        }

        /* renamed from: b */
        public int m2693b(long j2) {
            C2117a c2117a = this.f6371e;
            long j3 = this.f6369c;
            Objects.requireNonNull(c2117a);
            if (j2 == Long.MIN_VALUE) {
                return -1;
            }
            if (j3 != -9223372036854775807L && j2 >= j3) {
                return -1;
            }
            int i2 = 0;
            while (true) {
                long[] jArr = c2117a.f4608c;
                if (i2 >= jArr.length || jArr[i2] == Long.MIN_VALUE || (j2 < jArr[i2] && c2117a.f4609d[i2].m1838b())) {
                    break;
                }
                i2++;
            }
            if (i2 < c2117a.f4608c.length) {
                return i2;
            }
            return -1;
        }

        /* JADX WARN: Code restructure failed: missing block: B:10:0x0026, code lost:
        
            if (r10 >= r3) goto L17;
         */
        /* JADX WARN: Code restructure failed: missing block: B:13:0x002b, code lost:
        
            if (r10 < r7) goto L16;
         */
        /* renamed from: c */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public int m2694c(long r10) {
            /*
                r9 = this;
                b.l.a.a.k1.j0.a r0 = r9.f6371e
                long[] r1 = r0.f4608c
                int r1 = r1.length
                r2 = 1
                int r1 = r1 - r2
            L7:
                if (r1 < 0) goto L33
                r3 = -9223372036854775808
                r5 = 0
                int r6 = (r10 > r3 ? 1 : (r10 == r3 ? 0 : -1))
                if (r6 != 0) goto L11
                goto L2e
            L11:
                long[] r6 = r0.f4608c
                r7 = r6[r1]
                int r6 = (r7 > r3 ? 1 : (r7 == r3 ? 0 : -1))
                if (r6 != 0) goto L29
                long r3 = r0.f4610e
                r6 = -9223372036854775807(0x8000000000000001, double:-4.9E-324)
                int r8 = (r3 > r6 ? 1 : (r3 == r6 ? 0 : -1))
                if (r8 == 0) goto L2d
                int r6 = (r10 > r3 ? 1 : (r10 == r3 ? 0 : -1))
                if (r6 >= 0) goto L2e
                goto L2d
            L29:
                int r3 = (r10 > r7 ? 1 : (r10 == r7 ? 0 : -1))
                if (r3 >= 0) goto L2e
            L2d:
                r5 = 1
            L2e:
                if (r5 == 0) goto L33
                int r1 = r1 + (-1)
                goto L7
            L33:
                if (r1 < 0) goto L40
                b.l.a.a.k1.j0.a$a[] r10 = r0.f4609d
                r10 = r10[r1]
                boolean r10 = r10.m1838b()
                if (r10 == 0) goto L40
                goto L41
            L40:
                r1 = -1
            L41:
                return r1
            */
            throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.AbstractC2404x0.b.m2694c(long):int");
        }

        /* renamed from: d */
        public long m2695d(int i2) {
            return this.f6371e.f4608c[i2];
        }

        /* renamed from: e */
        public int m2696e(int i2) {
            return this.f6371e.f4609d[i2].m1837a(-1);
        }

        /* renamed from: f */
        public boolean m2697f(int i2, int i3) {
            C2117a.a aVar = this.f6371e.f4609d[i2];
            return (aVar.f4611a == -1 || aVar.f4613c[i3] == 0) ? false : true;
        }
    }

    /* renamed from: b.l.a.a.x0$c */
    public static final class c {

        /* renamed from: a */
        public static final Object f6372a = new Object();

        /* renamed from: b */
        public Object f6373b = f6372a;

        /* renamed from: c */
        @Nullable
        public Object f6374c;

        /* renamed from: d */
        @Nullable
        public Object f6375d;

        /* renamed from: e */
        public boolean f6376e;

        /* renamed from: f */
        public boolean f6377f;

        /* renamed from: g */
        public int f6378g;

        /* renamed from: h */
        public int f6379h;

        /* renamed from: i */
        public long f6380i;

        /* renamed from: j */
        public long f6381j;

        /* renamed from: k */
        public long f6382k;

        /* renamed from: a */
        public long m2698a() {
            return C2399v.m2669b(this.f6381j);
        }

        /* renamed from: b */
        public c m2699b(Object obj, @Nullable Object obj2, @Nullable Object obj3, long j2, long j3, boolean z, boolean z2, boolean z3, long j4, long j5, int i2, int i3, long j6) {
            this.f6373b = obj;
            this.f6374c = obj2;
            this.f6375d = obj3;
            this.f6376e = z;
            this.f6377f = z2;
            this.f6380i = j4;
            this.f6381j = j5;
            this.f6378g = i2;
            this.f6379h = i3;
            this.f6382k = j6;
            return this;
        }
    }

    /* renamed from: a */
    public int mo1926a(boolean z) {
        return m2691q() ? -1 : 0;
    }

    /* renamed from: b */
    public abstract int mo1831b(Object obj);

    /* renamed from: c */
    public int mo1927c(boolean z) {
        if (m2691q()) {
            return -1;
        }
        return mo1836p() - 1;
    }

    /* renamed from: d */
    public final int m2686d(int i2, b bVar, c cVar, int i3, boolean z) {
        int i4 = mo1832g(i2, bVar, false).f6368b;
        if (m2690n(i4, cVar).f6379h != i2) {
            return i2 + 1;
        }
        int mo1928e = mo1928e(i4, i3, z);
        if (mo1928e == -1) {
            return -1;
        }
        return m2690n(mo1928e, cVar).f6378g;
    }

    /* renamed from: e */
    public int mo1928e(int i2, int i3, boolean z) {
        if (i3 == 0) {
            if (i2 == mo1927c(z)) {
                return -1;
            }
            return i2 + 1;
        }
        if (i3 == 1) {
            return i2;
        }
        if (i3 == 2) {
            return i2 == mo1927c(z) ? mo1926a(z) : i2 + 1;
        }
        throw new IllegalStateException();
    }

    /* renamed from: f */
    public final b m2687f(int i2, b bVar) {
        return mo1832g(i2, bVar, false);
    }

    /* renamed from: g */
    public abstract b mo1832g(int i2, b bVar, boolean z);

    /* renamed from: h */
    public b mo1929h(Object obj, b bVar) {
        return mo1832g(mo1831b(obj), bVar, true);
    }

    /* renamed from: i */
    public abstract int mo1833i();

    /* renamed from: j */
    public final Pair<Object, Long> m2688j(c cVar, b bVar, int i2, long j2) {
        Pair<Object, Long> m2689k = m2689k(cVar, bVar, i2, j2, 0L);
        Objects.requireNonNull(m2689k);
        return m2689k;
    }

    @Nullable
    /* renamed from: k */
    public final Pair<Object, Long> m2689k(c cVar, b bVar, int i2, long j2, long j3) {
        C4195m.m4767G(i2, 0, mo1836p());
        mo1835o(i2, cVar, j3);
        if (j2 == -9223372036854775807L) {
            j2 = cVar.f6380i;
            if (j2 == -9223372036854775807L) {
                return null;
            }
        }
        int i3 = cVar.f6378g;
        long j4 = cVar.f6382k + j2;
        long j5 = mo1832g(i3, bVar, true).f6369c;
        while (j5 != -9223372036854775807L && j4 >= j5 && i3 < cVar.f6379h) {
            j4 -= j5;
            i3++;
            j5 = mo1832g(i3, bVar, true).f6369c;
        }
        Object obj = bVar.f6367a;
        Objects.requireNonNull(obj);
        return Pair.create(obj, Long.valueOf(j4));
    }

    /* renamed from: l */
    public int mo1930l(int i2, int i3, boolean z) {
        if (i3 == 0) {
            if (i2 == mo1926a(z)) {
                return -1;
            }
            return i2 - 1;
        }
        if (i3 == 1) {
            return i2;
        }
        if (i3 == 2) {
            return i2 == mo1926a(z) ? mo1927c(z) : i2 - 1;
        }
        throw new IllegalStateException();
    }

    /* renamed from: m */
    public abstract Object mo1834m(int i2);

    /* renamed from: n */
    public final c m2690n(int i2, c cVar) {
        return mo1835o(i2, cVar, 0L);
    }

    /* renamed from: o */
    public abstract c mo1835o(int i2, c cVar, long j2);

    /* renamed from: p */
    public abstract int mo1836p();

    /* renamed from: q */
    public final boolean m2691q() {
        return mo1836p() == 0;
    }
}
