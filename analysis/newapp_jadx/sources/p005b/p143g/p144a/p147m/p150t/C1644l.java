package p005b.p143g.p144a.p147m.p150t;

import android.os.SystemClock;
import android.util.Log;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;
import androidx.core.util.Pools;
import java.io.File;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Executor;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.C1555e;
import p005b.p143g.p144a.EnumC1556f;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.EnumC1569a;
import p005b.p143g.p144a.p147m.InterfaceC1579k;
import p005b.p143g.p144a.p147m.InterfaceC1586r;
import p005b.p143g.p144a.p147m.p150t.C1606a;
import p005b.p143g.p144a.p147m.p150t.C1649q;
import p005b.p143g.p144a.p147m.p150t.RunnableC1641i;
import p005b.p143g.p144a.p147m.p150t.p152d0.C1626b;
import p005b.p143g.p144a.p147m.p150t.p152d0.C1628d;
import p005b.p143g.p144a.p147m.p150t.p152d0.C1629e;
import p005b.p143g.p144a.p147m.p150t.p152d0.C1630f;
import p005b.p143g.p144a.p147m.p150t.p152d0.C1632h;
import p005b.p143g.p144a.p147m.p150t.p152d0.InterfaceC1625a;
import p005b.p143g.p144a.p147m.p150t.p152d0.InterfaceC1633i;
import p005b.p143g.p144a.p147m.p150t.p153e0.ExecutorServiceC1637a;
import p005b.p143g.p144a.p166q.C1781h;
import p005b.p143g.p144a.p166q.InterfaceC1780g;
import p005b.p143g.p144a.p170s.C1803e;
import p005b.p143g.p144a.p170s.p171j.C1808a;

/* renamed from: b.g.a.m.t.l */
/* loaded from: classes.dex */
public class C1644l implements InterfaceC1646n, InterfaceC1633i.a, C1649q.a {

    /* renamed from: a */
    public static final boolean f2226a = Log.isLoggable("Engine", 2);

    /* renamed from: b */
    public final C1652t f2227b;

    /* renamed from: c */
    public final C1648p f2228c;

    /* renamed from: d */
    public final InterfaceC1633i f2229d;

    /* renamed from: e */
    public final b f2230e;

    /* renamed from: f */
    public final C1658z f2231f;

    /* renamed from: g */
    public final c f2232g;

    /* renamed from: h */
    public final a f2233h;

    /* renamed from: i */
    public final C1606a f2234i;

    @VisibleForTesting
    /* renamed from: b.g.a.m.t.l$a */
    public static class a {

        /* renamed from: a */
        public final RunnableC1641i.d f2235a;

        /* renamed from: b */
        public final Pools.Pool<RunnableC1641i<?>> f2236b = C1808a.m1153a(150, new C5108a());

        /* renamed from: c */
        public int f2237c;

        /* renamed from: b.g.a.m.t.l$a$a, reason: collision with other inner class name */
        public class C5108a implements C1808a.b<RunnableC1641i<?>> {
            public C5108a() {
            }

            @Override // p005b.p143g.p144a.p170s.p171j.C1808a.b
            public RunnableC1641i<?> create() {
                a aVar = a.this;
                return new RunnableC1641i<>(aVar.f2235a, aVar.f2236b);
            }
        }

        public a(RunnableC1641i.d dVar) {
            this.f2235a = dVar;
        }
    }

    @VisibleForTesting
    /* renamed from: b.g.a.m.t.l$b */
    public static class b {

        /* renamed from: a */
        public final ExecutorServiceC1637a f2239a;

        /* renamed from: b */
        public final ExecutorServiceC1637a f2240b;

        /* renamed from: c */
        public final ExecutorServiceC1637a f2241c;

        /* renamed from: d */
        public final ExecutorServiceC1637a f2242d;

        /* renamed from: e */
        public final InterfaceC1646n f2243e;

        /* renamed from: f */
        public final C1649q.a f2244f;

        /* renamed from: g */
        public final Pools.Pool<C1645m<?>> f2245g = C1808a.m1153a(150, new a());

        /* renamed from: b.g.a.m.t.l$b$a */
        public class a implements C1808a.b<C1645m<?>> {
            public a() {
            }

            @Override // p005b.p143g.p144a.p170s.p171j.C1808a.b
            public C1645m<?> create() {
                b bVar = b.this;
                return new C1645m<>(bVar.f2239a, bVar.f2240b, bVar.f2241c, bVar.f2242d, bVar.f2243e, bVar.f2244f, bVar.f2245g);
            }
        }

        public b(ExecutorServiceC1637a executorServiceC1637a, ExecutorServiceC1637a executorServiceC1637a2, ExecutorServiceC1637a executorServiceC1637a3, ExecutorServiceC1637a executorServiceC1637a4, InterfaceC1646n interfaceC1646n, C1649q.a aVar) {
            this.f2239a = executorServiceC1637a;
            this.f2240b = executorServiceC1637a2;
            this.f2241c = executorServiceC1637a3;
            this.f2242d = executorServiceC1637a4;
            this.f2243e = interfaceC1646n;
            this.f2244f = aVar;
        }
    }

    /* renamed from: b.g.a.m.t.l$c */
    public static class c implements RunnableC1641i.d {

        /* renamed from: a */
        public final InterfaceC1625a.a f2247a;

        /* renamed from: b */
        public volatile InterfaceC1625a f2248b;

        public c(InterfaceC1625a.a aVar) {
            this.f2247a = aVar;
        }

        /* renamed from: a */
        public InterfaceC1625a m938a() {
            if (this.f2248b == null) {
                synchronized (this) {
                    if (this.f2248b == null) {
                        C1628d c1628d = (C1628d) this.f2247a;
                        C1630f c1630f = (C1630f) c1628d.f2111b;
                        File cacheDir = c1630f.f2117a.getCacheDir();
                        C1629e c1629e = null;
                        if (cacheDir == null) {
                            cacheDir = null;
                        } else if (c1630f.f2118b != null) {
                            cacheDir = new File(cacheDir, c1630f.f2118b);
                        }
                        if (cacheDir != null && (cacheDir.mkdirs() || (cacheDir.exists() && cacheDir.isDirectory()))) {
                            c1629e = new C1629e(cacheDir, c1628d.f2110a);
                        }
                        this.f2248b = c1629e;
                    }
                    if (this.f2248b == null) {
                        this.f2248b = new C1626b();
                    }
                }
            }
            return this.f2248b;
        }
    }

    /* renamed from: b.g.a.m.t.l$d */
    public class d {

        /* renamed from: a */
        public final C1645m<?> f2249a;

        /* renamed from: b */
        public final InterfaceC1780g f2250b;

        public d(InterfaceC1780g interfaceC1780g, C1645m<?> c1645m) {
            this.f2250b = interfaceC1780g;
            this.f2249a = c1645m;
        }
    }

    public C1644l(InterfaceC1633i interfaceC1633i, InterfaceC1625a.a aVar, ExecutorServiceC1637a executorServiceC1637a, ExecutorServiceC1637a executorServiceC1637a2, ExecutorServiceC1637a executorServiceC1637a3, ExecutorServiceC1637a executorServiceC1637a4, boolean z) {
        this.f2229d = interfaceC1633i;
        c cVar = new c(aVar);
        this.f2232g = cVar;
        C1606a c1606a = new C1606a(z);
        this.f2234i = c1606a;
        synchronized (this) {
            synchronized (c1606a) {
                c1606a.f2043d = this;
            }
        }
        this.f2228c = new C1648p();
        this.f2227b = new C1652t();
        this.f2230e = new b(executorServiceC1637a, executorServiceC1637a2, executorServiceC1637a3, executorServiceC1637a4, this, this);
        this.f2233h = new a(cVar);
        this.f2231f = new C1658z();
        ((C1632h) interfaceC1633i).f2119d = this;
    }

    /* renamed from: d */
    public static void m931d(String str, long j2, InterfaceC1579k interfaceC1579k) {
        StringBuilder m590L = C1499a.m590L(str, " in ");
        m590L.append(C1803e.m1138a(j2));
        m590L.append("ms, key: ");
        m590L.append(interfaceC1579k);
        m590L.toString();
    }

    @Override // p005b.p143g.p144a.p147m.p150t.C1649q.a
    /* renamed from: a */
    public void mo932a(InterfaceC1579k interfaceC1579k, C1649q<?> c1649q) {
        C1606a c1606a = this.f2234i;
        synchronized (c1606a) {
            C1606a.b remove = c1606a.f2041b.remove(interfaceC1579k);
            if (remove != null) {
                remove.f2047c = null;
                remove.clear();
            }
        }
        if (c1649q.f2293c) {
            ((C1632h) this.f2229d).m1140d(interfaceC1579k, c1649q);
        } else {
            this.f2231f.m959a(c1649q, false);
        }
    }

    /* renamed from: b */
    public <R> d m933b(C1555e c1555e, Object obj, InterfaceC1579k interfaceC1579k, int i2, int i3, Class<?> cls, Class<R> cls2, EnumC1556f enumC1556f, AbstractC1643k abstractC1643k, Map<Class<?>, InterfaceC1586r<?>> map, boolean z, boolean z2, C1582n c1582n, boolean z3, boolean z4, boolean z5, boolean z6, InterfaceC1780g interfaceC1780g, Executor executor) {
        long j2;
        if (f2226a) {
            int i4 = C1803e.f2759b;
            j2 = SystemClock.elapsedRealtimeNanos();
        } else {
            j2 = 0;
        }
        long j3 = j2;
        Objects.requireNonNull(this.f2228c);
        C1647o c1647o = new C1647o(obj, interfaceC1579k, i2, i3, map, cls, cls2, c1582n);
        synchronized (this) {
            C1649q<?> m934c = m934c(c1647o, z3, j3);
            if (m934c == null) {
                return m937g(c1555e, obj, interfaceC1579k, i2, i3, cls, cls2, enumC1556f, abstractC1643k, map, z, z2, c1582n, z3, z4, z5, z6, interfaceC1780g, executor, c1647o, j3);
            }
            ((C1781h) interfaceC1780g).m1120m(m934c, EnumC1569a.MEMORY_CACHE);
            return null;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Nullable
    /* renamed from: c */
    public final C1649q<?> m934c(C1647o c1647o, boolean z, long j2) {
        C1649q<?> c1649q;
        Object remove;
        if (!z) {
            return null;
        }
        C1606a c1606a = this.f2234i;
        synchronized (c1606a) {
            C1606a.b bVar = c1606a.f2041b.get(c1647o);
            if (bVar == null) {
                c1649q = null;
            } else {
                c1649q = bVar.get();
                if (c1649q == null) {
                    c1606a.m852b(bVar);
                }
            }
        }
        if (c1649q != null) {
            c1649q.m948b();
        }
        if (c1649q != null) {
            if (f2226a) {
                m931d("Loaded resource from active resources", j2, c1647o);
            }
            return c1649q;
        }
        C1632h c1632h = (C1632h) this.f2229d;
        synchronized (c1632h) {
            remove = c1632h.f2760a.remove(c1647o);
            if (remove != null) {
                c1632h.f2762c -= c1632h.mo899b(remove);
            }
        }
        InterfaceC1655w interfaceC1655w = (InterfaceC1655w) remove;
        C1649q<?> c1649q2 = interfaceC1655w == null ? null : interfaceC1655w instanceof C1649q ? (C1649q) interfaceC1655w : new C1649q<>(interfaceC1655w, true, true, c1647o, this);
        if (c1649q2 != null) {
            c1649q2.m948b();
            this.f2234i.m851a(c1647o, c1649q2);
        }
        if (c1649q2 == null) {
            return null;
        }
        if (f2226a) {
            m931d("Loaded resource from cache", j2, c1647o);
        }
        return c1649q2;
    }

    /* renamed from: e */
    public synchronized void m935e(C1645m<?> c1645m, InterfaceC1579k interfaceC1579k, C1649q<?> c1649q) {
        if (c1649q != null) {
            if (c1649q.f2293c) {
                this.f2234i.m851a(interfaceC1579k, c1649q);
            }
        }
        C1652t c1652t = this.f2227b;
        Objects.requireNonNull(c1652t);
        Map<InterfaceC1579k, C1645m<?>> m955a = c1652t.m955a(c1645m.f2270t);
        if (c1645m.equals(m955a.get(interfaceC1579k))) {
            m955a.remove(interfaceC1579k);
        }
    }

    /* renamed from: f */
    public void m936f(InterfaceC1655w<?> interfaceC1655w) {
        if (!(interfaceC1655w instanceof C1649q)) {
            throw new IllegalArgumentException("Cannot release anything but an EngineResource");
        }
        ((C1649q) interfaceC1655w).m949c();
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:27:0x00e9 A[Catch: all -> 0x0113, TryCatch #0 {, blocks: (B:20:0x00d3, B:22:0x00df, B:27:0x00e9, B:28:0x00fc, B:36:0x00ec, B:38:0x00f0, B:39:0x00f3, B:41:0x00f7, B:42:0x00fa), top: B:19:0x00d3 }] */
    /* JADX WARN: Removed duplicated region for block: B:36:0x00ec A[Catch: all -> 0x0113, TryCatch #0 {, blocks: (B:20:0x00d3, B:22:0x00df, B:27:0x00e9, B:28:0x00fc, B:36:0x00ec, B:38:0x00f0, B:39:0x00f3, B:41:0x00f7, B:42:0x00fa), top: B:19:0x00d3 }] */
    /* renamed from: g */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final <R> p005b.p143g.p144a.p147m.p150t.C1644l.d m937g(p005b.p143g.p144a.C1555e r17, java.lang.Object r18, p005b.p143g.p144a.p147m.InterfaceC1579k r19, int r20, int r21, java.lang.Class<?> r22, java.lang.Class<R> r23, p005b.p143g.p144a.EnumC1556f r24, p005b.p143g.p144a.p147m.p150t.AbstractC1643k r25, java.util.Map<java.lang.Class<?>, p005b.p143g.p144a.p147m.InterfaceC1586r<?>> r26, boolean r27, boolean r28, p005b.p143g.p144a.p147m.C1582n r29, boolean r30, boolean r31, boolean r32, boolean r33, p005b.p143g.p144a.p166q.InterfaceC1780g r34, java.util.concurrent.Executor r35, p005b.p143g.p144a.p147m.p150t.C1647o r36, long r37) {
        /*
            Method dump skipped, instructions count: 281
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p143g.p144a.p147m.p150t.C1644l.m937g(b.g.a.e, java.lang.Object, b.g.a.m.k, int, int, java.lang.Class, java.lang.Class, b.g.a.f, b.g.a.m.t.k, java.util.Map, boolean, boolean, b.g.a.m.n, boolean, boolean, boolean, boolean, b.g.a.q.g, java.util.concurrent.Executor, b.g.a.m.t.o, long):b.g.a.m.t.l$d");
    }
}
