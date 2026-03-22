package p005b.p143g.p144a.p147m.p150t;

import androidx.annotation.NonNull;
import androidx.annotation.VisibleForTesting;
import androidx.core.util.Pools;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicInteger;
import p005b.p143g.p144a.p147m.EnumC1569a;
import p005b.p143g.p144a.p147m.InterfaceC1579k;
import p005b.p143g.p144a.p147m.p150t.C1649q;
import p005b.p143g.p144a.p147m.p150t.RunnableC1641i;
import p005b.p143g.p144a.p147m.p150t.p153e0.ExecutorServiceC1637a;
import p005b.p143g.p144a.p166q.C1781h;
import p005b.p143g.p144a.p166q.InterfaceC1780g;
import p005b.p143g.p144a.p170s.C1802d;
import p005b.p143g.p144a.p170s.p171j.AbstractC1811d;
import p005b.p143g.p144a.p170s.p171j.C1808a;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.g.a.m.t.m */
/* loaded from: classes.dex */
public class C1645m<R> implements RunnableC1641i.a<R>, C1808a.d {

    /* renamed from: c */
    public static final c f2252c = new c();

    /* renamed from: A */
    public RunnableC1641i<R> f2253A;

    /* renamed from: B */
    public volatile boolean f2254B;

    /* renamed from: e */
    public final e f2255e;

    /* renamed from: f */
    public final AbstractC1811d f2256f;

    /* renamed from: g */
    public final C1649q.a f2257g;

    /* renamed from: h */
    public final Pools.Pool<C1645m<?>> f2258h;

    /* renamed from: i */
    public final c f2259i;

    /* renamed from: j */
    public final InterfaceC1646n f2260j;

    /* renamed from: k */
    public final ExecutorServiceC1637a f2261k;

    /* renamed from: l */
    public final ExecutorServiceC1637a f2262l;

    /* renamed from: m */
    public final ExecutorServiceC1637a f2263m;

    /* renamed from: n */
    public final ExecutorServiceC1637a f2264n;

    /* renamed from: o */
    public final AtomicInteger f2265o;

    /* renamed from: p */
    public InterfaceC1579k f2266p;

    /* renamed from: q */
    public boolean f2267q;

    /* renamed from: r */
    public boolean f2268r;

    /* renamed from: s */
    public boolean f2269s;

    /* renamed from: t */
    public boolean f2270t;

    /* renamed from: u */
    public InterfaceC1655w<?> f2271u;

    /* renamed from: v */
    public EnumC1569a f2272v;

    /* renamed from: w */
    public boolean f2273w;

    /* renamed from: x */
    public C1650r f2274x;

    /* renamed from: y */
    public boolean f2275y;

    /* renamed from: z */
    public C1649q<?> f2276z;

    /* renamed from: b.g.a.m.t.m$a */
    public class a implements Runnable {

        /* renamed from: c */
        public final InterfaceC1780g f2277c;

        public a(InterfaceC1780g interfaceC1780g) {
            this.f2277c = interfaceC1780g;
        }

        @Override // java.lang.Runnable
        public void run() {
            C1781h c1781h = (C1781h) this.f2277c;
            c1781h.f2695c.mo1155a();
            synchronized (c1781h.f2696d) {
                synchronized (C1645m.this) {
                    if (C1645m.this.f2255e.f2283c.contains(new d(this.f2277c, C1802d.f2756b))) {
                        C1645m c1645m = C1645m.this;
                        InterfaceC1780g interfaceC1780g = this.f2277c;
                        Objects.requireNonNull(c1645m);
                        try {
                            ((C1781h) interfaceC1780g).m1119l(c1645m.f2274x, 5);
                        } catch (Throwable th) {
                            throw new C1610c(th);
                        }
                    }
                    C1645m.this.m941d();
                }
            }
        }
    }

    /* renamed from: b.g.a.m.t.m$b */
    public class b implements Runnable {

        /* renamed from: c */
        public final InterfaceC1780g f2279c;

        public b(InterfaceC1780g interfaceC1780g) {
            this.f2279c = interfaceC1780g;
        }

        @Override // java.lang.Runnable
        public void run() {
            C1781h c1781h = (C1781h) this.f2279c;
            c1781h.f2695c.mo1155a();
            synchronized (c1781h.f2696d) {
                synchronized (C1645m.this) {
                    if (C1645m.this.f2255e.f2283c.contains(new d(this.f2279c, C1802d.f2756b))) {
                        C1645m.this.f2276z.m948b();
                        C1645m c1645m = C1645m.this;
                        InterfaceC1780g interfaceC1780g = this.f2279c;
                        Objects.requireNonNull(c1645m);
                        try {
                            ((C1781h) interfaceC1780g).m1120m(c1645m.f2276z, c1645m.f2272v);
                            C1645m.this.m945h(this.f2279c);
                        } catch (Throwable th) {
                            throw new C1610c(th);
                        }
                    }
                    C1645m.this.m941d();
                }
            }
        }
    }

    @VisibleForTesting
    /* renamed from: b.g.a.m.t.m$c */
    public static class c {
    }

    /* renamed from: b.g.a.m.t.m$d */
    public static final class d {

        /* renamed from: a */
        public final InterfaceC1780g f2281a;

        /* renamed from: b */
        public final Executor f2282b;

        public d(InterfaceC1780g interfaceC1780g, Executor executor) {
            this.f2281a = interfaceC1780g;
            this.f2282b = executor;
        }

        public boolean equals(Object obj) {
            if (obj instanceof d) {
                return this.f2281a.equals(((d) obj).f2281a);
            }
            return false;
        }

        public int hashCode() {
            return this.f2281a.hashCode();
        }
    }

    /* renamed from: b.g.a.m.t.m$e */
    public static final class e implements Iterable<d> {

        /* renamed from: c */
        public final List<d> f2283c = new ArrayList(2);

        public boolean isEmpty() {
            return this.f2283c.isEmpty();
        }

        @Override // java.lang.Iterable
        @NonNull
        public Iterator<d> iterator() {
            return this.f2283c.iterator();
        }
    }

    public C1645m(ExecutorServiceC1637a executorServiceC1637a, ExecutorServiceC1637a executorServiceC1637a2, ExecutorServiceC1637a executorServiceC1637a3, ExecutorServiceC1637a executorServiceC1637a4, InterfaceC1646n interfaceC1646n, C1649q.a aVar, Pools.Pool<C1645m<?>> pool) {
        c cVar = f2252c;
        this.f2255e = new e();
        this.f2256f = new AbstractC1811d.b();
        this.f2265o = new AtomicInteger();
        this.f2261k = executorServiceC1637a;
        this.f2262l = executorServiceC1637a2;
        this.f2263m = executorServiceC1637a3;
        this.f2264n = executorServiceC1637a4;
        this.f2260j = interfaceC1646n;
        this.f2257g = aVar;
        this.f2258h = pool;
        this.f2259i = cVar;
    }

    /* renamed from: a */
    public synchronized void m939a(InterfaceC1780g interfaceC1780g, Executor executor) {
        this.f2256f.mo1155a();
        this.f2255e.f2283c.add(new d(interfaceC1780g, executor));
        boolean z = true;
        if (this.f2273w) {
            m942e(1);
            executor.execute(new b(interfaceC1780g));
        } else if (this.f2275y) {
            m942e(1);
            executor.execute(new a(interfaceC1780g));
        } else {
            if (this.f2254B) {
                z = false;
            }
            C4195m.m4763E(z, "Cannot add callbacks to a cancelled EngineJob");
        }
    }

    @Override // p005b.p143g.p144a.p170s.p171j.C1808a.d
    @NonNull
    /* renamed from: b */
    public AbstractC1811d mo903b() {
        return this.f2256f;
    }

    /* renamed from: c */
    public void m940c() {
        if (m943f()) {
            return;
        }
        this.f2254B = true;
        RunnableC1641i<R> runnableC1641i = this.f2253A;
        runnableC1641i.f2174H = true;
        InterfaceC1639g interfaceC1639g = runnableC1641i.f2172F;
        if (interfaceC1639g != null) {
            interfaceC1639g.cancel();
        }
        InterfaceC1646n interfaceC1646n = this.f2260j;
        InterfaceC1579k interfaceC1579k = this.f2266p;
        C1644l c1644l = (C1644l) interfaceC1646n;
        synchronized (c1644l) {
            C1652t c1652t = c1644l.f2227b;
            Objects.requireNonNull(c1652t);
            Map<InterfaceC1579k, C1645m<?>> m955a = c1652t.m955a(this.f2270t);
            if (equals(m955a.get(interfaceC1579k))) {
                m955a.remove(interfaceC1579k);
            }
        }
    }

    /* renamed from: d */
    public void m941d() {
        C1649q<?> c1649q;
        synchronized (this) {
            this.f2256f.mo1155a();
            C4195m.m4763E(m943f(), "Not yet complete!");
            int decrementAndGet = this.f2265o.decrementAndGet();
            C4195m.m4763E(decrementAndGet >= 0, "Can't decrement below 0");
            if (decrementAndGet == 0) {
                c1649q = this.f2276z;
                m944g();
            } else {
                c1649q = null;
            }
        }
        if (c1649q != null) {
            c1649q.m949c();
        }
    }

    /* renamed from: e */
    public synchronized void m942e(int i2) {
        C1649q<?> c1649q;
        C4195m.m4763E(m943f(), "Not yet complete!");
        if (this.f2265o.getAndAdd(i2) == 0 && (c1649q = this.f2276z) != null) {
            c1649q.m948b();
        }
    }

    /* renamed from: f */
    public final boolean m943f() {
        return this.f2275y || this.f2273w || this.f2254B;
    }

    /* renamed from: g */
    public final synchronized void m944g() {
        boolean m924a;
        if (this.f2266p == null) {
            throw new IllegalArgumentException();
        }
        this.f2255e.f2283c.clear();
        this.f2266p = null;
        this.f2276z = null;
        this.f2271u = null;
        this.f2275y = false;
        this.f2254B = false;
        this.f2273w = false;
        RunnableC1641i<R> runnableC1641i = this.f2253A;
        RunnableC1641i.e eVar = runnableC1641i.f2181j;
        synchronized (eVar) {
            eVar.f2203a = true;
            m924a = eVar.m924a(false);
        }
        if (m924a) {
            runnableC1641i.m920l();
        }
        this.f2253A = null;
        this.f2274x = null;
        this.f2272v = null;
        this.f2258h.release(this);
    }

    /* renamed from: h */
    public synchronized void m945h(InterfaceC1780g interfaceC1780g) {
        boolean z;
        this.f2256f.mo1155a();
        this.f2255e.f2283c.remove(new d(interfaceC1780g, C1802d.f2756b));
        if (this.f2255e.isEmpty()) {
            m940c();
            if (!this.f2273w && !this.f2275y) {
                z = false;
                if (z && this.f2265o.get() == 0) {
                    m944g();
                }
            }
            z = true;
            if (z) {
                m944g();
            }
        }
    }

    /* renamed from: i */
    public void m946i(RunnableC1641i<?> runnableC1641i) {
        (this.f2268r ? this.f2263m : this.f2269s ? this.f2264n : this.f2262l).f2139f.execute(runnableC1641i);
    }
}
