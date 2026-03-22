package p005b.p143g.p144a.p147m.p150t;

import android.os.Build;
import android.os.SystemClock;
import android.util.Log;
import androidx.annotation.NonNull;
import androidx.core.util.Pools;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.C1555e;
import p005b.p143g.p144a.EnumC1556f;
import p005b.p143g.p144a.p147m.C1581m;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.EnumC1569a;
import p005b.p143g.p144a.p147m.InterfaceC1579k;
import p005b.p143g.p144a.p147m.InterfaceC1585q;
import p005b.p143g.p144a.p147m.p148s.C1592f;
import p005b.p143g.p144a.p147m.p148s.InterfaceC1590d;
import p005b.p143g.p144a.p147m.p148s.InterfaceC1591e;
import p005b.p143g.p144a.p147m.p150t.C1642j;
import p005b.p143g.p144a.p147m.p150t.C1644l;
import p005b.p143g.p144a.p147m.p150t.C1645m;
import p005b.p143g.p144a.p147m.p150t.C1649q;
import p005b.p143g.p144a.p147m.p150t.InterfaceC1639g;
import p005b.p143g.p144a.p147m.p156v.p157c.C1709n;
import p005b.p143g.p144a.p170s.C1803e;
import p005b.p143g.p144a.p170s.p171j.AbstractC1811d;
import p005b.p143g.p144a.p170s.p171j.C1808a;

/* renamed from: b.g.a.m.t.i */
/* loaded from: classes.dex */
public class RunnableC1641i<R> implements InterfaceC1639g.a, Runnable, Comparable<RunnableC1641i<?>>, C1808a.d {

    /* renamed from: A */
    public InterfaceC1579k f2167A;

    /* renamed from: B */
    public InterfaceC1579k f2168B;

    /* renamed from: C */
    public Object f2169C;

    /* renamed from: D */
    public EnumC1569a f2170D;

    /* renamed from: E */
    public InterfaceC1590d<?> f2171E;

    /* renamed from: F */
    public volatile InterfaceC1639g f2172F;

    /* renamed from: G */
    public volatile boolean f2173G;

    /* renamed from: H */
    public volatile boolean f2174H;

    /* renamed from: g */
    public final d f2178g;

    /* renamed from: h */
    public final Pools.Pool<RunnableC1641i<?>> f2179h;

    /* renamed from: k */
    public C1555e f2182k;

    /* renamed from: l */
    public InterfaceC1579k f2183l;

    /* renamed from: m */
    public EnumC1556f f2184m;

    /* renamed from: n */
    public C1647o f2185n;

    /* renamed from: o */
    public int f2186o;

    /* renamed from: p */
    public int f2187p;

    /* renamed from: q */
    public AbstractC1643k f2188q;

    /* renamed from: r */
    public C1582n f2189r;

    /* renamed from: s */
    public a<R> f2190s;

    /* renamed from: t */
    public int f2191t;

    /* renamed from: u */
    public g f2192u;

    /* renamed from: v */
    public f f2193v;

    /* renamed from: w */
    public long f2194w;

    /* renamed from: x */
    public boolean f2195x;

    /* renamed from: y */
    public Object f2196y;

    /* renamed from: z */
    public Thread f2197z;

    /* renamed from: c */
    public final C1640h<R> f2175c = new C1640h<>();

    /* renamed from: e */
    public final List<Throwable> f2176e = new ArrayList();

    /* renamed from: f */
    public final AbstractC1811d f2177f = new AbstractC1811d.b();

    /* renamed from: i */
    public final c<?> f2180i = new c<>();

    /* renamed from: j */
    public final e f2181j = new e();

    /* renamed from: b.g.a.m.t.i$a */
    public interface a<R> {
    }

    /* renamed from: b.g.a.m.t.i$b */
    public final class b<Z> implements C1642j.a<Z> {

        /* renamed from: a */
        public final EnumC1569a f2198a;

        public b(EnumC1569a enumC1569a) {
            this.f2198a = enumC1569a;
        }
    }

    /* renamed from: b.g.a.m.t.i$c */
    public static class c<Z> {

        /* renamed from: a */
        public InterfaceC1579k f2200a;

        /* renamed from: b */
        public InterfaceC1585q<Z> f2201b;

        /* renamed from: c */
        public C1654v<Z> f2202c;
    }

    /* renamed from: b.g.a.m.t.i$d */
    public interface d {
    }

    /* renamed from: b.g.a.m.t.i$e */
    public static class e {

        /* renamed from: a */
        public boolean f2203a;

        /* renamed from: b */
        public boolean f2204b;

        /* renamed from: c */
        public boolean f2205c;

        /* renamed from: a */
        public final boolean m924a(boolean z) {
            return (this.f2205c || z || this.f2204b) && this.f2203a;
        }
    }

    /* renamed from: b.g.a.m.t.i$f */
    public enum f {
        INITIALIZE,
        SWITCH_TO_SOURCE_SERVICE,
        DECODE_DATA
    }

    /* renamed from: b.g.a.m.t.i$g */
    public enum g {
        INITIALIZE,
        RESOURCE_CACHE,
        DATA_CACHE,
        SOURCE,
        ENCODE,
        FINISHED
    }

    public RunnableC1641i(d dVar, Pools.Pool<RunnableC1641i<?>> pool) {
        this.f2178g = dVar;
        this.f2179h = pool;
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1639g.a
    /* renamed from: a */
    public void mo853a(InterfaceC1579k interfaceC1579k, Exception exc, InterfaceC1590d<?> interfaceC1590d, EnumC1569a enumC1569a) {
        interfaceC1590d.mo835b();
        C1650r c1650r = new C1650r("Fetching data failed", exc);
        Class<?> mo832a = interfaceC1590d.mo832a();
        c1650r.f2302f = interfaceC1579k;
        c1650r.f2303g = enumC1569a;
        c1650r.f2304h = mo832a;
        this.f2176e.add(c1650r);
        if (Thread.currentThread() == this.f2197z) {
            m921m();
        } else {
            this.f2193v = f.SWITCH_TO_SOURCE_SERVICE;
            ((C1645m) this.f2190s).m946i(this);
        }
    }

    @Override // p005b.p143g.p144a.p170s.p171j.C1808a.d
    @NonNull
    /* renamed from: b */
    public AbstractC1811d mo903b() {
        return this.f2177f;
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1639g.a
    /* renamed from: c */
    public void mo855c() {
        this.f2193v = f.SWITCH_TO_SOURCE_SERVICE;
        ((C1645m) this.f2190s).m946i(this);
    }

    @Override // java.lang.Comparable
    public int compareTo(@NonNull RunnableC1641i<?> runnableC1641i) {
        RunnableC1641i<?> runnableC1641i2 = runnableC1641i;
        int ordinal = this.f2184m.ordinal() - runnableC1641i2.f2184m.ordinal();
        return ordinal == 0 ? this.f2191t - runnableC1641i2.f2191t : ordinal;
    }

    @Override // p005b.p143g.p144a.p147m.p150t.InterfaceC1639g.a
    /* renamed from: d */
    public void mo856d(InterfaceC1579k interfaceC1579k, Object obj, InterfaceC1590d<?> interfaceC1590d, EnumC1569a enumC1569a, InterfaceC1579k interfaceC1579k2) {
        this.f2167A = interfaceC1579k;
        this.f2169C = obj;
        this.f2171E = interfaceC1590d;
        this.f2170D = enumC1569a;
        this.f2168B = interfaceC1579k2;
        if (Thread.currentThread() == this.f2197z) {
            m915g();
        } else {
            this.f2193v = f.DECODE_DATA;
            ((C1645m) this.f2190s).m946i(this);
        }
    }

    /* renamed from: e */
    public final <Data> InterfaceC1655w<R> m913e(InterfaceC1590d<?> interfaceC1590d, Data data, EnumC1569a enumC1569a) {
        if (data == null) {
            return null;
        }
        try {
            int i2 = C1803e.f2759b;
            long elapsedRealtimeNanos = SystemClock.elapsedRealtimeNanos();
            InterfaceC1655w<R> m914f = m914f(data, enumC1569a);
            if (Log.isLoggable("DecodeJob", 2)) {
                m918j("Decoded result " + m914f, elapsedRealtimeNanos, null);
            }
            return m914f;
        } finally {
            interfaceC1590d.mo835b();
        }
    }

    /* renamed from: f */
    public final <Data> InterfaceC1655w<R> m914f(Data data, EnumC1569a enumC1569a) {
        InterfaceC1591e<Data> mo844b;
        C1653u<Data, ?, R> m909d = this.f2175c.m909d(data.getClass());
        C1582n c1582n = this.f2189r;
        if (Build.VERSION.SDK_INT >= 26) {
            boolean z = enumC1569a == EnumC1569a.RESOURCE_DISK_CACHE || this.f2175c.f2166r;
            C1581m<Boolean> c1581m = C1709n.f2509d;
            Boolean bool = (Boolean) c1582n.m827a(c1581m);
            if (bool == null || (bool.booleanValue() && !z)) {
                c1582n = new C1582n();
                c1582n.m828b(this.f2189r);
                c1582n.f1995b.put(c1581m, Boolean.valueOf(z));
            }
        }
        C1582n c1582n2 = c1582n;
        C1592f c1592f = this.f2182k.f1836c.f1854e;
        synchronized (c1592f) {
            InterfaceC1591e.a<?> aVar = c1592f.f2007b.get(data.getClass());
            if (aVar == null) {
                Iterator<InterfaceC1591e.a<?>> it = c1592f.f2007b.values().iterator();
                while (true) {
                    if (!it.hasNext()) {
                        break;
                    }
                    InterfaceC1591e.a<?> next = it.next();
                    if (next.mo843a().isAssignableFrom(data.getClass())) {
                        aVar = next;
                        break;
                    }
                }
            }
            if (aVar == null) {
                aVar = C1592f.f2006a;
            }
            mo844b = aVar.mo844b(data);
        }
        try {
            return m909d.m956a(mo844b, c1582n2, this.f2186o, this.f2187p, new b(enumC1569a));
        } finally {
            mo844b.mo842b();
        }
    }

    /* renamed from: g */
    public final void m915g() {
        C1654v c1654v;
        boolean m924a;
        if (Log.isLoggable("DecodeJob", 2)) {
            long j2 = this.f2194w;
            StringBuilder m586H = C1499a.m586H("data: ");
            m586H.append(this.f2169C);
            m586H.append(", cache key: ");
            m586H.append(this.f2167A);
            m586H.append(", fetcher: ");
            m586H.append(this.f2171E);
            m918j("Retrieved data", j2, m586H.toString());
        }
        C1654v c1654v2 = null;
        try {
            c1654v = m913e(this.f2171E, this.f2169C, this.f2170D);
        } catch (C1650r e2) {
            InterfaceC1579k interfaceC1579k = this.f2168B;
            EnumC1569a enumC1569a = this.f2170D;
            e2.f2302f = interfaceC1579k;
            e2.f2303g = enumC1569a;
            e2.f2304h = null;
            this.f2176e.add(e2);
            c1654v = null;
        }
        if (c1654v == null) {
            m921m();
            return;
        }
        EnumC1569a enumC1569a2 = this.f2170D;
        if (c1654v instanceof InterfaceC1651s) {
            ((InterfaceC1651s) c1654v).initialize();
        }
        if (this.f2180i.f2202c != null) {
            c1654v2 = C1654v.m957c(c1654v);
            c1654v = c1654v2;
        }
        m923o();
        C1645m<?> c1645m = (C1645m) this.f2190s;
        synchronized (c1645m) {
            c1645m.f2271u = c1654v;
            c1645m.f2272v = enumC1569a2;
        }
        synchronized (c1645m) {
            c1645m.f2256f.mo1155a();
            if (c1645m.f2254B) {
                c1645m.f2271u.recycle();
                c1645m.m944g();
            } else {
                if (c1645m.f2255e.isEmpty()) {
                    throw new IllegalStateException("Received a resource without any callbacks to notify");
                }
                if (c1645m.f2273w) {
                    throw new IllegalStateException("Already have resource");
                }
                C1645m.c cVar = c1645m.f2259i;
                InterfaceC1655w<?> interfaceC1655w = c1645m.f2271u;
                boolean z = c1645m.f2267q;
                InterfaceC1579k interfaceC1579k2 = c1645m.f2266p;
                C1649q.a aVar = c1645m.f2257g;
                Objects.requireNonNull(cVar);
                c1645m.f2276z = new C1649q<>(interfaceC1655w, z, true, interfaceC1579k2, aVar);
                c1645m.f2273w = true;
                C1645m.e eVar = c1645m.f2255e;
                Objects.requireNonNull(eVar);
                ArrayList arrayList = new ArrayList(eVar.f2283c);
                c1645m.m942e(arrayList.size() + 1);
                ((C1644l) c1645m.f2260j).m935e(c1645m, c1645m.f2266p, c1645m.f2276z);
                Iterator it = arrayList.iterator();
                while (it.hasNext()) {
                    C1645m.d dVar = (C1645m.d) it.next();
                    dVar.f2282b.execute(new C1645m.b(dVar.f2281a));
                }
                c1645m.m941d();
            }
        }
        this.f2192u = g.ENCODE;
        try {
            c<?> cVar2 = this.f2180i;
            if (cVar2.f2202c != null) {
                try {
                    ((C1644l.c) this.f2178g).m938a().mo894a(cVar2.f2200a, new C1638f(cVar2.f2201b, cVar2.f2202c, this.f2189r));
                    cVar2.f2202c.m958d();
                } catch (Throwable th) {
                    cVar2.f2202c.m958d();
                    throw th;
                }
            }
            e eVar2 = this.f2181j;
            synchronized (eVar2) {
                eVar2.f2204b = true;
                m924a = eVar2.m924a(false);
            }
            if (m924a) {
                m920l();
            }
        } finally {
            if (c1654v2 != null) {
                c1654v2.m958d();
            }
        }
    }

    /* renamed from: h */
    public final InterfaceC1639g m916h() {
        int ordinal = this.f2192u.ordinal();
        if (ordinal == 1) {
            return new C1656x(this.f2175c, this);
        }
        if (ordinal == 2) {
            return new C1624d(this.f2175c, this);
        }
        if (ordinal == 3) {
            return new C1609b0(this.f2175c, this);
        }
        if (ordinal == 5) {
            return null;
        }
        StringBuilder m586H = C1499a.m586H("Unrecognized stage: ");
        m586H.append(this.f2192u);
        throw new IllegalStateException(m586H.toString());
    }

    /* renamed from: i */
    public final g m917i(g gVar) {
        g gVar2 = g.RESOURCE_CACHE;
        g gVar3 = g.DATA_CACHE;
        g gVar4 = g.FINISHED;
        int ordinal = gVar.ordinal();
        if (ordinal == 0) {
            return this.f2188q.mo928b() ? gVar2 : m917i(gVar2);
        }
        if (ordinal == 1) {
            return this.f2188q.mo927a() ? gVar3 : m917i(gVar3);
        }
        if (ordinal == 2) {
            return this.f2195x ? gVar4 : g.SOURCE;
        }
        if (ordinal == 3 || ordinal == 5) {
            return gVar4;
        }
        throw new IllegalArgumentException("Unrecognized stage: " + gVar);
    }

    /* renamed from: j */
    public final void m918j(String str, long j2, String str2) {
        StringBuilder m590L = C1499a.m590L(str, " in ");
        m590L.append(C1803e.m1138a(j2));
        m590L.append(", load key: ");
        m590L.append(this.f2185n);
        m590L.append(str2 != null ? C1499a.m637w(", ", str2) : "");
        m590L.append(", thread: ");
        m590L.append(Thread.currentThread().getName());
        m590L.toString();
    }

    /* renamed from: k */
    public final void m919k() {
        boolean m924a;
        m923o();
        C1650r c1650r = new C1650r("Failed to load resource", new ArrayList(this.f2176e));
        C1645m<?> c1645m = (C1645m) this.f2190s;
        synchronized (c1645m) {
            c1645m.f2274x = c1650r;
        }
        synchronized (c1645m) {
            c1645m.f2256f.mo1155a();
            if (c1645m.f2254B) {
                c1645m.m944g();
            } else {
                if (c1645m.f2255e.isEmpty()) {
                    throw new IllegalStateException("Received an exception without any callbacks to notify");
                }
                if (c1645m.f2275y) {
                    throw new IllegalStateException("Already failed once");
                }
                c1645m.f2275y = true;
                InterfaceC1579k interfaceC1579k = c1645m.f2266p;
                C1645m.e eVar = c1645m.f2255e;
                Objects.requireNonNull(eVar);
                ArrayList arrayList = new ArrayList(eVar.f2283c);
                c1645m.m942e(arrayList.size() + 1);
                ((C1644l) c1645m.f2260j).m935e(c1645m, interfaceC1579k, null);
                Iterator it = arrayList.iterator();
                while (it.hasNext()) {
                    C1645m.d dVar = (C1645m.d) it.next();
                    dVar.f2282b.execute(new C1645m.a(dVar.f2281a));
                }
                c1645m.m941d();
            }
        }
        e eVar2 = this.f2181j;
        synchronized (eVar2) {
            eVar2.f2205c = true;
            m924a = eVar2.m924a(false);
        }
        if (m924a) {
            m920l();
        }
    }

    /* renamed from: l */
    public final void m920l() {
        e eVar = this.f2181j;
        synchronized (eVar) {
            eVar.f2204b = false;
            eVar.f2203a = false;
            eVar.f2205c = false;
        }
        c<?> cVar = this.f2180i;
        cVar.f2200a = null;
        cVar.f2201b = null;
        cVar.f2202c = null;
        C1640h<R> c1640h = this.f2175c;
        c1640h.f2151c = null;
        c1640h.f2152d = null;
        c1640h.f2162n = null;
        c1640h.f2155g = null;
        c1640h.f2159k = null;
        c1640h.f2157i = null;
        c1640h.f2163o = null;
        c1640h.f2158j = null;
        c1640h.f2164p = null;
        c1640h.f2149a.clear();
        c1640h.f2160l = false;
        c1640h.f2150b.clear();
        c1640h.f2161m = false;
        this.f2173G = false;
        this.f2182k = null;
        this.f2183l = null;
        this.f2189r = null;
        this.f2184m = null;
        this.f2185n = null;
        this.f2190s = null;
        this.f2192u = null;
        this.f2172F = null;
        this.f2197z = null;
        this.f2167A = null;
        this.f2169C = null;
        this.f2170D = null;
        this.f2171E = null;
        this.f2194w = 0L;
        this.f2174H = false;
        this.f2196y = null;
        this.f2176e.clear();
        this.f2179h.release(this);
    }

    /* renamed from: m */
    public final void m921m() {
        this.f2197z = Thread.currentThread();
        int i2 = C1803e.f2759b;
        this.f2194w = SystemClock.elapsedRealtimeNanos();
        boolean z = false;
        while (!this.f2174H && this.f2172F != null && !(z = this.f2172F.mo854b())) {
            this.f2192u = m917i(this.f2192u);
            this.f2172F = m916h();
            if (this.f2192u == g.SOURCE) {
                this.f2193v = f.SWITCH_TO_SOURCE_SERVICE;
                ((C1645m) this.f2190s).m946i(this);
                return;
            }
        }
        if ((this.f2192u == g.FINISHED || this.f2174H) && !z) {
            m919k();
        }
    }

    /* renamed from: n */
    public final void m922n() {
        int ordinal = this.f2193v.ordinal();
        if (ordinal == 0) {
            this.f2192u = m917i(g.INITIALIZE);
            this.f2172F = m916h();
            m921m();
        } else if (ordinal == 1) {
            m921m();
        } else if (ordinal == 2) {
            m915g();
        } else {
            StringBuilder m586H = C1499a.m586H("Unrecognized run reason: ");
            m586H.append(this.f2193v);
            throw new IllegalStateException(m586H.toString());
        }
    }

    /* renamed from: o */
    public final void m923o() {
        this.f2177f.mo1155a();
        if (this.f2173G) {
            throw new IllegalStateException("Already notified", this.f2176e.isEmpty() ? null : (Throwable) C1499a.m611d(this.f2176e, 1));
        }
        this.f2173G = true;
    }

    @Override // java.lang.Runnable
    public void run() {
        InterfaceC1590d<?> interfaceC1590d = this.f2171E;
        try {
            try {
                try {
                    if (this.f2174H) {
                        m919k();
                        if (interfaceC1590d != null) {
                            interfaceC1590d.mo835b();
                            return;
                        }
                        return;
                    }
                    m922n();
                    if (interfaceC1590d != null) {
                        interfaceC1590d.mo835b();
                    }
                } catch (Throwable th) {
                    if (Log.isLoggable("DecodeJob", 3)) {
                        String str = "DecodeJob threw unexpectedly, isCancelled: " + this.f2174H + ", stage: " + this.f2192u;
                    }
                    if (this.f2192u != g.ENCODE) {
                        this.f2176e.add(th);
                        m919k();
                    }
                    if (!this.f2174H) {
                        throw th;
                    }
                    throw th;
                }
            } catch (C1610c e2) {
                throw e2;
            }
        } catch (Throwable th2) {
            if (interfaceC1590d != null) {
                interfaceC1590d.mo835b();
            }
            throw th2;
        }
    }
}
