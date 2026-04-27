package S;

import R.a;
import R.c;
import S.f;
import c0.C0326a;
import e0.C0514d;
import e0.InterfaceC0511a;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;

/* JADX INFO: loaded from: classes.dex */
public class g implements k, U.a {

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private static final Class f2686r = g.class;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private static final long f2687s = TimeUnit.HOURS.toMillis(2);

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private static final long f2688t = TimeUnit.MINUTES.toMillis(30);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final long f2689a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final long f2690b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final CountDownLatch f2691c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private long f2692d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final R.c f2693e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    final Set f2694f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private long f2695g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final long f2696h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final C0326a f2697i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final f f2698j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private final j f2699k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private final R.a f2700l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private final boolean f2701m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private final b f2702n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private final InterfaceC0511a f2703o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private final Object f2704p = new Object();

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private boolean f2705q;

    class a implements Runnable {
        a() {
        }

        @Override // java.lang.Runnable
        public void run() {
            synchronized (g.this.f2704p) {
                g.this.p();
            }
            g.this.f2705q = true;
            g.this.f2691c.countDown();
        }
    }

    static class b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private boolean f2707a = false;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private long f2708b = -1;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private long f2709c = -1;

        b() {
        }

        public synchronized long a() {
            return this.f2709c;
        }

        public synchronized long b() {
            return this.f2708b;
        }

        public synchronized void c(long j3, long j4) {
            if (this.f2707a) {
                this.f2708b += j3;
                this.f2709c += j4;
            }
        }

        public synchronized boolean d() {
            return this.f2707a;
        }

        public synchronized void e() {
            this.f2707a = false;
            this.f2709c = -1L;
            this.f2708b = -1L;
        }

        public synchronized void f(long j3, long j4) {
            this.f2709c = j4;
            this.f2708b = j3;
            this.f2707a = true;
        }
    }

    public static class c {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        public final long f2710a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        public final long f2711b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        public final long f2712c;

        public c(long j3, long j4, long j5) {
            this.f2710a = j3;
            this.f2711b = j4;
            this.f2712c = j5;
        }
    }

    public g(f fVar, j jVar, c cVar, R.c cVar2, R.a aVar, U.b bVar, Executor executor, boolean z3) {
        this.f2689a = cVar.f2711b;
        long j3 = cVar.f2712c;
        this.f2690b = j3;
        this.f2692d = j3;
        this.f2697i = C0326a.d();
        this.f2698j = fVar;
        this.f2699k = jVar;
        this.f2695g = -1L;
        this.f2693e = cVar2;
        this.f2696h = cVar.f2710a;
        this.f2700l = aVar;
        this.f2702n = new b();
        this.f2703o = C0514d.a();
        this.f2701m = z3;
        this.f2694f = new HashSet();
        if (bVar != null) {
            bVar.a(this);
        }
        if (!z3) {
            this.f2691c = new CountDownLatch(0);
        } else {
            this.f2691c = new CountDownLatch(1);
            executor.execute(new a());
        }
    }

    private Q.a l(f.b bVar, R.d dVar, String str) {
        Q.a aVarC;
        synchronized (this.f2704p) {
            aVarC = bVar.c(dVar);
            this.f2694f.add(str);
            this.f2702n.c(aVarC.size(), 1L);
        }
        return aVarC;
    }

    private void m(long j3, c.a aVar) throws IOException {
        try {
            Collection<f.a> collectionN = n(this.f2698j.b());
            long jB = this.f2702n.b();
            long j4 = jB - j3;
            int i3 = 0;
            long j5 = 0;
            for (f.a aVar2 : collectionN) {
                if (j5 > j4) {
                    break;
                }
                long jE = this.f2698j.e(aVar2);
                this.f2694f.remove(aVar2.getId());
                if (jE > 0) {
                    i3++;
                    j5 += jE;
                    l lVarE = l.a().j(aVar2.getId()).g(aVar).i(jE).f(jB - j5).e(j3);
                    R.c cVar = this.f2693e;
                    if (cVar != null) {
                        cVar.a(lVarE);
                    }
                    lVarE.b();
                }
            }
            this.f2702n.c(-j5, -i3);
            this.f2698j.d();
        } catch (IOException e3) {
            this.f2700l.a(a.EnumC0038a.EVICTION, f2686r, "evictAboveSize: " + e3.getMessage(), e3);
            throw e3;
        }
    }

    private Collection n(Collection collection) {
        long jNow = this.f2703o.now() + f2687s;
        ArrayList arrayList = new ArrayList(collection.size());
        ArrayList arrayList2 = new ArrayList(collection.size());
        Iterator it = collection.iterator();
        while (it.hasNext()) {
            f.a aVar = (f.a) it.next();
            if (aVar.a() > jNow) {
                arrayList.add(aVar);
            } else {
                arrayList2.add(aVar);
            }
        }
        Collections.sort(arrayList2, this.f2699k.get());
        arrayList.addAll(arrayList2);
        return arrayList;
    }

    private void o() {
        synchronized (this.f2704p) {
            try {
                boolean zP = p();
                s();
                long jB = this.f2702n.b();
                if (jB > this.f2692d && !zP) {
                    this.f2702n.e();
                    p();
                }
                long j3 = this.f2692d;
                if (jB > j3) {
                    m((j3 * 9) / 10, c.a.CACHE_FULL);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean p() {
        long jNow = this.f2703o.now();
        if (this.f2702n.d()) {
            long j3 = this.f2695g;
            if (j3 != -1 && jNow - j3 <= f2688t) {
                return false;
            }
        }
        return q();
    }

    private boolean q() {
        long j3;
        long jNow = this.f2703o.now();
        long j4 = f2687s + jNow;
        Set hashSet = (this.f2701m && this.f2694f.isEmpty()) ? this.f2694f : this.f2701m ? new HashSet() : null;
        try {
            long jI = 0;
            long jMax = -1;
            int i3 = 0;
            boolean z3 = false;
            int i4 = 0;
            int i5 = 0;
            for (f.a aVar : this.f2698j.b()) {
                i4++;
                jI += aVar.i();
                if (aVar.a() > j4) {
                    i5++;
                    i3 = (int) (((long) i3) + aVar.i());
                    j3 = j4;
                    jMax = Math.max(aVar.a() - jNow, jMax);
                    z3 = true;
                } else {
                    j3 = j4;
                    if (this.f2701m) {
                        X.k.g(hashSet);
                        hashSet.add(aVar.getId());
                    }
                }
                j4 = j3;
            }
            if (z3) {
                this.f2700l.a(a.EnumC0038a.READ_INVALID_ENTRY, f2686r, "Future timestamp found in " + i5 + " files , with a total size of " + i3 + " bytes, and a maximum time delta of " + jMax + "ms", null);
            }
            long j5 = i4;
            if (this.f2702n.a() != j5 || this.f2702n.b() != jI) {
                if (this.f2701m && this.f2694f != hashSet) {
                    X.k.g(hashSet);
                    this.f2694f.clear();
                    this.f2694f.addAll(hashSet);
                }
                this.f2702n.f(jI, j5);
            }
            this.f2695g = jNow;
            return true;
        } catch (IOException e3) {
            this.f2700l.a(a.EnumC0038a.GENERIC_IO, f2686r, "calcFileCacheSize: " + e3.getMessage(), e3);
            return false;
        }
    }

    private f.b r(String str, R.d dVar) {
        o();
        return this.f2698j.f(str, dVar);
    }

    private void s() {
        if (this.f2697i.f(this.f2698j.c() ? C0326a.EnumC0086a.EXTERNAL : C0326a.EnumC0086a.INTERNAL, this.f2690b - this.f2702n.b())) {
            this.f2692d = this.f2689a;
        } else {
            this.f2692d = this.f2690b;
        }
    }

    @Override // S.k
    public void a() {
        synchronized (this.f2704p) {
            try {
                this.f2698j.a();
                this.f2694f.clear();
                R.c cVar = this.f2693e;
                if (cVar != null) {
                    cVar.e();
                }
            } catch (IOException | NullPointerException e3) {
                this.f2700l.a(a.EnumC0038a.EVICTION, f2686r, "clearAll: " + e3.getMessage(), e3);
            }
            this.f2702n.e();
        }
    }

    @Override // S.k
    public boolean b(R.d dVar) {
        synchronized (this.f2704p) {
            try {
                List listB = R.e.b(dVar);
                for (int i3 = 0; i3 < listB.size(); i3++) {
                    if (this.f2694f.contains((String) listB.get(i3))) {
                        return true;
                    }
                }
                return false;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // S.k
    public Q.a c(R.d dVar, R.j jVar) {
        String strA;
        l lVarD = l.a().d(dVar);
        R.c cVar = this.f2693e;
        if (cVar != null) {
            cVar.h(lVarD);
        }
        synchronized (this.f2704p) {
            strA = R.e.a(dVar);
        }
        lVarD.j(strA);
        try {
            try {
                f.b bVarR = r(strA, dVar);
                try {
                    bVarR.b(jVar, dVar);
                    Q.a aVarL = l(bVarR, dVar, strA);
                    lVarD.i(aVarL.size()).f(this.f2702n.b());
                    R.c cVar2 = this.f2693e;
                    if (cVar2 != null) {
                        cVar2.b(lVarD);
                    }
                    return aVarL;
                } finally {
                    if (!bVarR.a()) {
                        Y.a.i(f2686r, "Failed to delete temp file");
                    }
                }
            } catch (IOException e3) {
                lVarD.h(e3);
                R.c cVar3 = this.f2693e;
                if (cVar3 != null) {
                    cVar3.f(lVarD);
                }
                Y.a.j(f2686r, "Failed inserting a file into the cache", e3);
                throw e3;
            }
        } finally {
            lVarD.b();
        }
    }

    @Override // S.k
    public Q.a d(R.d dVar) {
        Q.a aVarJ;
        l lVarD = l.a().d(dVar);
        try {
            synchronized (this.f2704p) {
                try {
                    List listB = R.e.b(dVar);
                    String str = null;
                    aVarJ = null;
                    for (int i3 = 0; i3 < listB.size(); i3++) {
                        str = (String) listB.get(i3);
                        lVarD.j(str);
                        aVarJ = this.f2698j.j(str, dVar);
                        if (aVarJ != null) {
                            break;
                        }
                    }
                    if (aVarJ == null) {
                        R.c cVar = this.f2693e;
                        if (cVar != null) {
                            cVar.d(lVarD);
                        }
                        this.f2694f.remove(str);
                    } else {
                        X.k.g(str);
                        R.c cVar2 = this.f2693e;
                        if (cVar2 != null) {
                            cVar2.g(lVarD);
                        }
                        this.f2694f.add(str);
                    }
                } finally {
                }
            }
            return aVarJ;
        } catch (IOException e3) {
            this.f2700l.a(a.EnumC0038a.GENERIC_IO, f2686r, "getResource", e3);
            lVarD.h(e3);
            R.c cVar3 = this.f2693e;
            if (cVar3 != null) {
                cVar3.c(lVarD);
            }
            return null;
        } finally {
            lVarD.b();
        }
    }

    @Override // S.k
    public boolean e(R.d dVar) throws Throwable {
        String str;
        IOException e3;
        String str2 = null;
        try {
            try {
                synchronized (this.f2704p) {
                    try {
                        List listB = R.e.b(dVar);
                        int i3 = 0;
                        while (i3 < listB.size()) {
                            String str3 = (String) listB.get(i3);
                            if (this.f2698j.g(str3, dVar)) {
                                this.f2694f.add(str3);
                                return true;
                            }
                            i3++;
                            str2 = str3;
                        }
                        return false;
                    } catch (Throwable th) {
                        str = str2;
                        th = th;
                        try {
                            throw th;
                        } catch (IOException e4) {
                            e3 = e4;
                            l lVarH = l.a().d(dVar).j(str).h(e3);
                            R.c cVar = this.f2693e;
                            if (cVar != null) {
                                cVar.c(lVarH);
                            }
                            lVarH.b();
                            return false;
                        }
                    }
                }
            } catch (Throwable th2) {
                th = th2;
            }
        } catch (IOException e5) {
            str = null;
            e3 = e5;
        }
    }

    @Override // S.k
    public boolean f(R.d dVar) {
        synchronized (this.f2704p) {
            if (b(dVar)) {
                return true;
            }
            try {
                List listB = R.e.b(dVar);
                for (int i3 = 0; i3 < listB.size(); i3++) {
                    String str = (String) listB.get(i3);
                    if (this.f2698j.i(str, dVar)) {
                        this.f2694f.add(str);
                        return true;
                    }
                }
                return false;
            } catch (IOException unused) {
                return false;
            }
        }
    }

    @Override // S.k
    public void g(R.d dVar) {
        synchronized (this.f2704p) {
            try {
                List listB = R.e.b(dVar);
                for (int i3 = 0; i3 < listB.size(); i3++) {
                    String str = (String) listB.get(i3);
                    this.f2698j.h(str);
                    this.f2694f.remove(str);
                }
            } catch (IOException e3) {
                this.f2700l.a(a.EnumC0038a.DELETE_FILE, f2686r, "delete: " + e3.getMessage(), e3);
            }
        }
    }
}
