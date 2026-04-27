package G0;

import G0.n;
import G0.x;
import android.os.SystemClock;
import b0.AbstractC0311a;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Map;
import java.util.WeakHashMap;

/* JADX INFO: loaded from: classes.dex */
public class w implements n, x {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    final m f822a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    final m f823b;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final D f825d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final x.a f826e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final X.n f827f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    protected y f828g;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final boolean f830i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final boolean f831j;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    final Map f824c = new WeakHashMap();

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private long f829h = SystemClock.uptimeMillis();

    class a implements D {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ D f832a;

        a(D d3) {
            this.f832a = d3;
        }

        @Override // G0.D
        /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
        public int a(n.a aVar) {
            return w.this.f830i ? aVar.f812f : this.f832a.a(aVar.f808b.P());
        }
    }

    class b implements b0.g {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ n.a f834a;

        b(n.a aVar) {
            this.f834a = aVar;
        }

        @Override // b0.g
        public void a(Object obj) {
            w.this.y(this.f834a);
        }
    }

    public w(D d3, x.a aVar, X.n nVar, n.b bVar, boolean z3, boolean z4) {
        this.f825d = d3;
        this.f822a = new m(A(d3));
        this.f823b = new m(A(d3));
        this.f826e = aVar;
        this.f827f = nVar;
        this.f828g = (y) X.k.h((y) nVar.get(), "mMemoryCacheParamsSupplier returned null");
        this.f830i = z3;
        this.f831j = z4;
    }

    private D A(D d3) {
        return new a(d3);
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x0021  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private synchronized boolean i(int r4) {
        /*
            r3 = this;
            monitor-enter(r3)
            G0.y r0 = r3.f828g     // Catch: java.lang.Throwable -> L1f
            int r0 = r0.f840e     // Catch: java.lang.Throwable -> L1f
            if (r4 > r0) goto L21
            int r0 = r3.k()     // Catch: java.lang.Throwable -> L1f
            G0.y r1 = r3.f828g     // Catch: java.lang.Throwable -> L1f
            int r1 = r1.f837b     // Catch: java.lang.Throwable -> L1f
            r2 = 1
            int r1 = r1 - r2
            if (r0 > r1) goto L21
            int r0 = r3.l()     // Catch: java.lang.Throwable -> L1f
            G0.y r1 = r3.f828g     // Catch: java.lang.Throwable -> L1f
            int r1 = r1.f836a     // Catch: java.lang.Throwable -> L1f
            int r1 = r1 - r4
            if (r0 > r1) goto L21
            goto L22
        L1f:
            r4 = move-exception
            goto L24
        L21:
            r2 = 0
        L22:
            monitor-exit(r3)
            return r2
        L24:
            monitor-exit(r3)     // Catch: java.lang.Throwable -> L1f
            throw r4
        */
        throw new UnsupportedOperationException("Method not decompiled: G0.w.i(int):boolean");
    }

    private synchronized void j(n.a aVar) {
        X.k.g(aVar);
        X.k.i(aVar.f809c > 0);
        aVar.f809c--;
    }

    private synchronized void m(n.a aVar) {
        X.k.g(aVar);
        X.k.i(!aVar.f810d);
        aVar.f809c++;
    }

    private synchronized void n(n.a aVar) {
        X.k.g(aVar);
        X.k.i(!aVar.f810d);
        aVar.f810d = true;
    }

    private synchronized void o(ArrayList arrayList) {
        if (arrayList != null) {
            Iterator it = arrayList.iterator();
            while (it.hasNext()) {
                n((n.a) it.next());
            }
        }
    }

    private synchronized boolean p(n.a aVar) {
        if (aVar.f810d || aVar.f809c != 0) {
            return false;
        }
        this.f822a.g(aVar.f807a, aVar);
        return true;
    }

    private void q(ArrayList arrayList) {
        if (arrayList != null) {
            Iterator it = arrayList.iterator();
            while (it.hasNext()) {
                AbstractC0311a.D(x((n.a) it.next()));
            }
        }
    }

    private void u(ArrayList arrayList) {
        if (arrayList != null) {
            Iterator it = arrayList.iterator();
            while (it.hasNext()) {
                t((n.a) it.next());
            }
        }
    }

    private synchronized void v() {
        if (this.f829h + this.f828g.f841f > SystemClock.uptimeMillis()) {
            return;
        }
        this.f829h = SystemClock.uptimeMillis();
        this.f828g = (y) X.k.h((y) this.f827f.get(), "mMemoryCacheParamsSupplier returned null");
    }

    private synchronized AbstractC0311a w(n.a aVar) {
        m(aVar);
        return AbstractC0311a.n0(aVar.f808b.P(), new b(aVar));
    }

    private synchronized AbstractC0311a x(n.a aVar) {
        X.k.g(aVar);
        return (aVar.f810d && aVar.f809c == 0) ? aVar.f808b : null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void y(n.a aVar) {
        boolean zP;
        AbstractC0311a abstractC0311aX;
        X.k.g(aVar);
        synchronized (this) {
            j(aVar);
            zP = p(aVar);
            abstractC0311aX = x(aVar);
        }
        AbstractC0311a.D(abstractC0311aX);
        if (!zP) {
            aVar = null;
        }
        s(aVar);
        v();
        r();
    }

    private synchronized ArrayList z(int i3, int i4) {
        int iMax = Math.max(i3, 0);
        int iMax2 = Math.max(i4, 0);
        if (this.f822a.b() <= iMax && this.f822a.e() <= iMax2) {
            return null;
        }
        ArrayList arrayList = new ArrayList();
        while (true) {
            if (this.f822a.b() <= iMax && this.f822a.e() <= iMax2) {
                break;
            }
            Object objC = this.f822a.c();
            if (objC != null) {
                this.f822a.h(objC);
                arrayList.add((n.a) this.f823b.h(objC));
            } else {
                if (!this.f831j) {
                    throw new IllegalStateException(String.format("key is null, but exclusiveEntries count: %d, size: %d", Integer.valueOf(this.f822a.b()), Integer.valueOf(this.f822a.e())));
                }
                this.f822a.j();
            }
        }
        return arrayList;
    }

    @Override // G0.x
    public AbstractC0311a b(Object obj, AbstractC0311a abstractC0311a) {
        return h(obj, abstractC0311a, null);
    }

    @Override // G0.x
    public void c(Object obj) {
        X.k.g(obj);
        synchronized (this) {
            try {
                n.a aVar = (n.a) this.f822a.h(obj);
                if (aVar != null) {
                    this.f822a.g(obj, aVar);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // G0.x
    public synchronized boolean d(X.l lVar) {
        return !this.f823b.d(lVar).isEmpty();
    }

    @Override // G0.x
    public int e(X.l lVar) {
        ArrayList arrayListI;
        ArrayList arrayListI2;
        synchronized (this) {
            arrayListI = this.f822a.i(lVar);
            arrayListI2 = this.f823b.i(lVar);
            o(arrayListI2);
        }
        q(arrayListI2);
        u(arrayListI);
        v();
        r();
        return arrayListI2.size();
    }

    @Override // G0.x
    public AbstractC0311a get(Object obj) {
        n.a aVar;
        AbstractC0311a abstractC0311aW;
        X.k.g(obj);
        synchronized (this) {
            try {
                aVar = (n.a) this.f822a.h(obj);
                n.a aVar2 = (n.a) this.f823b.a(obj);
                abstractC0311aW = aVar2 != null ? w(aVar2) : null;
            } catch (Throwable th) {
                throw th;
            }
        }
        t(aVar);
        v();
        r();
        return abstractC0311aW;
    }

    public AbstractC0311a h(Object obj, AbstractC0311a abstractC0311a, n.b bVar) {
        n.a aVar;
        AbstractC0311a abstractC0311aW;
        AbstractC0311a abstractC0311aX;
        X.k.g(obj);
        X.k.g(abstractC0311a);
        v();
        synchronized (this) {
            try {
                aVar = (n.a) this.f822a.h(obj);
                n.a aVar2 = (n.a) this.f823b.h(obj);
                abstractC0311aW = null;
                if (aVar2 != null) {
                    n(aVar2);
                    abstractC0311aX = x(aVar2);
                } else {
                    abstractC0311aX = null;
                }
                int iA = this.f825d.a(abstractC0311a.P());
                if (i(iA)) {
                    n.a aVarA = this.f830i ? n.a.a(obj, abstractC0311a, iA, bVar) : n.a.b(obj, abstractC0311a, bVar);
                    this.f823b.g(obj, aVarA);
                    abstractC0311aW = w(aVarA);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        AbstractC0311a.D(abstractC0311aX);
        t(aVar);
        r();
        return abstractC0311aW;
    }

    public synchronized int k() {
        return this.f823b.b() - this.f822a.b();
    }

    public synchronized int l() {
        return this.f823b.e() - this.f822a.e();
    }

    public void r() {
        ArrayList arrayListZ;
        synchronized (this) {
            y yVar = this.f828g;
            int iMin = Math.min(yVar.f839d, yVar.f837b - k());
            y yVar2 = this.f828g;
            arrayListZ = z(iMin, Math.min(yVar2.f838c, yVar2.f836a - l()));
            o(arrayListZ);
        }
        q(arrayListZ);
        u(arrayListZ);
    }

    private static void s(n.a aVar) {
    }

    private static void t(n.a aVar) {
    }
}
