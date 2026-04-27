package N;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CancellationException;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;

/* JADX INFO: loaded from: classes.dex */
public class f {

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    public static final ExecutorService f1847i = N.b.a();

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private static final Executor f1848j = N.b.b();

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    public static final Executor f1849k = N.a.c();

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private static f f1850l = new f((Object) null);

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private static f f1851m = new f(Boolean.TRUE);

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private static f f1852n = new f(Boolean.FALSE);

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private static f f1853o = new f(true);

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private boolean f1855b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private boolean f1856c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private Object f1857d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private Exception f1858e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private boolean f1859f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private h f1860g;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Object f1854a = new Object();

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private List f1861h = new ArrayList();

    class a implements N.d {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ g f1862a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ N.d f1863b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ Executor f1864c;

        a(g gVar, N.d dVar, Executor executor, N.c cVar) {
            this.f1862a = gVar;
            this.f1863b = dVar;
            this.f1864c = executor;
        }

        @Override // N.d
        /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
        public Void a(f fVar) {
            f.d(this.f1862a, this.f1863b, fVar, this.f1864c, null);
            return null;
        }
    }

    static class b implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ g f1866b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ N.d f1867c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ f f1868d;

        b(N.c cVar, g gVar, N.d dVar, f fVar) {
            this.f1866b = gVar;
            this.f1867c = dVar;
            this.f1868d = fVar;
        }

        @Override // java.lang.Runnable
        public void run() {
            try {
                this.f1866b.d(this.f1867c.a(this.f1868d));
            } catch (CancellationException unused) {
                this.f1866b.b();
            } catch (Exception e3) {
                this.f1866b.c(e3);
            }
        }
    }

    static class c implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ g f1869b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ Callable f1870c;

        c(N.c cVar, g gVar, Callable callable) {
            this.f1869b = gVar;
            this.f1870c = callable;
        }

        @Override // java.lang.Runnable
        public void run() {
            try {
                this.f1869b.d(this.f1870c.call());
            } catch (CancellationException unused) {
                this.f1869b.b();
            } catch (Exception e3) {
                this.f1869b.c(e3);
            }
        }
    }

    public interface d {
    }

    f() {
    }

    public static f b(Callable callable, Executor executor) {
        return c(callable, executor, null);
    }

    public static f c(Callable callable, Executor executor, N.c cVar) {
        g gVar = new g();
        try {
            executor.execute(new c(cVar, gVar, callable));
        } catch (Exception e3) {
            gVar.c(new e(e3));
        }
        return gVar.a();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void d(g gVar, N.d dVar, f fVar, Executor executor, N.c cVar) {
        try {
            executor.execute(new b(cVar, gVar, dVar, fVar));
        } catch (Exception e3) {
            gVar.c(new e(e3));
        }
    }

    public static f g(Exception exc) {
        g gVar = new g();
        gVar.c(exc);
        return gVar.a();
    }

    public static f h(Object obj) {
        if (obj == null) {
            return f1850l;
        }
        if (obj instanceof Boolean) {
            return ((Boolean) obj).booleanValue() ? f1851m : f1852n;
        }
        g gVar = new g();
        gVar.d(obj);
        return gVar.a();
    }

    public static d k() {
        return null;
    }

    private void o() {
        synchronized (this.f1854a) {
            Iterator it = this.f1861h.iterator();
            while (it.hasNext()) {
                try {
                    ((N.d) it.next()).a(this);
                } catch (RuntimeException e3) {
                    throw e3;
                } catch (Exception e4) {
                    throw new RuntimeException(e4);
                }
            }
            this.f1861h = null;
        }
    }

    public f e(N.d dVar) {
        return f(dVar, f1848j, null);
    }

    public f f(N.d dVar, Executor executor, N.c cVar) {
        boolean zM;
        g gVar = new g();
        synchronized (this.f1854a) {
            try {
                zM = m();
                if (!zM) {
                    this.f1861h.add(new a(gVar, dVar, executor, cVar));
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        if (zM) {
            d(gVar, dVar, this, executor, cVar);
        }
        return gVar.a();
    }

    public Exception i() {
        Exception exc;
        synchronized (this.f1854a) {
            try {
                if (this.f1858e != null) {
                    this.f1859f = true;
                }
                exc = this.f1858e;
            } catch (Throwable th) {
                throw th;
            }
        }
        return exc;
    }

    public Object j() {
        Object obj;
        synchronized (this.f1854a) {
            obj = this.f1857d;
        }
        return obj;
    }

    public boolean l() {
        boolean z3;
        synchronized (this.f1854a) {
            z3 = this.f1856c;
        }
        return z3;
    }

    public boolean m() {
        boolean z3;
        synchronized (this.f1854a) {
            z3 = this.f1855b;
        }
        return z3;
    }

    public boolean n() {
        boolean z3;
        synchronized (this.f1854a) {
            z3 = i() != null;
        }
        return z3;
    }

    boolean p() {
        synchronized (this.f1854a) {
            try {
                if (this.f1855b) {
                    return false;
                }
                this.f1855b = true;
                this.f1856c = true;
                this.f1854a.notifyAll();
                o();
                return true;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    boolean q(Exception exc) {
        synchronized (this.f1854a) {
            try {
                if (this.f1855b) {
                    return false;
                }
                this.f1855b = true;
                this.f1858e = exc;
                this.f1859f = false;
                this.f1854a.notifyAll();
                o();
                if (!this.f1859f) {
                    k();
                }
                return true;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    boolean r(Object obj) {
        synchronized (this.f1854a) {
            try {
                if (this.f1855b) {
                    return false;
                }
                this.f1855b = true;
                this.f1857d = obj;
                this.f1854a.notifyAll();
                o();
                return true;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    private f(Object obj) {
        r(obj);
    }

    private f(boolean z3) {
        if (z3) {
            p();
        } else {
            r(null);
        }
    }
}
