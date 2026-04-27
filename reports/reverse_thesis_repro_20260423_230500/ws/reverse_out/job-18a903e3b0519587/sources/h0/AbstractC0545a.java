package h0;

import X.k;
import android.util.Pair;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executor;

/* JADX INFO: renamed from: h0.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public abstract class AbstractC0545a implements InterfaceC0547c {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private Map f9232a;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private Object f9235d = null;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private Throwable f9236e = null;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private float f9237f = 0.0f;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private boolean f9234c = false;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private d f9233b = d.IN_PROGRESS;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final ConcurrentLinkedQueue f9238g = new ConcurrentLinkedQueue();

    /* JADX INFO: renamed from: h0.a$a, reason: collision with other inner class name */
    class RunnableC0128a implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ boolean f9239b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ InterfaceC0549e f9240c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ boolean f9241d;

        RunnableC0128a(boolean z3, InterfaceC0549e interfaceC0549e, boolean z4) {
            this.f9239b = z3;
            this.f9240c = interfaceC0549e;
            this.f9241d = z4;
        }

        @Override // java.lang.Runnable
        public void run() {
            if (this.f9239b) {
                this.f9240c.c(AbstractC0545a.this);
            } else if (this.f9241d) {
                this.f9240c.d(AbstractC0545a.this);
            } else {
                this.f9240c.a(AbstractC0545a.this);
            }
        }
    }

    /* JADX INFO: renamed from: h0.a$b */
    class b implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ InterfaceC0549e f9243b;

        b(InterfaceC0549e interfaceC0549e) {
            this.f9243b = interfaceC0549e;
        }

        @Override // java.lang.Runnable
        public void run() {
            this.f9243b.b(AbstractC0545a.this);
        }
    }

    /* JADX INFO: renamed from: h0.a$c */
    public interface c {
    }

    /* JADX INFO: renamed from: h0.a$d */
    private enum d {
        IN_PROGRESS,
        SUCCESS,
        FAILURE
    }

    protected AbstractC0545a() {
    }

    public static c j() {
        return null;
    }

    private void n() {
        boolean zK = k();
        boolean zX = x();
        for (Pair pair : this.f9238g) {
            m((InterfaceC0549e) pair.first, (Executor) pair.second, zK, zX);
        }
    }

    private synchronized boolean s(Throwable th, Map map) {
        if (!this.f9234c && this.f9233b == d.IN_PROGRESS) {
            this.f9233b = d.FAILURE;
            this.f9236e = th;
            this.f9232a = map;
            return true;
        }
        return false;
    }

    private synchronized boolean u(float f3) {
        if (!this.f9234c && this.f9233b == d.IN_PROGRESS) {
            if (f3 < this.f9237f) {
                return false;
            }
            this.f9237f = f3;
            return true;
        }
        return false;
    }

    /* JADX WARN: Code restructure failed: missing block: B:23:0x002c, code lost:
    
        return true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:28:0x0033, code lost:
    
        if (r4 == null) goto L46;
     */
    /* JADX WARN: Code restructure failed: missing block: B:29:0x0035, code lost:
    
        i(r4);
     */
    /* JADX WARN: Code restructure failed: missing block: B:30:0x0038, code lost:
    
        return false;
     */
    /* JADX WARN: Code restructure failed: missing block: B:45:?, code lost:
    
        return true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:46:?, code lost:
    
        return false;
     */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:12:0x0019 -> B:32:0x003a). Please report as a decompilation issue!!! */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private boolean w(java.lang.Object r4, boolean r5) {
        /*
            r3 = this;
            r0 = 0
            monitor-enter(r3)     // Catch: java.lang.Throwable -> L3c
            boolean r1 = r3.f9234c     // Catch: java.lang.Throwable -> L18
            if (r1 != 0) goto L32
            h0.a$d r1 = r3.f9233b     // Catch: java.lang.Throwable -> L18
            h0.a$d r2 = h0.AbstractC0545a.d.IN_PROGRESS     // Catch: java.lang.Throwable -> L18
            if (r1 == r2) goto Ld
            goto L32
        Ld:
            if (r5 == 0) goto L1a
            h0.a$d r5 = h0.AbstractC0545a.d.SUCCESS     // Catch: java.lang.Throwable -> L18
            r3.f9233b = r5     // Catch: java.lang.Throwable -> L18
            r5 = 1065353216(0x3f800000, float:1.0)
            r3.f9237f = r5     // Catch: java.lang.Throwable -> L18
            goto L1a
        L18:
            r4 = move-exception
            goto L3a
        L1a:
            java.lang.Object r5 = r3.f9235d     // Catch: java.lang.Throwable -> L18
            if (r5 == r4) goto L25
            r3.f9235d = r4     // Catch: java.lang.Throwable -> L22
            r4 = r5
            goto L26
        L22:
            r4 = move-exception
            r0 = r5
            goto L3a
        L25:
            r4 = r0
        L26:
            monitor-exit(r3)     // Catch: java.lang.Throwable -> L2e
            if (r4 == 0) goto L2c
            r3.i(r4)
        L2c:
            r4 = 1
            return r4
        L2e:
            r5 = move-exception
            r0 = r4
            r4 = r5
            goto L3a
        L32:
            monitor-exit(r3)     // Catch: java.lang.Throwable -> L2e
            if (r4 == 0) goto L38
            r3.i(r4)
        L38:
            r4 = 0
            return r4
        L3a:
            monitor-exit(r3)     // Catch: java.lang.Throwable -> L18
            throw r4     // Catch: java.lang.Throwable -> L3c
        L3c:
            r4 = move-exception
            if (r0 == 0) goto L42
            r3.i(r0)
        L42:
            throw r4
        */
        throw new UnsupportedOperationException("Method not decompiled: h0.AbstractC0545a.w(java.lang.Object, boolean):boolean");
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x0011  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private synchronized boolean x() {
        /*
            r1 = this;
            monitor-enter(r1)
            boolean r0 = r1.l()     // Catch: java.lang.Throwable -> Lf
            if (r0 == 0) goto L11
            boolean r0 = r1.e()     // Catch: java.lang.Throwable -> Lf
            if (r0 != 0) goto L11
            r0 = 1
            goto L12
        Lf:
            r0 = move-exception
            goto L14
        L11:
            r0 = 0
        L12:
            monitor-exit(r1)
            return r0
        L14:
            monitor-exit(r1)     // Catch: java.lang.Throwable -> Lf
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: h0.AbstractC0545a.x():boolean");
    }

    @Override // h0.InterfaceC0547c
    public synchronized Object a() {
        return this.f9235d;
    }

    @Override // h0.InterfaceC0547c
    public Map b() {
        return this.f9232a;
    }

    @Override // h0.InterfaceC0547c
    public boolean c() {
        return false;
    }

    @Override // h0.InterfaceC0547c
    public boolean close() {
        synchronized (this) {
            try {
                if (this.f9234c) {
                    return false;
                }
                this.f9234c = true;
                Object obj = this.f9235d;
                this.f9235d = null;
                if (obj != null) {
                    i(obj);
                }
                if (!e()) {
                    n();
                }
                synchronized (this) {
                    this.f9238g.clear();
                }
                return true;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // h0.InterfaceC0547c
    public synchronized boolean d() {
        return this.f9235d != null;
    }

    @Override // h0.InterfaceC0547c
    public synchronized boolean e() {
        return this.f9233b != d.IN_PROGRESS;
    }

    @Override // h0.InterfaceC0547c
    public synchronized Throwable f() {
        return this.f9236e;
    }

    @Override // h0.InterfaceC0547c
    public synchronized float g() {
        return this.f9237f;
    }

    @Override // h0.InterfaceC0547c
    public void h(InterfaceC0549e interfaceC0549e, Executor executor) {
        k.g(interfaceC0549e);
        k.g(executor);
        synchronized (this) {
            try {
                if (this.f9234c) {
                    return;
                }
                if (this.f9233b == d.IN_PROGRESS) {
                    this.f9238g.add(Pair.create(interfaceC0549e, executor));
                }
                boolean z3 = d() || e() || x();
                if (z3) {
                    m(interfaceC0549e, executor, k(), x());
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public synchronized boolean k() {
        return this.f9233b == d.FAILURE;
    }

    public synchronized boolean l() {
        return this.f9234c;
    }

    protected void m(InterfaceC0549e interfaceC0549e, Executor executor, boolean z3, boolean z4) {
        RunnableC0128a runnableC0128a = new RunnableC0128a(z3, interfaceC0549e, z4);
        j();
        executor.execute(runnableC0128a);
    }

    protected void o() {
        for (Pair pair : this.f9238g) {
            ((Executor) pair.second).execute(new b((InterfaceC0549e) pair.first));
        }
    }

    protected void p(Map map) {
        this.f9232a = map;
    }

    protected boolean q(Throwable th) {
        return r(th, null);
    }

    protected boolean r(Throwable th, Map map) {
        boolean zS = s(th, map);
        if (zS) {
            n();
        }
        return zS;
    }

    protected boolean t(float f3) {
        boolean zU = u(f3);
        if (zU) {
            o();
        }
        return zU;
    }

    protected boolean v(Object obj, boolean z3, Map map) {
        p(map);
        boolean zW = w(obj, z3);
        if (zW) {
            n();
        }
        return zW;
    }

    protected void i(Object obj) {
    }
}
