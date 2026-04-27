package G2;

import B2.B;
import B2.C0163a;
import B2.C0169g;
import B2.D;
import B2.InterfaceC0167e;
import B2.InterfaceC0168f;
import B2.p;
import B2.r;
import B2.u;
import B2.z;
import Q2.C0211g;
import h2.AbstractC0555a;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.lang.ref.Reference;
import java.lang.ref.WeakReference;
import java.net.Socket;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSocketFactory;

/* JADX INFO: loaded from: classes.dex */
public final class e implements InterfaceC0167e {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final h f905b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final r f906c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final c f907d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final AtomicBoolean f908e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private Object f909f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private d f910g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private f f911h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private boolean f912i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private G2.c f913j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private boolean f914k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private boolean f915l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private boolean f916m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private volatile boolean f917n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private volatile G2.c f918o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private volatile f f919p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private final z f920q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private final B f921r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private final boolean f922s;

    public final class a implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private volatile AtomicInteger f923b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final InterfaceC0168f f924c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ e f925d;

        public a(e eVar, InterfaceC0168f interfaceC0168f) {
            t2.j.f(interfaceC0168f, "responseCallback");
            this.f925d = eVar;
            this.f924c = interfaceC0168f;
            this.f923b = new AtomicInteger(0);
        }

        public final void a(ExecutorService executorService) {
            t2.j.f(executorService, "executorService");
            p pVarS = this.f925d.l().s();
            if (C2.c.f585h && Thread.holdsLock(pVarS)) {
                StringBuilder sb = new StringBuilder();
                sb.append("Thread ");
                Thread threadCurrentThread = Thread.currentThread();
                t2.j.e(threadCurrentThread, "Thread.currentThread()");
                sb.append(threadCurrentThread.getName());
                sb.append(" MUST NOT hold lock on ");
                sb.append(pVarS);
                throw new AssertionError(sb.toString());
            }
            try {
                try {
                    executorService.execute(this);
                } catch (RejectedExecutionException e3) {
                    InterruptedIOException interruptedIOException = new InterruptedIOException("executor rejected");
                    interruptedIOException.initCause(e3);
                    this.f925d.w(interruptedIOException);
                    this.f924c.b(this.f925d, interruptedIOException);
                    this.f925d.l().s().g(this);
                }
            } catch (Throwable th) {
                this.f925d.l().s().g(this);
                throw th;
            }
        }

        public final e b() {
            return this.f925d;
        }

        public final AtomicInteger c() {
            return this.f923b;
        }

        public final String d() {
            return this.f925d.s().l().h();
        }

        public final void e(a aVar) {
            t2.j.f(aVar, "other");
            this.f923b = aVar.f923b;
        }

        @Override // java.lang.Runnable
        public void run() {
            boolean z3;
            Throwable th;
            IOException e3;
            p pVarS;
            String str = "OkHttp " + this.f925d.x();
            Thread threadCurrentThread = Thread.currentThread();
            t2.j.e(threadCurrentThread, "currentThread");
            String name = threadCurrentThread.getName();
            threadCurrentThread.setName(str);
            try {
                this.f925d.f907d.r();
                try {
                    try {
                        z3 = true;
                        try {
                            this.f924c.a(this.f925d, this.f925d.t());
                            pVarS = this.f925d.l().s();
                        } catch (IOException e4) {
                            e3 = e4;
                            if (z3) {
                                L2.j.f1746c.g().k("Callback failure for " + this.f925d.D(), 4, e3);
                            } else {
                                this.f924c.b(this.f925d, e3);
                            }
                            pVarS = this.f925d.l().s();
                        } catch (Throwable th2) {
                            th = th2;
                            this.f925d.cancel();
                            if (!z3) {
                                IOException iOException = new IOException("canceled due to " + th);
                                AbstractC0555a.a(iOException, th);
                                this.f924c.b(this.f925d, iOException);
                            }
                            throw th;
                        }
                    } catch (Throwable th3) {
                        this.f925d.l().s().g(this);
                        throw th3;
                    }
                } catch (IOException e5) {
                    z3 = false;
                    e3 = e5;
                } catch (Throwable th4) {
                    z3 = false;
                    th = th4;
                }
                pVarS.g(this);
            } finally {
                threadCurrentThread.setName(name);
            }
        }
    }

    public static final class b extends WeakReference {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final Object f926a;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public b(e eVar, Object obj) {
            super(eVar);
            t2.j.f(eVar, "referent");
            this.f926a = obj;
        }

        public final Object a() {
            return this.f926a;
        }
    }

    public static final class c extends C0211g {
        c() {
        }

        @Override // Q2.C0211g
        protected void x() {
            e.this.cancel();
        }
    }

    public e(z zVar, B b3, boolean z3) {
        t2.j.f(zVar, "client");
        t2.j.f(b3, "originalRequest");
        this.f920q = zVar;
        this.f921r = b3;
        this.f922s = z3;
        this.f905b = zVar.n().a();
        this.f906c = zVar.u().a(this);
        c cVar = new c();
        cVar.g(zVar.j(), TimeUnit.MILLISECONDS);
        h2.r rVar = h2.r.f9288a;
        this.f907d = cVar;
        this.f908e = new AtomicBoolean();
        this.f916m = true;
    }

    private final IOException C(IOException iOException) {
        if (this.f912i || !this.f907d.s()) {
            return iOException;
        }
        InterruptedIOException interruptedIOException = new InterruptedIOException("timeout");
        if (iOException != null) {
            interruptedIOException.initCause(iOException);
        }
        return interruptedIOException;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final String D() {
        StringBuilder sb = new StringBuilder();
        sb.append(r() ? "canceled " : "");
        sb.append(this.f922s ? "web socket" : "call");
        sb.append(" to ");
        sb.append(x());
        return sb.toString();
    }

    private final IOException e(IOException iOException) {
        Socket socketY;
        boolean z3 = C2.c.f585h;
        if (z3 && Thread.holdsLock(this)) {
            StringBuilder sb = new StringBuilder();
            sb.append("Thread ");
            Thread threadCurrentThread = Thread.currentThread();
            t2.j.e(threadCurrentThread, "Thread.currentThread()");
            sb.append(threadCurrentThread.getName());
            sb.append(" MUST NOT hold lock on ");
            sb.append(this);
            throw new AssertionError(sb.toString());
        }
        f fVar = this.f911h;
        if (fVar != null) {
            if (z3 && Thread.holdsLock(fVar)) {
                StringBuilder sb2 = new StringBuilder();
                sb2.append("Thread ");
                Thread threadCurrentThread2 = Thread.currentThread();
                t2.j.e(threadCurrentThread2, "Thread.currentThread()");
                sb2.append(threadCurrentThread2.getName());
                sb2.append(" MUST NOT hold lock on ");
                sb2.append(fVar);
                throw new AssertionError(sb2.toString());
            }
            synchronized (fVar) {
                socketY = y();
            }
            if (this.f911h == null) {
                if (socketY != null) {
                    C2.c.k(socketY);
                }
                this.f906c.l(this, fVar);
            } else {
                if (!(socketY == null)) {
                    throw new IllegalStateException("Check failed.");
                }
            }
        }
        IOException iOExceptionC = C(iOException);
        if (iOException != null) {
            r rVar = this.f906c;
            t2.j.c(iOExceptionC);
            rVar.e(this, iOExceptionC);
        } else {
            this.f906c.d(this);
        }
        return iOExceptionC;
    }

    private final void f() {
        this.f909f = L2.j.f1746c.g().i("response.body().close()");
        this.f906c.f(this);
    }

    private final C0163a h(u uVar) {
        SSLSocketFactory sSLSocketFactoryM;
        HostnameVerifier hostnameVerifierY;
        C0169g c0169gL;
        if (uVar.i()) {
            sSLSocketFactoryM = this.f920q.M();
            hostnameVerifierY = this.f920q.y();
            c0169gL = this.f920q.l();
        } else {
            sSLSocketFactoryM = null;
            hostnameVerifierY = null;
            c0169gL = null;
        }
        return new C0163a(uVar.h(), uVar.l(), this.f920q.t(), this.f920q.L(), sSLSocketFactoryM, hostnameVerifierY, c0169gL, this.f920q.H(), this.f920q.G(), this.f920q.F(), this.f920q.o(), this.f920q.I());
    }

    public final void A(f fVar) {
        this.f919p = fVar;
    }

    public final void B() {
        if (this.f912i) {
            throw new IllegalStateException("Check failed.");
        }
        this.f912i = true;
        this.f907d.s();
    }

    @Override // B2.InterfaceC0167e
    public D b() {
        if (!this.f908e.compareAndSet(false, true)) {
            throw new IllegalStateException("Already Executed");
        }
        this.f907d.r();
        f();
        try {
            this.f920q.s().c(this);
            return t();
        } finally {
            this.f920q.s().h(this);
        }
    }

    @Override // B2.InterfaceC0167e
    public void cancel() {
        if (this.f917n) {
            return;
        }
        this.f917n = true;
        G2.c cVar = this.f918o;
        if (cVar != null) {
            cVar.b();
        }
        f fVar = this.f919p;
        if (fVar != null) {
            fVar.d();
        }
        this.f906c.g(this);
    }

    public final void d(f fVar) {
        t2.j.f(fVar, "connection");
        if (!C2.c.f585h || Thread.holdsLock(fVar)) {
            if (!(this.f911h == null)) {
                throw new IllegalStateException("Check failed.");
            }
            this.f911h = fVar;
            fVar.n().add(new b(this, this.f909f));
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Thread ");
        Thread threadCurrentThread = Thread.currentThread();
        t2.j.e(threadCurrentThread, "Thread.currentThread()");
        sb.append(threadCurrentThread.getName());
        sb.append(" MUST hold lock on ");
        sb.append(fVar);
        throw new AssertionError(sb.toString());
    }

    /* JADX INFO: renamed from: g, reason: merged with bridge method [inline-methods] */
    public e clone() {
        return new e(this.f920q, this.f921r, this.f922s);
    }

    @Override // B2.InterfaceC0167e
    public B i() {
        return this.f921r;
    }

    public final void j(B b3, boolean z3) {
        t2.j.f(b3, "request");
        if (!(this.f913j == null)) {
            throw new IllegalStateException("Check failed.");
        }
        synchronized (this) {
            if (this.f915l) {
                throw new IllegalStateException("cannot make a new request because the previous response is still open: please call response.close()");
            }
            if (this.f914k) {
                throw new IllegalStateException("Check failed.");
            }
            h2.r rVar = h2.r.f9288a;
        }
        if (z3) {
            this.f910g = new d(this.f905b, h(b3.l()), this, this.f906c);
        }
    }

    public final void k(boolean z3) {
        G2.c cVar;
        synchronized (this) {
            if (!this.f916m) {
                throw new IllegalStateException("released");
            }
            h2.r rVar = h2.r.f9288a;
        }
        if (z3 && (cVar = this.f918o) != null) {
            cVar.d();
        }
        this.f913j = null;
    }

    public final z l() {
        return this.f920q;
    }

    public final f m() {
        return this.f911h;
    }

    public final r n() {
        return this.f906c;
    }

    public final boolean o() {
        return this.f922s;
    }

    @Override // B2.InterfaceC0167e
    public void p(InterfaceC0168f interfaceC0168f) {
        t2.j.f(interfaceC0168f, "responseCallback");
        if (!this.f908e.compareAndSet(false, true)) {
            throw new IllegalStateException("Already Executed");
        }
        f();
        this.f920q.s().b(new a(this, interfaceC0168f));
    }

    public final G2.c q() {
        return this.f913j;
    }

    @Override // B2.InterfaceC0167e
    public boolean r() {
        return this.f917n;
    }

    public final B s() {
        return this.f921r;
    }

    /* JADX WARN: Removed duplicated region for block: B:24:0x00a4  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final B2.D t() throws java.lang.Throwable {
        /*
            r11 = this;
            java.util.ArrayList r2 = new java.util.ArrayList
            r2.<init>()
            B2.z r0 = r11.f920q
            java.util.List r0 = r0.z()
            i2.AbstractC0586n.q(r2, r0)
            H2.j r0 = new H2.j
            B2.z r1 = r11.f920q
            r0.<init>(r1)
            r2.add(r0)
            H2.a r0 = new H2.a
            B2.z r1 = r11.f920q
            B2.n r1 = r1.q()
            r0.<init>(r1)
            r2.add(r0)
            E2.a r0 = new E2.a
            B2.z r1 = r11.f920q
            B2.c r1 = r1.h()
            r0.<init>(r1)
            r2.add(r0)
            G2.a r0 = G2.a.f873a
            r2.add(r0)
            boolean r0 = r11.f922s
            if (r0 != 0) goto L46
            B2.z r0 = r11.f920q
            java.util.List r0 = r0.B()
            i2.AbstractC0586n.q(r2, r0)
        L46:
            H2.b r0 = new H2.b
            boolean r1 = r11.f922s
            r0.<init>(r1)
            r2.add(r0)
            H2.g r9 = new H2.g
            B2.B r5 = r11.f921r
            B2.z r0 = r11.f920q
            int r6 = r0.m()
            B2.z r0 = r11.f920q
            int r7 = r0.J()
            B2.z r0 = r11.f920q
            int r8 = r0.O()
            r3 = 0
            r4 = 0
            r0 = r9
            r1 = r11
            r0.<init>(r1, r2, r3, r4, r5, r6, r7, r8)
            r0 = 0
            r1 = 0
            B2.B r2 = r11.f921r     // Catch: java.lang.Throwable -> L8a java.io.IOException -> L8c
            B2.D r2 = r9.a(r2)     // Catch: java.lang.Throwable -> L8a java.io.IOException -> L8c
            boolean r3 = r11.r()     // Catch: java.lang.Throwable -> L8a java.io.IOException -> L8c
            if (r3 != 0) goto L7f
            r11.w(r0)
            return r2
        L7f:
            C2.c.j(r2)     // Catch: java.lang.Throwable -> L8a java.io.IOException -> L8c
            java.io.IOException r2 = new java.io.IOException     // Catch: java.lang.Throwable -> L8a java.io.IOException -> L8c
            java.lang.String r3 = "Canceled"
            r2.<init>(r3)     // Catch: java.lang.Throwable -> L8a java.io.IOException -> L8c
            throw r2     // Catch: java.lang.Throwable -> L8a java.io.IOException -> L8c
        L8a:
            r2 = move-exception
            goto La2
        L8c:
            r1 = move-exception
            r2 = 1
            java.io.IOException r1 = r11.w(r1)     // Catch: java.lang.Throwable -> L9c
            if (r1 != 0) goto La1
            java.lang.NullPointerException r1 = new java.lang.NullPointerException     // Catch: java.lang.Throwable -> L9c
            java.lang.String r3 = "null cannot be cast to non-null type kotlin.Throwable"
            r1.<init>(r3)     // Catch: java.lang.Throwable -> L9c
            throw r1     // Catch: java.lang.Throwable -> L9c
        L9c:
            r1 = move-exception
            r10 = r2
            r2 = r1
            r1 = r10
            goto La2
        La1:
            throw r1     // Catch: java.lang.Throwable -> L9c
        La2:
            if (r1 != 0) goto La7
            r11.w(r0)
        La7:
            throw r2
        */
        throw new UnsupportedOperationException("Method not decompiled: G2.e.t():B2.D");
    }

    public final G2.c u(H2.g gVar) throws IOException {
        t2.j.f(gVar, "chain");
        synchronized (this) {
            if (!this.f916m) {
                throw new IllegalStateException("released");
            }
            if (this.f915l) {
                throw new IllegalStateException("Check failed.");
            }
            if (this.f914k) {
                throw new IllegalStateException("Check failed.");
            }
            h2.r rVar = h2.r.f9288a;
        }
        d dVar = this.f910g;
        t2.j.c(dVar);
        G2.c cVar = new G2.c(this, this.f906c, dVar, dVar.a(this.f920q, gVar));
        this.f913j = cVar;
        this.f918o = cVar;
        synchronized (this) {
            this.f914k = true;
            this.f915l = true;
        }
        if (this.f917n) {
            throw new IOException("Canceled");
        }
        return cVar;
    }

    public final IOException v(G2.c cVar, boolean z3, boolean z4, IOException iOException) {
        boolean z5;
        boolean z6;
        t2.j.f(cVar, "exchange");
        if (!t2.j.b(cVar, this.f918o)) {
            return iOException;
        }
        synchronized (this) {
            z5 = false;
            if (z3) {
                try {
                    if (!this.f914k) {
                        if (z4 || !this.f915l) {
                            z6 = false;
                        }
                    }
                    if (z3) {
                        this.f914k = false;
                    }
                    if (z4) {
                        this.f915l = false;
                    }
                    boolean z7 = this.f914k;
                    boolean z8 = (z7 || this.f915l) ? false : true;
                    if (!z7 && !this.f915l && !this.f916m) {
                        z5 = true;
                    }
                    z6 = z5;
                    z5 = z8;
                } catch (Throwable th) {
                    throw th;
                }
            } else {
                if (z4) {
                }
                z6 = false;
            }
            h2.r rVar = h2.r.f9288a;
        }
        if (z5) {
            this.f918o = null;
            f fVar = this.f911h;
            if (fVar != null) {
                fVar.s();
            }
        }
        return z6 ? e(iOException) : iOException;
    }

    public final IOException w(IOException iOException) {
        boolean z3;
        synchronized (this) {
            try {
                z3 = false;
                if (this.f916m) {
                    this.f916m = false;
                    if (!this.f914k && !this.f915l) {
                        z3 = true;
                    }
                }
                h2.r rVar = h2.r.f9288a;
            } catch (Throwable th) {
                throw th;
            }
        }
        return z3 ? e(iOException) : iOException;
    }

    public final String x() {
        return this.f921r.l().n();
    }

    public final Socket y() {
        f fVar = this.f911h;
        t2.j.c(fVar);
        if (C2.c.f585h && !Thread.holdsLock(fVar)) {
            StringBuilder sb = new StringBuilder();
            sb.append("Thread ");
            Thread threadCurrentThread = Thread.currentThread();
            t2.j.e(threadCurrentThread, "Thread.currentThread()");
            sb.append(threadCurrentThread.getName());
            sb.append(" MUST hold lock on ");
            sb.append(fVar);
            throw new AssertionError(sb.toString());
        }
        List listN = fVar.n();
        Iterator it = listN.iterator();
        int i3 = 0;
        while (true) {
            if (!it.hasNext()) {
                i3 = -1;
                break;
            }
            if (t2.j.b((e) ((Reference) it.next()).get(), this)) {
                break;
            }
            i3++;
        }
        if (!(i3 != -1)) {
            throw new IllegalStateException("Check failed.");
        }
        listN.remove(i3);
        this.f911h = null;
        if (listN.isEmpty()) {
            fVar.C(System.nanoTime());
            if (this.f905b.c(fVar)) {
                return fVar.E();
            }
        }
        return null;
    }

    public final boolean z() {
        d dVar = this.f910g;
        t2.j.c(dVar);
        return dVar.e();
    }
}
