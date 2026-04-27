package G0;

import a0.InterfaceC0222h;
import a0.InterfaceC0223i;
import b0.AbstractC0311a;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.Callable;
import java.util.concurrent.CancellationException;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class j {

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    public static final a f794h = new a(null);

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private static final Class f795i = j.class;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final S.k f796a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final InterfaceC0223i f797b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final a0.l f798c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final Executor f799d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final Executor f800e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final t f801f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final C f802g;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    public j(S.k kVar, InterfaceC0223i interfaceC0223i, a0.l lVar, Executor executor, Executor executor2, t tVar) {
        t2.j.f(kVar, "fileCache");
        t2.j.f(interfaceC0223i, "pooledByteBufferFactory");
        t2.j.f(lVar, "pooledByteStreams");
        t2.j.f(executor, "readExecutor");
        t2.j.f(executor2, "writeExecutor");
        t2.j.f(tVar, "imageCacheStatsTracker");
        this.f796a = kVar;
        this.f797b = interfaceC0223i;
        this.f798c = lVar;
        this.f799d = executor;
        this.f800e = executor2;
        this.f801f = tVar;
        C cD = C.d();
        t2.j.e(cD, "getInstance(...)");
        this.f802g = cD;
    }

    private final boolean g(R.d dVar) {
        N0.j jVarC = this.f802g.c(dVar);
        if (jVarC != null) {
            jVarC.close();
            Y.a.y(f795i, "Found image for %s in staging area", dVar.c());
            this.f801f.d(dVar);
            return true;
        }
        Y.a.y(f795i, "Did not find image for %s in staging area", dVar.c());
        this.f801f.b(dVar);
        try {
            return this.f796a.f(dVar);
        } catch (Exception unused) {
            return false;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Void i(Object obj, j jVar) {
        t2.j.f(jVar, "this$0");
        Object objE = O0.a.e(obj, null);
        try {
            jVar.f802g.a();
            jVar.f796a.a();
            return null;
        } finally {
        }
    }

    private final N.f l(R.d dVar, N0.j jVar) {
        Y.a.y(f795i, "Found image for %s in staging area", dVar.c());
        this.f801f.d(dVar);
        N.f fVarH = N.f.h(jVar);
        t2.j.e(fVarH, "forResult(...)");
        return fVarH;
    }

    private final N.f n(final R.d dVar, final AtomicBoolean atomicBoolean) {
        try {
            final Object objD = O0.a.d("BufferedDiskCache_getAsync");
            return N.f.b(new Callable() { // from class: G0.f
                @Override // java.util.concurrent.Callable
                public final Object call() {
                    return j.o(objD, atomicBoolean, this, dVar);
                }
            }, this.f799d);
        } catch (Exception e3) {
            Y.a.H(f795i, e3, "Failed to schedule disk-cache read for %s", dVar.c());
            return N.f.g(e3);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final N0.j o(Object obj, AtomicBoolean atomicBoolean, j jVar, R.d dVar) {
        t2.j.f(atomicBoolean, "$isCancelled");
        t2.j.f(jVar, "this$0");
        t2.j.f(dVar, "$key");
        Object objE = O0.a.e(obj, null);
        try {
            if (atomicBoolean.get()) {
                throw new CancellationException();
            }
            N0.j jVarC = jVar.f802g.c(dVar);
            if (jVarC != null) {
                Y.a.y(f795i, "Found image for %s in staging area", dVar.c());
                jVar.f801f.d(dVar);
            } else {
                Y.a.y(f795i, "Did not find image for %s in staging area", dVar.c());
                jVar.f801f.b(dVar);
                try {
                    InterfaceC0222h interfaceC0222hR = jVar.r(dVar);
                    if (interfaceC0222hR == null) {
                        return null;
                    }
                    AbstractC0311a abstractC0311aE0 = AbstractC0311a.e0(interfaceC0222hR);
                    t2.j.e(abstractC0311aE0, "of(...)");
                    try {
                        jVarC = new N0.j(abstractC0311aE0);
                    } finally {
                        AbstractC0311a.D(abstractC0311aE0);
                    }
                } catch (Exception unused) {
                    return null;
                }
            }
            if (!Thread.interrupted()) {
                return jVarC;
            }
            Y.a.x(f795i, "Host thread was interrupted, decreasing reference count");
            jVarC.close();
            throw new InterruptedException();
        } catch (Throwable th) {
            try {
                O0.a.c(obj, th);
                throw th;
            } finally {
                O0.a.f(objE);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void q(Object obj, j jVar, R.d dVar, N0.j jVar2) {
        t2.j.f(jVar, "this$0");
        t2.j.f(dVar, "$key");
        Object objE = O0.a.e(obj, null);
        try {
            jVar.u(dVar, jVar2);
        } finally {
        }
    }

    private final InterfaceC0222h r(R.d dVar) throws IOException {
        try {
            Class cls = f795i;
            Y.a.y(cls, "Disk cache read for %s", dVar.c());
            Q.a aVarD = this.f796a.d(dVar);
            if (aVarD == null) {
                Y.a.y(cls, "Disk cache miss for %s", dVar.c());
                this.f801f.m(dVar);
                return null;
            }
            Y.a.y(cls, "Found entry in disk cache for %s", dVar.c());
            this.f801f.i(dVar);
            InputStream inputStreamA = aVarD.a();
            try {
                InterfaceC0222h interfaceC0222hA = this.f797b.a(inputStreamA, (int) aVarD.size());
                inputStreamA.close();
                Y.a.y(cls, "Successful read from disk cache for %s", dVar.c());
                return interfaceC0222hA;
            } catch (Throwable th) {
                inputStreamA.close();
                throw th;
            }
        } catch (IOException e3) {
            Y.a.H(f795i, e3, "Exception reading from cache for %s", dVar.c());
            this.f801f.f(dVar);
            throw e3;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final Void t(Object obj, j jVar, R.d dVar) {
        t2.j.f(jVar, "this$0");
        t2.j.f(dVar, "$key");
        Object objE = O0.a.e(obj, null);
        try {
            jVar.f802g.g(dVar);
            jVar.f796a.g(dVar);
            return null;
        } finally {
        }
    }

    private final void u(R.d dVar, final N0.j jVar) {
        Class cls = f795i;
        Y.a.y(cls, "About to write to disk-cache for key %s", dVar.c());
        try {
            this.f796a.c(dVar, new R.j() { // from class: G0.i
                @Override // R.j
                public final void a(OutputStream outputStream) {
                    j.v(jVar, this, outputStream);
                }
            });
            this.f801f.e(dVar);
            Y.a.y(cls, "Successful disk-cache write for key %s", dVar.c());
        } catch (IOException e3) {
            Y.a.H(f795i, e3, "Failed to write to disk-cache for key %s", dVar.c());
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void v(N0.j jVar, j jVar2, OutputStream outputStream) {
        t2.j.f(jVar2, "this$0");
        t2.j.f(outputStream, "os");
        t2.j.c(jVar);
        InputStream inputStreamP = jVar.P();
        if (inputStreamP == null) {
            throw new IllegalStateException("Required value was null.");
        }
        jVar2.f798c.a(inputStreamP, outputStream);
    }

    public final void f(R.d dVar) {
        t2.j.f(dVar, "key");
        this.f796a.e(dVar);
    }

    public final N.f h() {
        this.f802g.a();
        final Object objD = O0.a.d("BufferedDiskCache_clearAll");
        try {
            return N.f.b(new Callable() { // from class: G0.h
                @Override // java.util.concurrent.Callable
                public final Object call() {
                    return j.i(objD, this);
                }
            }, this.f800e);
        } catch (Exception e3) {
            Y.a.H(f795i, e3, "Failed to schedule disk-cache clear", new Object[0]);
            return N.f.g(e3);
        }
    }

    public final boolean j(R.d dVar) {
        t2.j.f(dVar, "key");
        return this.f802g.b(dVar) || this.f796a.b(dVar);
    }

    public final boolean k(R.d dVar) {
        t2.j.f(dVar, "key");
        if (j(dVar)) {
            return true;
        }
        return g(dVar);
    }

    public final N.f m(R.d dVar, AtomicBoolean atomicBoolean) {
        N.f fVarN;
        N.f fVarL;
        t2.j.f(dVar, "key");
        t2.j.f(atomicBoolean, "isCancelled");
        if (!U0.b.d()) {
            N0.j jVarC = this.f802g.c(dVar);
            return (jVarC == null || (fVarL = l(dVar, jVarC)) == null) ? n(dVar, atomicBoolean) : fVarL;
        }
        U0.b.a("BufferedDiskCache#get");
        try {
            N0.j jVarC2 = this.f802g.c(dVar);
            if (jVarC2 == null || (fVarN = l(dVar, jVarC2)) == null) {
                fVarN = n(dVar, atomicBoolean);
            }
            U0.b.b();
            return fVarN;
        } catch (Throwable th) {
            U0.b.b();
            throw th;
        }
    }

    public final void p(final R.d dVar, N0.j jVar) {
        t2.j.f(dVar, "key");
        t2.j.f(jVar, "encodedImage");
        if (!U0.b.d()) {
            if (!N0.j.w0(jVar)) {
                throw new IllegalStateException("Check failed.");
            }
            this.f802g.f(dVar, jVar);
            final N0.j jVarI = N0.j.i(jVar);
            try {
                final Object objD = O0.a.d("BufferedDiskCache_putAsync");
                this.f800e.execute(new Runnable() { // from class: G0.e
                    @Override // java.lang.Runnable
                    public final void run() {
                        j.q(objD, this, dVar, jVarI);
                    }
                });
                return;
            } catch (Exception e3) {
                Y.a.H(f795i, e3, "Failed to schedule disk-cache write for %s", dVar.c());
                this.f802g.h(dVar, jVar);
                N0.j.p(jVarI);
                return;
            }
        }
        U0.b.a("BufferedDiskCache#put");
        try {
            if (!N0.j.w0(jVar)) {
                throw new IllegalStateException("Check failed.");
            }
            this.f802g.f(dVar, jVar);
            final N0.j jVarI2 = N0.j.i(jVar);
            try {
                final Object objD2 = O0.a.d("BufferedDiskCache_putAsync");
                this.f800e.execute(new Runnable() { // from class: G0.e
                    @Override // java.lang.Runnable
                    public final void run() {
                        j.q(objD2, this, dVar, jVarI2);
                    }
                });
            } catch (Exception e4) {
                Y.a.H(f795i, e4, "Failed to schedule disk-cache write for %s", dVar.c());
                this.f802g.h(dVar, jVar);
                N0.j.p(jVarI2);
            }
            h2.r rVar = h2.r.f9288a;
        } finally {
            U0.b.b();
        }
    }

    public final N.f s(final R.d dVar) {
        t2.j.f(dVar, "key");
        this.f802g.g(dVar);
        try {
            final Object objD = O0.a.d("BufferedDiskCache_remove");
            return N.f.b(new Callable() { // from class: G0.g
                @Override // java.util.concurrent.Callable
                public final Object call() {
                    return j.t(objD, this, dVar);
                }
            }, this.f800e);
        } catch (Exception e3) {
            Y.a.H(f795i, e3, "Failed to schedule disk-cache remove for %s", dVar.c());
            return N.f.g(e3);
        }
    }
}
