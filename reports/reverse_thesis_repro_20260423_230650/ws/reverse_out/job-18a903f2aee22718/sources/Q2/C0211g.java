package Q2;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.util.concurrent.TimeUnit;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: renamed from: Q2.g, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0211g extends G {

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private static final long f2533i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private static final long f2534j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private static C0211g f2535k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    public static final a f2536l = new a(null);

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private boolean f2537f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private C0211g f2538g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private long f2539h;

    /* JADX INFO: renamed from: Q2.g$a */
    public static final class a {
        private a() {
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final boolean d(C0211g c0211g) {
            synchronized (C0211g.class) {
                for (C0211g c0211g2 = C0211g.f2535k; c0211g2 != null; c0211g2 = c0211g2.f2538g) {
                    if (c0211g2.f2538g == c0211g) {
                        c0211g2.f2538g = c0211g.f2538g;
                        c0211g.f2538g = null;
                        return false;
                    }
                }
                return true;
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final void e(C0211g c0211g, long j3, boolean z3) {
            synchronized (C0211g.class) {
                try {
                    if (C0211g.f2535k == null) {
                        C0211g.f2535k = new C0211g();
                        new b().start();
                    }
                    long jNanoTime = System.nanoTime();
                    if (j3 != 0 && z3) {
                        c0211g.f2539h = Math.min(j3, c0211g.c() - jNanoTime) + jNanoTime;
                    } else if (j3 != 0) {
                        c0211g.f2539h = j3 + jNanoTime;
                    } else {
                        if (!z3) {
                            throw new AssertionError();
                        }
                        c0211g.f2539h = c0211g.c();
                    }
                    long jU = c0211g.u(jNanoTime);
                    C0211g c0211g2 = C0211g.f2535k;
                    t2.j.c(c0211g2);
                    while (c0211g2.f2538g != null) {
                        C0211g c0211g3 = c0211g2.f2538g;
                        t2.j.c(c0211g3);
                        if (jU < c0211g3.u(jNanoTime)) {
                            break;
                        }
                        c0211g2 = c0211g2.f2538g;
                        t2.j.c(c0211g2);
                    }
                    c0211g.f2538g = c0211g2.f2538g;
                    c0211g2.f2538g = c0211g;
                    if (c0211g2 == C0211g.f2535k) {
                        C0211g.class.notify();
                    }
                    h2.r rVar = h2.r.f9288a;
                } catch (Throwable th) {
                    throw th;
                }
            }
        }

        public final C0211g c() throws InterruptedException {
            C0211g c0211g = C0211g.f2535k;
            t2.j.c(c0211g);
            C0211g c0211g2 = c0211g.f2538g;
            if (c0211g2 == null) {
                long jNanoTime = System.nanoTime();
                C0211g.class.wait(C0211g.f2533i);
                C0211g c0211g3 = C0211g.f2535k;
                t2.j.c(c0211g3);
                if (c0211g3.f2538g != null || System.nanoTime() - jNanoTime < C0211g.f2534j) {
                    return null;
                }
                return C0211g.f2535k;
            }
            long jU = c0211g2.u(System.nanoTime());
            if (jU > 0) {
                long j3 = jU / 1000000;
                C0211g.class.wait(j3, (int) (jU - (1000000 * j3)));
                return null;
            }
            C0211g c0211g4 = C0211g.f2535k;
            t2.j.c(c0211g4);
            c0211g4.f2538g = c0211g2.f2538g;
            c0211g2.f2538g = null;
            return c0211g2;
        }

        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    /* JADX INFO: renamed from: Q2.g$b */
    private static final class b extends Thread {
        public b() {
            super("Okio Watchdog");
            setDaemon(true);
        }

        @Override // java.lang.Thread, java.lang.Runnable
        public void run() {
            C0211g c0211gC;
            while (true) {
                try {
                    synchronized (C0211g.class) {
                        c0211gC = C0211g.f2536l.c();
                        if (c0211gC == C0211g.f2535k) {
                            C0211g.f2535k = null;
                            return;
                        }
                        h2.r rVar = h2.r.f9288a;
                    }
                    if (c0211gC != null) {
                        c0211gC.x();
                    }
                } catch (InterruptedException unused) {
                    continue;
                }
            }
        }
    }

    /* JADX INFO: renamed from: Q2.g$c */
    public static final class c implements D {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ D f2541c;

        c(D d3) {
            this.f2541c = d3;
        }

        @Override // Q2.D
        /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
        public C0211g f() {
            return C0211g.this;
        }

        @Override // Q2.D, java.io.Closeable, java.lang.AutoCloseable
        public void close() throws IOException {
            C0211g c0211g = C0211g.this;
            c0211g.r();
            try {
                this.f2541c.close();
                h2.r rVar = h2.r.f9288a;
                if (c0211g.s()) {
                    throw c0211g.m(null);
                }
            } catch (IOException e3) {
                if (!c0211g.s()) {
                    throw e3;
                }
                throw c0211g.m(e3);
            } finally {
                c0211g.s();
            }
        }

        @Override // Q2.D, java.io.Flushable
        public void flush() throws IOException {
            C0211g c0211g = C0211g.this;
            c0211g.r();
            try {
                this.f2541c.flush();
                h2.r rVar = h2.r.f9288a;
                if (c0211g.s()) {
                    throw c0211g.m(null);
                }
            } catch (IOException e3) {
                if (!c0211g.s()) {
                    throw e3;
                }
                throw c0211g.m(e3);
            } finally {
                c0211g.s();
            }
        }

        @Override // Q2.D
        public void m(i iVar, long j3) throws IOException {
            t2.j.f(iVar, "source");
            AbstractC0210f.b(iVar.F0(), 0L, j3);
            while (true) {
                long j4 = 0;
                if (j3 <= 0) {
                    return;
                }
                A a3 = iVar.f2544b;
                t2.j.c(a3);
                while (true) {
                    if (j4 >= 65536) {
                        break;
                    }
                    j4 += (long) (a3.f2509c - a3.f2508b);
                    if (j4 >= j3) {
                        j4 = j3;
                        break;
                    } else {
                        a3 = a3.f2512f;
                        t2.j.c(a3);
                    }
                }
                C0211g c0211g = C0211g.this;
                c0211g.r();
                try {
                    this.f2541c.m(iVar, j4);
                    h2.r rVar = h2.r.f9288a;
                    if (c0211g.s()) {
                        throw c0211g.m(null);
                    }
                    j3 -= j4;
                } catch (IOException e3) {
                    if (!c0211g.s()) {
                        throw e3;
                    }
                    throw c0211g.m(e3);
                } finally {
                    c0211g.s();
                }
            }
        }

        public String toString() {
            return "AsyncTimeout.sink(" + this.f2541c + ')';
        }
    }

    /* JADX INFO: renamed from: Q2.g$d */
    public static final class d implements F {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ F f2543c;

        d(F f3) {
            this.f2543c = f3;
        }

        @Override // Q2.F
        public long R(i iVar, long j3) throws IOException {
            t2.j.f(iVar, "sink");
            C0211g c0211g = C0211g.this;
            c0211g.r();
            try {
                long jR = this.f2543c.R(iVar, j3);
                if (c0211g.s()) {
                    throw c0211g.m(null);
                }
                return jR;
            } catch (IOException e3) {
                if (c0211g.s()) {
                    throw c0211g.m(e3);
                }
                throw e3;
            } finally {
                c0211g.s();
            }
        }

        @Override // Q2.F
        /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
        public C0211g f() {
            return C0211g.this;
        }

        @Override // Q2.F, java.io.Closeable, java.lang.AutoCloseable
        public void close() throws IOException {
            C0211g c0211g = C0211g.this;
            c0211g.r();
            try {
                this.f2543c.close();
                h2.r rVar = h2.r.f9288a;
                if (c0211g.s()) {
                    throw c0211g.m(null);
                }
            } catch (IOException e3) {
                if (!c0211g.s()) {
                    throw e3;
                }
                throw c0211g.m(e3);
            } finally {
                c0211g.s();
            }
        }

        public String toString() {
            return "AsyncTimeout.source(" + this.f2543c + ')';
        }
    }

    static {
        long millis = TimeUnit.SECONDS.toMillis(60L);
        f2533i = millis;
        f2534j = TimeUnit.MILLISECONDS.toNanos(millis);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final long u(long j3) {
        return this.f2539h - j3;
    }

    public final IOException m(IOException iOException) {
        return t(iOException);
    }

    public final void r() {
        if (this.f2537f) {
            throw new IllegalStateException("Unbalanced enter/exit");
        }
        long jH = h();
        boolean zE = e();
        if (jH != 0 || zE) {
            this.f2537f = true;
            f2536l.e(this, jH, zE);
        }
    }

    public final boolean s() {
        if (!this.f2537f) {
            return false;
        }
        this.f2537f = false;
        return f2536l.d(this);
    }

    protected IOException t(IOException iOException) {
        InterruptedIOException interruptedIOException = new InterruptedIOException("timeout");
        if (iOException != null) {
            interruptedIOException.initCause(iOException);
        }
        return interruptedIOException;
    }

    public final D v(D d3) {
        t2.j.f(d3, "sink");
        return new c(d3);
    }

    public final F w(F f3) {
        t2.j.f(f3, "source");
        return new d(f3);
    }

    protected void x() {
    }
}
