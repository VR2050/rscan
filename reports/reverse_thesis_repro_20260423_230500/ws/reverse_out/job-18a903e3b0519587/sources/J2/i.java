package J2;

import B2.t;
import Q2.C0211g;
import Q2.D;
import Q2.F;
import Q2.G;
import h2.r;
import java.io.EOFException;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.SocketTimeoutException;
import java.util.ArrayDeque;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class i {

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    public static final a f1640o = new a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private long f1641a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private long f1642b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private long f1643c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private long f1644d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final ArrayDeque f1645e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private boolean f1646f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final c f1647g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final b f1648h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final d f1649i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final d f1650j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private J2.b f1651k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private IOException f1652l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private final int f1653m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private final f f1654n;

    public static final class a {
        private a() {
        }

        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    public final class b implements D {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final Q2.i f1655b = new Q2.i();

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private t f1656c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private boolean f1657d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private boolean f1658e;

        public b(boolean z3) {
            this.f1658e = z3;
        }

        private final void b(boolean z3) throws IOException {
            long jMin;
            boolean z4;
            synchronized (i.this) {
                try {
                    i.this.s().r();
                    while (i.this.r() >= i.this.q() && !this.f1658e && !this.f1657d && i.this.h() == null) {
                        try {
                            i.this.D();
                        } finally {
                        }
                    }
                    i.this.s().y();
                    i.this.c();
                    jMin = Math.min(i.this.q() - i.this.r(), this.f1655b.F0());
                    i iVar = i.this;
                    iVar.B(iVar.r() + jMin);
                    z4 = z3 && jMin == this.f1655b.F0() && i.this.h() == null;
                    r rVar = r.f9288a;
                } catch (Throwable th) {
                    throw th;
                }
            }
            i.this.s().r();
            try {
                i.this.g().Y0(i.this.j(), z4, this.f1655b, jMin);
            } finally {
            }
        }

        @Override // Q2.D, java.io.Closeable, java.lang.AutoCloseable
        public void close() throws IOException {
            i iVar = i.this;
            if (C2.c.f585h && Thread.holdsLock(iVar)) {
                StringBuilder sb = new StringBuilder();
                sb.append("Thread ");
                Thread threadCurrentThread = Thread.currentThread();
                t2.j.e(threadCurrentThread, "Thread.currentThread()");
                sb.append(threadCurrentThread.getName());
                sb.append(" MUST NOT hold lock on ");
                sb.append(iVar);
                throw new AssertionError(sb.toString());
            }
            synchronized (i.this) {
                if (this.f1657d) {
                    return;
                }
                boolean z3 = i.this.h() == null;
                r rVar = r.f9288a;
                if (!i.this.o().f1658e) {
                    boolean z4 = this.f1655b.F0() > 0;
                    if (this.f1656c != null) {
                        while (this.f1655b.F0() > 0) {
                            b(false);
                        }
                        f fVarG = i.this.g();
                        int iJ = i.this.j();
                        t tVar = this.f1656c;
                        t2.j.c(tVar);
                        fVarG.Z0(iJ, z3, C2.c.L(tVar));
                    } else if (z4) {
                        while (this.f1655b.F0() > 0) {
                            b(true);
                        }
                    } else if (z3) {
                        i.this.g().Y0(i.this.j(), true, null, 0L);
                    }
                }
                synchronized (i.this) {
                    this.f1657d = true;
                    r rVar2 = r.f9288a;
                }
                i.this.g().flush();
                i.this.b();
            }
        }

        @Override // Q2.D
        public G f() {
            return i.this.s();
        }

        @Override // Q2.D, java.io.Flushable
        public void flush() throws IOException {
            i iVar = i.this;
            if (C2.c.f585h && Thread.holdsLock(iVar)) {
                StringBuilder sb = new StringBuilder();
                sb.append("Thread ");
                Thread threadCurrentThread = Thread.currentThread();
                t2.j.e(threadCurrentThread, "Thread.currentThread()");
                sb.append(threadCurrentThread.getName());
                sb.append(" MUST NOT hold lock on ");
                sb.append(iVar);
                throw new AssertionError(sb.toString());
            }
            synchronized (i.this) {
                i.this.c();
                r rVar = r.f9288a;
            }
            while (this.f1655b.F0() > 0) {
                b(false);
                i.this.g().flush();
            }
        }

        public final boolean i() {
            return this.f1657d;
        }

        @Override // Q2.D
        public void m(Q2.i iVar, long j3) throws IOException {
            t2.j.f(iVar, "source");
            i iVar2 = i.this;
            if (!C2.c.f585h || !Thread.holdsLock(iVar2)) {
                this.f1655b.m(iVar, j3);
                while (this.f1655b.F0() >= 16384) {
                    b(false);
                }
                return;
            }
            StringBuilder sb = new StringBuilder();
            sb.append("Thread ");
            Thread threadCurrentThread = Thread.currentThread();
            t2.j.e(threadCurrentThread, "Thread.currentThread()");
            sb.append(threadCurrentThread.getName());
            sb.append(" MUST NOT hold lock on ");
            sb.append(iVar2);
            throw new AssertionError(sb.toString());
        }

        public final boolean p() {
            return this.f1658e;
        }
    }

    public final class c implements F {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final Q2.i f1660b = new Q2.i();

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final Q2.i f1661c = new Q2.i();

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private t f1662d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private boolean f1663e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private final long f1664f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        private boolean f1665g;

        public c(long j3, boolean z3) {
            this.f1664f = j3;
            this.f1665g = z3;
        }

        private final void x(long j3) {
            i iVar = i.this;
            if (!C2.c.f585h || !Thread.holdsLock(iVar)) {
                i.this.g().X0(j3);
                return;
            }
            StringBuilder sb = new StringBuilder();
            sb.append("Thread ");
            Thread threadCurrentThread = Thread.currentThread();
            t2.j.e(threadCurrentThread, "Thread.currentThread()");
            sb.append(threadCurrentThread.getName());
            sb.append(" MUST NOT hold lock on ");
            sb.append(iVar);
            throw new AssertionError(sb.toString());
        }

        /* JADX WARN: Finally extract failed */
        @Override // Q2.F
        public long R(Q2.i iVar, long j3) throws IOException {
            IOException iOExceptionI;
            long jR;
            boolean z3;
            t2.j.f(iVar, "sink");
            long j4 = 0;
            if (!(j3 >= 0)) {
                throw new IllegalArgumentException(("byteCount < 0: " + j3).toString());
            }
            while (true) {
                synchronized (i.this) {
                    i.this.m().r();
                    try {
                        if (i.this.h() != null) {
                            iOExceptionI = i.this.i();
                            if (iOExceptionI == null) {
                                J2.b bVarH = i.this.h();
                                t2.j.c(bVarH);
                                iOExceptionI = new n(bVarH);
                            }
                        } else {
                            iOExceptionI = null;
                        }
                        if (this.f1663e) {
                            throw new IOException("stream closed");
                        }
                        if (this.f1661c.F0() > j4) {
                            Q2.i iVar2 = this.f1661c;
                            jR = iVar2.R(iVar, Math.min(j3, iVar2.F0()));
                            i iVar3 = i.this;
                            iVar3.A(iVar3.l() + jR);
                            long jL = i.this.l() - i.this.k();
                            if (iOExceptionI == null && jL >= i.this.g().C0().c() / 2) {
                                i.this.g().d1(i.this.j(), jL);
                                i iVar4 = i.this;
                                iVar4.z(iVar4.l());
                            }
                        } else if (this.f1665g || iOExceptionI != null) {
                            jR = -1;
                        } else {
                            i.this.D();
                            jR = -1;
                            z3 = true;
                            i.this.m().y();
                            r rVar = r.f9288a;
                        }
                        z3 = false;
                        i.this.m().y();
                        r rVar2 = r.f9288a;
                    } catch (Throwable th) {
                        i.this.m().y();
                        throw th;
                    }
                }
                if (!z3) {
                    if (jR != -1) {
                        x(jR);
                        return jR;
                    }
                    if (iOExceptionI == null) {
                        return -1L;
                    }
                    t2.j.c(iOExceptionI);
                    throw iOExceptionI;
                }
                j4 = 0;
            }
        }

        public final boolean b() {
            return this.f1663e;
        }

        @Override // Q2.F, java.io.Closeable, java.lang.AutoCloseable
        public void close() {
            long jF0;
            synchronized (i.this) {
                this.f1663e = true;
                jF0 = this.f1661c.F0();
                this.f1661c.v();
                i iVar = i.this;
                if (iVar == null) {
                    throw new NullPointerException("null cannot be cast to non-null type java.lang.Object");
                }
                iVar.notifyAll();
                r rVar = r.f9288a;
            }
            if (jF0 > 0) {
                x(jF0);
            }
            i.this.b();
        }

        @Override // Q2.F
        public G f() {
            return i.this.m();
        }

        public final boolean i() {
            return this.f1665g;
        }

        public final void p(Q2.k kVar, long j3) throws EOFException {
            boolean z3;
            boolean z4;
            long jF0;
            t2.j.f(kVar, "source");
            i iVar = i.this;
            if (C2.c.f585h && Thread.holdsLock(iVar)) {
                StringBuilder sb = new StringBuilder();
                sb.append("Thread ");
                Thread threadCurrentThread = Thread.currentThread();
                t2.j.e(threadCurrentThread, "Thread.currentThread()");
                sb.append(threadCurrentThread.getName());
                sb.append(" MUST NOT hold lock on ");
                sb.append(iVar);
                throw new AssertionError(sb.toString());
            }
            while (j3 > 0) {
                synchronized (i.this) {
                    z3 = this.f1665g;
                    z4 = this.f1661c.F0() + j3 > this.f1664f;
                    r rVar = r.f9288a;
                }
                if (z4) {
                    kVar.t(j3);
                    i.this.f(J2.b.FLOW_CONTROL_ERROR);
                    return;
                }
                if (z3) {
                    kVar.t(j3);
                    return;
                }
                long jR = kVar.R(this.f1660b, j3);
                if (jR == -1) {
                    throw new EOFException();
                }
                j3 -= jR;
                synchronized (i.this) {
                    try {
                        if (this.f1663e) {
                            jF0 = this.f1660b.F0();
                            this.f1660b.v();
                        } else {
                            boolean z5 = this.f1661c.F0() == 0;
                            this.f1661c.o(this.f1660b);
                            if (z5) {
                                i iVar2 = i.this;
                                if (iVar2 == null) {
                                    throw new NullPointerException("null cannot be cast to non-null type java.lang.Object");
                                }
                                iVar2.notifyAll();
                            }
                            jF0 = 0;
                        }
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                if (jF0 > 0) {
                    x(jF0);
                }
            }
        }

        public final void r(boolean z3) {
            this.f1665g = z3;
        }

        public final void v(t tVar) {
            this.f1662d = tVar;
        }
    }

    public final class d extends C0211g {
        public d() {
        }

        @Override // Q2.C0211g
        protected IOException t(IOException iOException) {
            SocketTimeoutException socketTimeoutException = new SocketTimeoutException("timeout");
            if (iOException != null) {
                socketTimeoutException.initCause(iOException);
            }
            return socketTimeoutException;
        }

        @Override // Q2.C0211g
        protected void x() {
            i.this.f(J2.b.CANCEL);
            i.this.g().R0();
        }

        public final void y() throws IOException {
            if (s()) {
                throw t(null);
            }
        }
    }

    public i(int i3, f fVar, boolean z3, boolean z4, t tVar) {
        t2.j.f(fVar, "connection");
        this.f1653m = i3;
        this.f1654n = fVar;
        this.f1644d = fVar.D0().c();
        ArrayDeque arrayDeque = new ArrayDeque();
        this.f1645e = arrayDeque;
        this.f1647g = new c(fVar.C0().c(), z4);
        this.f1648h = new b(z3);
        this.f1649i = new d();
        this.f1650j = new d();
        if (tVar == null) {
            if (!t()) {
                throw new IllegalStateException("remotely-initiated streams should have headers");
            }
        } else {
            if (t()) {
                throw new IllegalStateException("locally-initiated streams shouldn't have headers yet");
            }
            arrayDeque.add(tVar);
        }
    }

    private final boolean e(J2.b bVar, IOException iOException) {
        if (C2.c.f585h && Thread.holdsLock(this)) {
            StringBuilder sb = new StringBuilder();
            sb.append("Thread ");
            Thread threadCurrentThread = Thread.currentThread();
            t2.j.e(threadCurrentThread, "Thread.currentThread()");
            sb.append(threadCurrentThread.getName());
            sb.append(" MUST NOT hold lock on ");
            sb.append(this);
            throw new AssertionError(sb.toString());
        }
        synchronized (this) {
            if (this.f1651k != null) {
                return false;
            }
            if (this.f1647g.i() && this.f1648h.p()) {
                return false;
            }
            this.f1651k = bVar;
            this.f1652l = iOException;
            notifyAll();
            r rVar = r.f9288a;
            this.f1654n.Q0(this.f1653m);
            return true;
        }
    }

    public final void A(long j3) {
        this.f1641a = j3;
    }

    public final void B(long j3) {
        this.f1643c = j3;
    }

    public final synchronized t C() {
        Object objRemoveFirst;
        this.f1649i.r();
        while (this.f1645e.isEmpty() && this.f1651k == null) {
            try {
                D();
            } catch (Throwable th) {
                this.f1649i.y();
                throw th;
            }
        }
        this.f1649i.y();
        if (this.f1645e.isEmpty()) {
            IOException iOException = this.f1652l;
            if (iOException != null) {
                throw iOException;
            }
            J2.b bVar = this.f1651k;
            t2.j.c(bVar);
            throw new n(bVar);
        }
        objRemoveFirst = this.f1645e.removeFirst();
        t2.j.e(objRemoveFirst, "headersQueue.removeFirst()");
        return (t) objRemoveFirst;
    }

    public final void D() throws InterruptedIOException {
        try {
            wait();
        } catch (InterruptedException unused) {
            Thread.currentThread().interrupt();
            throw new InterruptedIOException();
        }
    }

    public final G E() {
        return this.f1650j;
    }

    public final void a(long j3) {
        this.f1644d += j3;
        if (j3 > 0) {
            notifyAll();
        }
    }

    public final void b() {
        boolean z3;
        boolean zU;
        if (C2.c.f585h && Thread.holdsLock(this)) {
            StringBuilder sb = new StringBuilder();
            sb.append("Thread ");
            Thread threadCurrentThread = Thread.currentThread();
            t2.j.e(threadCurrentThread, "Thread.currentThread()");
            sb.append(threadCurrentThread.getName());
            sb.append(" MUST NOT hold lock on ");
            sb.append(this);
            throw new AssertionError(sb.toString());
        }
        synchronized (this) {
            try {
                z3 = !this.f1647g.i() && this.f1647g.b() && (this.f1648h.p() || this.f1648h.i());
                zU = u();
                r rVar = r.f9288a;
            } catch (Throwable th) {
                throw th;
            }
        }
        if (z3) {
            d(J2.b.CANCEL, null);
        } else {
            if (zU) {
                return;
            }
            this.f1654n.Q0(this.f1653m);
        }
    }

    public final void c() throws IOException {
        if (this.f1648h.i()) {
            throw new IOException("stream closed");
        }
        if (this.f1648h.p()) {
            throw new IOException("stream finished");
        }
        if (this.f1651k != null) {
            IOException iOException = this.f1652l;
            if (iOException != null) {
                throw iOException;
            }
            J2.b bVar = this.f1651k;
            t2.j.c(bVar);
            throw new n(bVar);
        }
    }

    public final void d(J2.b bVar, IOException iOException) {
        t2.j.f(bVar, "rstStatusCode");
        if (e(bVar, iOException)) {
            this.f1654n.b1(this.f1653m, bVar);
        }
    }

    public final void f(J2.b bVar) {
        t2.j.f(bVar, "errorCode");
        if (e(bVar, null)) {
            this.f1654n.c1(this.f1653m, bVar);
        }
    }

    public final f g() {
        return this.f1654n;
    }

    public final synchronized J2.b h() {
        return this.f1651k;
    }

    public final IOException i() {
        return this.f1652l;
    }

    public final int j() {
        return this.f1653m;
    }

    public final long k() {
        return this.f1642b;
    }

    public final long l() {
        return this.f1641a;
    }

    public final d m() {
        return this.f1649i;
    }

    public final D n() {
        synchronized (this) {
            try {
                if (!(this.f1646f || t())) {
                    throw new IllegalStateException("reply before requesting the sink");
                }
                r rVar = r.f9288a;
            } finally {
            }
        }
        return this.f1648h;
    }

    public final b o() {
        return this.f1648h;
    }

    public final c p() {
        return this.f1647g;
    }

    public final long q() {
        return this.f1644d;
    }

    public final long r() {
        return this.f1643c;
    }

    public final d s() {
        return this.f1650j;
    }

    public final boolean t() {
        return this.f1654n.x0() == ((this.f1653m & 1) == 1);
    }

    public final synchronized boolean u() {
        try {
            if (this.f1651k != null) {
                return false;
            }
            if (this.f1647g.i() || this.f1647g.b()) {
                if (this.f1648h.p() || this.f1648h.i()) {
                    if (this.f1646f) {
                        return false;
                    }
                }
            }
            return true;
        } catch (Throwable th) {
            throw th;
        }
    }

    public final G v() {
        return this.f1649i;
    }

    public final void w(Q2.k kVar, int i3) {
        t2.j.f(kVar, "source");
        if (!C2.c.f585h || !Thread.holdsLock(this)) {
            this.f1647g.p(kVar, i3);
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Thread ");
        Thread threadCurrentThread = Thread.currentThread();
        t2.j.e(threadCurrentThread, "Thread.currentThread()");
        sb.append(threadCurrentThread.getName());
        sb.append(" MUST NOT hold lock on ");
        sb.append(this);
        throw new AssertionError(sb.toString());
    }

    public final void x(t tVar, boolean z3) {
        boolean zU;
        t2.j.f(tVar, "headers");
        if (C2.c.f585h && Thread.holdsLock(this)) {
            StringBuilder sb = new StringBuilder();
            sb.append("Thread ");
            Thread threadCurrentThread = Thread.currentThread();
            t2.j.e(threadCurrentThread, "Thread.currentThread()");
            sb.append(threadCurrentThread.getName());
            sb.append(" MUST NOT hold lock on ");
            sb.append(this);
            throw new AssertionError(sb.toString());
        }
        synchronized (this) {
            try {
                if (this.f1646f && z3) {
                    this.f1647g.v(tVar);
                } else {
                    this.f1646f = true;
                    this.f1645e.add(tVar);
                }
                if (z3) {
                    this.f1647g.r(true);
                }
                zU = u();
                notifyAll();
                r rVar = r.f9288a;
            } catch (Throwable th) {
                throw th;
            }
        }
        if (zU) {
            return;
        }
        this.f1654n.Q0(this.f1653m);
    }

    public final synchronized void y(J2.b bVar) {
        t2.j.f(bVar, "errorCode");
        if (this.f1651k == null) {
            this.f1651k = bVar;
            notifyAll();
        }
    }

    public final void z(long j3) {
        this.f1642b = j3;
    }
}
