package I2;

import B2.B;
import B2.D;
import B2.n;
import B2.t;
import B2.u;
import B2.z;
import Q2.D;
import Q2.F;
import Q2.G;
import Q2.i;
import Q2.j;
import Q2.k;
import Q2.p;
import java.io.EOFException;
import java.io.IOException;
import java.net.ProtocolException;
import java.net.Proxy;
import java.util.concurrent.TimeUnit;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class b implements H2.d {

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    public static final d f1426h = new d(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private int f1427a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final I2.a f1428b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private t f1429c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final z f1430d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final G2.f f1431e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final k f1432f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final j f1433g;

    private abstract class a implements F {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final p f1434b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private boolean f1435c;

        public a() {
            this.f1434b = new p(b.this.f1432f.f());
        }

        @Override // Q2.F
        public long R(i iVar, long j3) throws IOException {
            t2.j.f(iVar, "sink");
            try {
                return b.this.f1432f.R(iVar, j3);
            } catch (IOException e3) {
                b.this.h().z();
                i();
                throw e3;
            }
        }

        protected final boolean b() {
            return this.f1435c;
        }

        @Override // Q2.F
        public G f() {
            return this.f1434b;
        }

        public final void i() {
            if (b.this.f1427a == 6) {
                return;
            }
            if (b.this.f1427a == 5) {
                b.this.r(this.f1434b);
                b.this.f1427a = 6;
            } else {
                throw new IllegalStateException("state: " + b.this.f1427a);
            }
        }

        protected final void p(boolean z3) {
            this.f1435c = z3;
        }
    }

    /* JADX INFO: renamed from: I2.b$b, reason: collision with other inner class name */
    private final class C0020b implements D {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final p f1437b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private boolean f1438c;

        public C0020b() {
            this.f1437b = new p(b.this.f1433g.f());
        }

        @Override // Q2.D, java.io.Closeable, java.lang.AutoCloseable
        public synchronized void close() {
            if (this.f1438c) {
                return;
            }
            this.f1438c = true;
            b.this.f1433g.j0("0\r\n\r\n");
            b.this.r(this.f1437b);
            b.this.f1427a = 3;
        }

        @Override // Q2.D
        public G f() {
            return this.f1437b;
        }

        @Override // Q2.D, java.io.Flushable
        public synchronized void flush() {
            if (this.f1438c) {
                return;
            }
            b.this.f1433g.flush();
        }

        @Override // Q2.D
        public void m(i iVar, long j3) {
            t2.j.f(iVar, "source");
            if (this.f1438c) {
                throw new IllegalStateException("closed");
            }
            if (j3 == 0) {
                return;
            }
            b.this.f1433g.n(j3);
            b.this.f1433g.j0("\r\n");
            b.this.f1433g.m(iVar, j3);
            b.this.f1433g.j0("\r\n");
        }
    }

    private final class c extends a {

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private long f1440e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private boolean f1441f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        private final u f1442g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        final /* synthetic */ b f1443h;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public c(b bVar, u uVar) {
            super();
            t2.j.f(uVar, "url");
            this.f1443h = bVar;
            this.f1442g = uVar;
            this.f1440e = -1L;
            this.f1441f = true;
        }

        private final void r() throws ProtocolException {
            if (this.f1440e != -1) {
                this.f1443h.f1432f.H();
            }
            try {
                this.f1440e = this.f1443h.f1432f.o0();
                String strH = this.f1443h.f1432f.H();
                if (strH == null) {
                    throw new NullPointerException("null cannot be cast to non-null type kotlin.CharSequence");
                }
                String string = z2.g.n0(strH).toString();
                if (this.f1440e < 0 || (string.length() > 0 && !z2.g.u(string, ";", false, 2, null))) {
                    throw new ProtocolException("expected chunk size and optional extensions but was \"" + this.f1440e + string + '\"');
                }
                if (this.f1440e == 0) {
                    this.f1441f = false;
                    b bVar = this.f1443h;
                    bVar.f1429c = bVar.f1428b.a();
                    z zVar = this.f1443h.f1430d;
                    t2.j.c(zVar);
                    n nVarQ = zVar.q();
                    u uVar = this.f1442g;
                    t tVar = this.f1443h.f1429c;
                    t2.j.c(tVar);
                    H2.e.f(nVarQ, uVar, tVar);
                    i();
                }
            } catch (NumberFormatException e3) {
                throw new ProtocolException(e3.getMessage());
            }
        }

        @Override // I2.b.a, Q2.F
        public long R(i iVar, long j3) throws IOException {
            t2.j.f(iVar, "sink");
            if (!(j3 >= 0)) {
                throw new IllegalArgumentException(("byteCount < 0: " + j3).toString());
            }
            if (b()) {
                throw new IllegalStateException("closed");
            }
            if (!this.f1441f) {
                return -1L;
            }
            long j4 = this.f1440e;
            if (j4 == 0 || j4 == -1) {
                r();
                if (!this.f1441f) {
                    return -1L;
                }
            }
            long jR = super.R(iVar, Math.min(j3, this.f1440e));
            if (jR != -1) {
                this.f1440e -= jR;
                return jR;
            }
            this.f1443h.h().z();
            ProtocolException protocolException = new ProtocolException("unexpected end of stream");
            i();
            throw protocolException;
        }

        @Override // Q2.F, java.io.Closeable, java.lang.AutoCloseable
        public void close() {
            if (b()) {
                return;
            }
            if (this.f1441f && !C2.c.p(this, 100, TimeUnit.MILLISECONDS)) {
                this.f1443h.h().z();
                i();
            }
            p(true);
        }
    }

    public static final class d {
        private d() {
        }

        public /* synthetic */ d(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    private final class e extends a {

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private long f1444e;

        public e(long j3) {
            super();
            this.f1444e = j3;
            if (j3 == 0) {
                i();
            }
        }

        @Override // I2.b.a, Q2.F
        public long R(i iVar, long j3) throws IOException {
            t2.j.f(iVar, "sink");
            if (!(j3 >= 0)) {
                throw new IllegalArgumentException(("byteCount < 0: " + j3).toString());
            }
            if (b()) {
                throw new IllegalStateException("closed");
            }
            long j4 = this.f1444e;
            if (j4 == 0) {
                return -1L;
            }
            long jR = super.R(iVar, Math.min(j4, j3));
            if (jR == -1) {
                b.this.h().z();
                ProtocolException protocolException = new ProtocolException("unexpected end of stream");
                i();
                throw protocolException;
            }
            long j5 = this.f1444e - jR;
            this.f1444e = j5;
            if (j5 == 0) {
                i();
            }
            return jR;
        }

        @Override // Q2.F, java.io.Closeable, java.lang.AutoCloseable
        public void close() {
            if (b()) {
                return;
            }
            if (this.f1444e != 0 && !C2.c.p(this, 100, TimeUnit.MILLISECONDS)) {
                b.this.h().z();
                i();
            }
            p(true);
        }
    }

    private final class f implements D {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final p f1446b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private boolean f1447c;

        public f() {
            this.f1446b = new p(b.this.f1433g.f());
        }

        @Override // Q2.D, java.io.Closeable, java.lang.AutoCloseable
        public void close() {
            if (this.f1447c) {
                return;
            }
            this.f1447c = true;
            b.this.r(this.f1446b);
            b.this.f1427a = 3;
        }

        @Override // Q2.D
        public G f() {
            return this.f1446b;
        }

        @Override // Q2.D, java.io.Flushable
        public void flush() {
            if (this.f1447c) {
                return;
            }
            b.this.f1433g.flush();
        }

        @Override // Q2.D
        public void m(i iVar, long j3) {
            t2.j.f(iVar, "source");
            if (this.f1447c) {
                throw new IllegalStateException("closed");
            }
            C2.c.i(iVar.F0(), 0L, j3);
            b.this.f1433g.m(iVar, j3);
        }
    }

    private final class g extends a {

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private boolean f1449e;

        public g() {
            super();
        }

        @Override // I2.b.a, Q2.F
        public long R(i iVar, long j3) throws IOException {
            t2.j.f(iVar, "sink");
            if (!(j3 >= 0)) {
                throw new IllegalArgumentException(("byteCount < 0: " + j3).toString());
            }
            if (b()) {
                throw new IllegalStateException("closed");
            }
            if (this.f1449e) {
                return -1L;
            }
            long jR = super.R(iVar, j3);
            if (jR != -1) {
                return jR;
            }
            this.f1449e = true;
            i();
            return -1L;
        }

        @Override // Q2.F, java.io.Closeable, java.lang.AutoCloseable
        public void close() {
            if (b()) {
                return;
            }
            if (!this.f1449e) {
                i();
            }
            p(true);
        }
    }

    public b(z zVar, G2.f fVar, k kVar, j jVar) {
        t2.j.f(fVar, "connection");
        t2.j.f(kVar, "source");
        t2.j.f(jVar, "sink");
        this.f1430d = zVar;
        this.f1431e = fVar;
        this.f1432f = kVar;
        this.f1433g = jVar;
        this.f1428b = new I2.a(kVar);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void r(p pVar) {
        G gI = pVar.i();
        pVar.j(G.f2522d);
        gI.a();
        gI.b();
    }

    private final boolean s(B b3) {
        return z2.g.j("chunked", b3.d("Transfer-Encoding"), true);
    }

    private final boolean t(B2.D d3) {
        return z2.g.j("chunked", B2.D.d0(d3, "Transfer-Encoding", null, 2, null), true);
    }

    private final D u() {
        if (this.f1427a == 1) {
            this.f1427a = 2;
            return new C0020b();
        }
        throw new IllegalStateException(("state: " + this.f1427a).toString());
    }

    private final F v(u uVar) {
        if (this.f1427a == 4) {
            this.f1427a = 5;
            return new c(this, uVar);
        }
        throw new IllegalStateException(("state: " + this.f1427a).toString());
    }

    private final F w(long j3) {
        if (this.f1427a == 4) {
            this.f1427a = 5;
            return new e(j3);
        }
        throw new IllegalStateException(("state: " + this.f1427a).toString());
    }

    private final D x() {
        if (this.f1427a == 1) {
            this.f1427a = 2;
            return new f();
        }
        throw new IllegalStateException(("state: " + this.f1427a).toString());
    }

    private final F y() {
        if (this.f1427a == 4) {
            this.f1427a = 5;
            h().z();
            return new g();
        }
        throw new IllegalStateException(("state: " + this.f1427a).toString());
    }

    public final void A(t tVar, String str) {
        t2.j.f(tVar, "headers");
        t2.j.f(str, "requestLine");
        if (!(this.f1427a == 0)) {
            throw new IllegalStateException(("state: " + this.f1427a).toString());
        }
        this.f1433g.j0(str).j0("\r\n");
        int size = tVar.size();
        for (int i3 = 0; i3 < size; i3++) {
            this.f1433g.j0(tVar.b(i3)).j0(": ").j0(tVar.h(i3)).j0("\r\n");
        }
        this.f1433g.j0("\r\n");
        this.f1427a = 1;
    }

    @Override // H2.d
    public long a(B2.D d3) {
        t2.j.f(d3, "response");
        if (!H2.e.b(d3)) {
            return 0L;
        }
        if (t(d3)) {
            return -1L;
        }
        return C2.c.s(d3);
    }

    @Override // H2.d
    public D b(B b3, long j3) throws ProtocolException {
        t2.j.f(b3, "request");
        if (b3.a() != null && b3.a().f()) {
            throw new ProtocolException("Duplex connections are not supported for HTTP/1");
        }
        if (s(b3)) {
            return u();
        }
        if (j3 != -1) {
            return x();
        }
        throw new IllegalStateException("Cannot stream a request body without chunked encoding or a known content length!");
    }

    @Override // H2.d
    public void c() {
        this.f1433g.flush();
    }

    @Override // H2.d
    public void cancel() {
        h().d();
    }

    @Override // H2.d
    public void d() {
        this.f1433g.flush();
    }

    @Override // H2.d
    public void e(B b3) {
        t2.j.f(b3, "request");
        H2.i iVar = H2.i.f1091a;
        Proxy.Type type = h().A().b().type();
        t2.j.e(type, "connection.route().proxy.type()");
        A(b3.e(), iVar.a(b3, type));
    }

    @Override // H2.d
    public F f(B2.D d3) {
        t2.j.f(d3, "response");
        if (!H2.e.b(d3)) {
            return w(0L);
        }
        if (t(d3)) {
            return v(d3.y0().l());
        }
        long jS = C2.c.s(d3);
        return jS != -1 ? w(jS) : y();
    }

    @Override // H2.d
    public D.a g(boolean z3) {
        int i3 = this.f1427a;
        boolean z4 = true;
        if (i3 != 1 && i3 != 3) {
            z4 = false;
        }
        if (!z4) {
            throw new IllegalStateException(("state: " + this.f1427a).toString());
        }
        try {
            H2.k kVarA = H2.k.f1094d.a(this.f1428b.b());
            D.a aVarK = new D.a().p(kVarA.f1095a).g(kVarA.f1096b).m(kVarA.f1097c).k(this.f1428b.a());
            if (z3 && kVarA.f1096b == 100) {
                return null;
            }
            if (kVarA.f1096b == 100) {
                this.f1427a = 3;
                return aVarK;
            }
            this.f1427a = 4;
            return aVarK;
        } catch (EOFException e3) {
            throw new IOException("unexpected end of stream on " + h().A().a().l().n(), e3);
        }
    }

    @Override // H2.d
    public G2.f h() {
        return this.f1431e;
    }

    public final void z(B2.D d3) {
        t2.j.f(d3, "response");
        long jS = C2.c.s(d3);
        if (jS == -1) {
            return;
        }
        F fW = w(jS);
        C2.c.J(fW, Integer.MAX_VALUE, TimeUnit.MILLISECONDS);
        fW.close();
    }
}
