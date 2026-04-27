package G2;

import B2.B;
import B2.C;
import B2.D;
import B2.E;
import B2.r;
import P2.d;
import Q2.D;
import Q2.F;
import Q2.n;
import Q2.o;
import Q2.t;
import java.io.IOException;
import java.net.ProtocolException;

/* JADX INFO: loaded from: classes.dex */
public final class c {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private boolean f878a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final f f879b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final e f880c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final r f881d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final d f882e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final H2.d f883f;

    private final class a extends n {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private boolean f884c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private long f885d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private boolean f886e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private final long f887f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        final /* synthetic */ c f888g;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public a(c cVar, D d3, long j3) {
            super(d3);
            t2.j.f(d3, "delegate");
            this.f888g = cVar;
            this.f887f = j3;
        }

        private final IOException b(IOException iOException) {
            if (this.f884c) {
                return iOException;
            }
            this.f884c = true;
            return this.f888g.a(this.f885d, false, true, iOException);
        }

        @Override // Q2.n, Q2.D, java.io.Closeable, java.lang.AutoCloseable
        public void close() throws IOException {
            if (this.f886e) {
                return;
            }
            this.f886e = true;
            long j3 = this.f887f;
            if (j3 != -1 && this.f885d != j3) {
                throw new ProtocolException("unexpected end of stream");
            }
            try {
                super.close();
                b(null);
            } catch (IOException e3) {
                throw b(e3);
            }
        }

        @Override // Q2.n, Q2.D, java.io.Flushable
        public void flush() throws IOException {
            try {
                super.flush();
            } catch (IOException e3) {
                throw b(e3);
            }
        }

        @Override // Q2.n, Q2.D
        public void m(Q2.i iVar, long j3) throws IOException {
            t2.j.f(iVar, "source");
            if (this.f886e) {
                throw new IllegalStateException("closed");
            }
            long j4 = this.f887f;
            if (j4 == -1 || this.f885d + j3 <= j4) {
                try {
                    super.m(iVar, j3);
                    this.f885d += j3;
                    return;
                } catch (IOException e3) {
                    throw b(e3);
                }
            }
            throw new ProtocolException("expected " + this.f887f + " bytes but received " + (this.f885d + j3));
        }
    }

    public final class b extends o {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private long f889c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private boolean f890d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private boolean f891e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private boolean f892f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        private final long f893g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        final /* synthetic */ c f894h;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public b(c cVar, F f3, long j3) {
            super(f3);
            t2.j.f(f3, "delegate");
            this.f894h = cVar;
            this.f893g = j3;
            this.f890d = true;
            if (j3 == 0) {
                i(null);
            }
        }

        @Override // Q2.o, Q2.F
        public long R(Q2.i iVar, long j3) throws IOException {
            t2.j.f(iVar, "sink");
            if (this.f892f) {
                throw new IllegalStateException("closed");
            }
            try {
                long jR = b().R(iVar, j3);
                if (this.f890d) {
                    this.f890d = false;
                    this.f894h.i().w(this.f894h.g());
                }
                if (jR == -1) {
                    i(null);
                    return -1L;
                }
                long j4 = this.f889c + jR;
                long j5 = this.f893g;
                if (j5 != -1 && j4 > j5) {
                    throw new ProtocolException("expected " + this.f893g + " bytes but received " + j4);
                }
                this.f889c = j4;
                if (j4 == j5) {
                    i(null);
                }
                return jR;
            } catch (IOException e3) {
                throw i(e3);
            }
        }

        @Override // Q2.o, Q2.F, java.io.Closeable, java.lang.AutoCloseable
        public void close() throws IOException {
            if (this.f892f) {
                return;
            }
            this.f892f = true;
            try {
                super.close();
                i(null);
            } catch (IOException e3) {
                throw i(e3);
            }
        }

        public final IOException i(IOException iOException) {
            if (this.f891e) {
                return iOException;
            }
            this.f891e = true;
            if (iOException == null && this.f890d) {
                this.f890d = false;
                this.f894h.i().w(this.f894h.g());
            }
            return this.f894h.a(this.f889c, true, false, iOException);
        }
    }

    public c(e eVar, r rVar, d dVar, H2.d dVar2) {
        t2.j.f(eVar, "call");
        t2.j.f(rVar, "eventListener");
        t2.j.f(dVar, "finder");
        t2.j.f(dVar2, "codec");
        this.f880c = eVar;
        this.f881d = rVar;
        this.f882e = dVar;
        this.f883f = dVar2;
        this.f879b = dVar2.h();
    }

    private final void t(IOException iOException) {
        this.f882e.h(iOException);
        this.f883f.h().H(this.f880c, iOException);
    }

    public final IOException a(long j3, boolean z3, boolean z4, IOException iOException) {
        if (iOException != null) {
            t(iOException);
        }
        if (z4) {
            if (iOException != null) {
                this.f881d.s(this.f880c, iOException);
            } else {
                this.f881d.q(this.f880c, j3);
            }
        }
        if (z3) {
            if (iOException != null) {
                this.f881d.x(this.f880c, iOException);
            } else {
                this.f881d.v(this.f880c, j3);
            }
        }
        return this.f880c.v(this, z4, z3, iOException);
    }

    public final void b() {
        this.f883f.cancel();
    }

    public final D c(B b3, boolean z3) {
        t2.j.f(b3, "request");
        this.f878a = z3;
        C cA = b3.a();
        t2.j.c(cA);
        long jA = cA.a();
        this.f881d.r(this.f880c);
        return new a(this, this.f883f.b(b3, jA), jA);
    }

    public final void d() {
        this.f883f.cancel();
        this.f880c.v(this, true, true, null);
    }

    public final void e() throws IOException {
        try {
            this.f883f.c();
        } catch (IOException e3) {
            this.f881d.s(this.f880c, e3);
            t(e3);
            throw e3;
        }
    }

    public final void f() throws IOException {
        try {
            this.f883f.d();
        } catch (IOException e3) {
            this.f881d.s(this.f880c, e3);
            t(e3);
            throw e3;
        }
    }

    public final e g() {
        return this.f880c;
    }

    public final f h() {
        return this.f879b;
    }

    public final r i() {
        return this.f881d;
    }

    public final d j() {
        return this.f882e;
    }

    public final boolean k() {
        return !t2.j.b(this.f882e.d().l().h(), this.f879b.A().a().l().h());
    }

    public final boolean l() {
        return this.f878a;
    }

    public final d.AbstractC0035d m() {
        this.f880c.B();
        return this.f883f.h().x(this);
    }

    public final void n() {
        this.f883f.h().z();
    }

    public final void o() {
        this.f880c.v(this, true, false, null);
    }

    public final E p(B2.D d3) throws IOException {
        t2.j.f(d3, "response");
        try {
            String strD0 = B2.D.d0(d3, "Content-Type", null, 2, null);
            long jA = this.f883f.a(d3);
            return new H2.h(strD0, jA, t.d(new b(this, this.f883f.f(d3), jA)));
        } catch (IOException e3) {
            this.f881d.x(this.f880c, e3);
            t(e3);
            throw e3;
        }
    }

    public final D.a q(boolean z3) throws IOException {
        try {
            D.a aVarG = this.f883f.g(z3);
            if (aVarG != null) {
                aVarG.l(this);
            }
            return aVarG;
        } catch (IOException e3) {
            this.f881d.x(this.f880c, e3);
            t(e3);
            throw e3;
        }
    }

    public final void r(B2.D d3) {
        t2.j.f(d3, "response");
        this.f881d.y(this.f880c, d3);
    }

    public final void s() {
        this.f881d.z(this.f880c);
    }

    public final void u() {
        a(-1L, true, true, null);
    }

    public final void v(B b3) throws IOException {
        t2.j.f(b3, "request");
        try {
            this.f881d.u(this.f880c);
            this.f883f.e(b3);
            this.f881d.t(this.f880c, b3);
        } catch (IOException e3) {
            this.f881d.s(this.f880c, e3);
            t(e3);
            throw e3;
        }
    }
}
