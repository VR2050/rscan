package J2;

import J2.d;
import Q2.F;
import Q2.G;
import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import kotlin.jvm.internal.DefaultConstructorMarker;
import org.chromium.support_lib_boundary.WebSettingsBoundaryInterface;

/* JADX INFO: loaded from: classes.dex */
public final class h implements Closeable {

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private static final Logger f1628f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    public static final a f1629g = new a(null);

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final b f1630b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final d.a f1631c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final Q2.k f1632d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final boolean f1633e;

    public static final class a {
        private a() {
        }

        public final Logger a() {
            return h.f1628f;
        }

        public final int b(int i3, int i4, int i5) throws IOException {
            if ((i4 & 8) != 0) {
                i3--;
            }
            if (i5 <= i3) {
                return i3 - i5;
            }
            throw new IOException("PROTOCOL_ERROR padding " + i5 + " > remaining length " + i3);
        }

        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    public interface c {
        void b(boolean z3, m mVar);

        void c(boolean z3, int i3, Q2.k kVar, int i4);

        void d();

        void e(boolean z3, int i3, int i4);

        void f(int i3, int i4, int i5, boolean z3);

        void g(boolean z3, int i3, int i4, List list);

        void h(int i3, J2.b bVar);

        void i(int i3, long j3);

        void j(int i3, int i4, List list);

        void k(int i3, J2.b bVar, Q2.l lVar);
    }

    static {
        Logger logger = Logger.getLogger(e.class.getName());
        t2.j.e(logger, "Logger.getLogger(Http2::class.java.name)");
        f1628f = logger;
    }

    public h(Q2.k kVar, boolean z3) {
        t2.j.f(kVar, "source");
        this.f1632d = kVar;
        this.f1633e = z3;
        b bVar = new b(kVar);
        this.f1630b = bVar;
        this.f1631c = new d.a(bVar, 4096, 0, 4, null);
    }

    private final void A(c cVar, int i3, int i4, int i5) throws IOException {
        if (i3 != 8) {
            throw new IOException("TYPE_PING length != 8: " + i3);
        }
        if (i5 != 0) {
            throw new IOException("TYPE_PING streamId != 0");
        }
        cVar.e((i4 & 1) != 0, this.f1632d.B(), this.f1632d.B());
    }

    private final void D(c cVar, int i3) {
        int iB = this.f1632d.B();
        cVar.f(i3, iB & Integer.MAX_VALUE, C2.c.b(this.f1632d.r0(), 255) + 1, (((int) 2147483648L) & iB) != 0);
    }

    private final void P(c cVar, int i3, int i4, int i5) throws IOException {
        if (i3 == 5) {
            if (i5 == 0) {
                throw new IOException("TYPE_PRIORITY streamId == 0");
            }
            D(cVar, i5);
        } else {
            throw new IOException("TYPE_PRIORITY length: " + i3 + " != 5");
        }
    }

    private final void W(c cVar, int i3, int i4, int i5) throws IOException {
        if (i5 == 0) {
            throw new IOException("PROTOCOL_ERROR: TYPE_PUSH_PROMISE streamId == 0");
        }
        int iB = (i4 & 8) != 0 ? C2.c.b(this.f1632d.r0(), 255) : 0;
        cVar.j(i5, this.f1632d.B() & Integer.MAX_VALUE, x(f1629g.b(i3 - 4, i4, iB), iB, i4, i5));
    }

    private final void Z(c cVar, int i3, int i4, int i5) throws IOException {
        if (i3 != 4) {
            throw new IOException("TYPE_RST_STREAM length: " + i3 + " != 4");
        }
        if (i5 == 0) {
            throw new IOException("TYPE_RST_STREAM streamId == 0");
        }
        int iB = this.f1632d.B();
        J2.b bVarA = J2.b.f1473r.a(iB);
        if (bVarA != null) {
            cVar.h(i5, bVarA);
            return;
        }
        throw new IOException("TYPE_RST_STREAM unexpected error code: " + iB);
    }

    private final void d0(c cVar, int i3, int i4, int i5) throws IOException {
        int iB;
        if (i5 != 0) {
            throw new IOException("TYPE_SETTINGS streamId != 0");
        }
        if ((i4 & 1) != 0) {
            if (i3 != 0) {
                throw new IOException("FRAME_SIZE_ERROR ack frame should be empty!");
            }
            cVar.d();
            return;
        }
        if (i3 % 6 != 0) {
            throw new IOException("TYPE_SETTINGS length % 6 != 0: " + i3);
        }
        m mVar = new m();
        w2.a aVarH = w2.d.h(w2.d.i(0, i3), 6);
        int iA = aVarH.a();
        int iB2 = aVarH.b();
        int iC = aVarH.c();
        if (iC < 0 ? iA >= iB2 : iA <= iB2) {
            while (true) {
                int iC2 = C2.c.c(this.f1632d.X(), 65535);
                iB = this.f1632d.B();
                if (iC2 != 2) {
                    if (iC2 == 3) {
                        iC2 = 4;
                    } else if (iC2 != 4) {
                        if (iC2 == 5 && (iB < 16384 || iB > 16777215)) {
                            break;
                        }
                    } else {
                        if (iB < 0) {
                            throw new IOException("PROTOCOL_ERROR SETTINGS_INITIAL_WINDOW_SIZE > 2^31 - 1");
                        }
                        iC2 = 7;
                    }
                } else if (iB != 0 && iB != 1) {
                    throw new IOException("PROTOCOL_ERROR SETTINGS_ENABLE_PUSH != 0 or 1");
                }
                mVar.h(iC2, iB);
                if (iA == iB2) {
                    break;
                } else {
                    iA += iC;
                }
            }
            throw new IOException("PROTOCOL_ERROR SETTINGS_MAX_FRAME_SIZE: " + iB);
        }
        cVar.b(false, mVar);
    }

    private final void e0(c cVar, int i3, int i4, int i5) throws IOException {
        if (i3 != 4) {
            throw new IOException("TYPE_WINDOW_UPDATE length !=4: " + i3);
        }
        long jD = C2.c.d(this.f1632d.B(), 2147483647L);
        if (jD == 0) {
            throw new IOException("windowSizeIncrement was 0");
        }
        cVar.i(i5, jD);
    }

    private final void r(c cVar, int i3, int i4, int i5) throws IOException {
        if (i5 == 0) {
            throw new IOException("PROTOCOL_ERROR: TYPE_DATA streamId == 0");
        }
        boolean z3 = (i4 & 1) != 0;
        if ((i4 & 32) != 0) {
            throw new IOException("PROTOCOL_ERROR: FLAG_COMPRESSED without SETTINGS_COMPRESS_DATA");
        }
        int iB = (i4 & 8) != 0 ? C2.c.b(this.f1632d.r0(), 255) : 0;
        cVar.c(z3, i5, this.f1632d, f1629g.b(i3, i4, iB));
        this.f1632d.t(iB);
    }

    private final void v(c cVar, int i3, int i4, int i5) throws IOException {
        if (i3 < 8) {
            throw new IOException("TYPE_GOAWAY length < 8: " + i3);
        }
        if (i5 != 0) {
            throw new IOException("TYPE_GOAWAY streamId != 0");
        }
        int iB = this.f1632d.B();
        int iB2 = this.f1632d.B();
        int i6 = i3 - 8;
        J2.b bVarA = J2.b.f1473r.a(iB2);
        if (bVarA == null) {
            throw new IOException("TYPE_GOAWAY unexpected error code: " + iB2);
        }
        Q2.l lVarQ = Q2.l.f2555e;
        if (i6 > 0) {
            lVarQ = this.f1632d.q(i6);
        }
        cVar.k(iB, bVarA, lVarQ);
    }

    private final List x(int i3, int i4, int i5, int i6) throws IOException {
        this.f1630b.r(i3);
        b bVar = this.f1630b;
        bVar.v(bVar.b());
        this.f1630b.x(i4);
        this.f1630b.p(i5);
        this.f1630b.y(i6);
        this.f1631c.k();
        return this.f1631c.e();
    }

    private final void y(c cVar, int i3, int i4, int i5) throws IOException {
        if (i5 == 0) {
            throw new IOException("PROTOCOL_ERROR: TYPE_HEADERS streamId == 0");
        }
        boolean z3 = (i4 & 1) != 0;
        int iB = (i4 & 8) != 0 ? C2.c.b(this.f1632d.r0(), 255) : 0;
        if ((i4 & 32) != 0) {
            D(cVar, i5);
            i3 -= 5;
        }
        cVar.g(z3, i5, -1, x(f1629g.b(i3, i4, iB), iB, i4, i5));
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        this.f1632d.close();
    }

    public final boolean i(boolean z3, c cVar) throws IOException {
        t2.j.f(cVar, "handler");
        try {
            this.f1632d.i0(9L);
            int iH = C2.c.H(this.f1632d);
            if (iH > 16384) {
                throw new IOException("FRAME_SIZE_ERROR: " + iH);
            }
            int iB = C2.c.b(this.f1632d.r0(), 255);
            int iB2 = C2.c.b(this.f1632d.r0(), 255);
            int iB3 = this.f1632d.B() & Integer.MAX_VALUE;
            Logger logger = f1628f;
            if (logger.isLoggable(Level.FINE)) {
                logger.fine(e.f1510e.c(true, iB3, iH, iB, iB2));
            }
            if (z3 && iB != 4) {
                throw new IOException("Expected a SETTINGS frame but was " + e.f1510e.b(iB));
            }
            switch (iB) {
                case WebSettingsBoundaryInterface.ForceDarkBehavior.FORCE_DARK_ONLY /* 0 */:
                    r(cVar, iH, iB2, iB3);
                    return true;
                case 1:
                    y(cVar, iH, iB2, iB3);
                    return true;
                case 2:
                    P(cVar, iH, iB2, iB3);
                    return true;
                case 3:
                    Z(cVar, iH, iB2, iB3);
                    return true;
                case 4:
                    d0(cVar, iH, iB2, iB3);
                    return true;
                case 5:
                    W(cVar, iH, iB2, iB3);
                    return true;
                case 6:
                    A(cVar, iH, iB2, iB3);
                    return true;
                case 7:
                    v(cVar, iH, iB2, iB3);
                    return true;
                case 8:
                    e0(cVar, iH, iB2, iB3);
                    return true;
                default:
                    this.f1632d.t(iH);
                    return true;
            }
        } catch (EOFException unused) {
            return false;
        }
    }

    public final void p(c cVar) throws IOException {
        t2.j.f(cVar, "handler");
        if (this.f1633e) {
            if (!i(true, cVar)) {
                throw new IOException("Required SETTINGS preface not received");
            }
            return;
        }
        Q2.k kVar = this.f1632d;
        Q2.l lVar = e.f1506a;
        Q2.l lVarQ = kVar.q(lVar.v());
        Logger logger = f1628f;
        if (logger.isLoggable(Level.FINE)) {
            logger.fine(C2.c.q("<< CONNECTION " + lVarQ.k(), new Object[0]));
        }
        if (t2.j.b(lVar, lVarQ)) {
            return;
        }
        throw new IOException("Expected a connection header but was " + lVarQ.z());
    }

    public static final class b implements F {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private int f1634b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private int f1635c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private int f1636d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private int f1637e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private int f1638f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        private final Q2.k f1639g;

        public b(Q2.k kVar) {
            t2.j.f(kVar, "source");
            this.f1639g = kVar;
        }

        private final void i() throws IOException {
            int i3 = this.f1636d;
            int iH = C2.c.H(this.f1639g);
            this.f1637e = iH;
            this.f1634b = iH;
            int iB = C2.c.b(this.f1639g.r0(), 255);
            this.f1635c = C2.c.b(this.f1639g.r0(), 255);
            a aVar = h.f1629g;
            if (aVar.a().isLoggable(Level.FINE)) {
                aVar.a().fine(e.f1510e.c(true, this.f1636d, this.f1634b, iB, this.f1635c));
            }
            int iB2 = this.f1639g.B() & Integer.MAX_VALUE;
            this.f1636d = iB2;
            if (iB == 9) {
                if (iB2 != i3) {
                    throw new IOException("TYPE_CONTINUATION streamId changed");
                }
            } else {
                throw new IOException(iB + " != TYPE_CONTINUATION");
            }
        }

        @Override // Q2.F
        public long R(Q2.i iVar, long j3) throws IOException {
            t2.j.f(iVar, "sink");
            while (true) {
                int i3 = this.f1637e;
                if (i3 != 0) {
                    long jR = this.f1639g.R(iVar, Math.min(j3, i3));
                    if (jR == -1) {
                        return -1L;
                    }
                    this.f1637e -= (int) jR;
                    return jR;
                }
                this.f1639g.t(this.f1638f);
                this.f1638f = 0;
                if ((this.f1635c & 4) != 0) {
                    return -1L;
                }
                i();
            }
        }

        public final int b() {
            return this.f1637e;
        }

        @Override // Q2.F
        public G f() {
            return this.f1639g.f();
        }

        public final void p(int i3) {
            this.f1635c = i3;
        }

        public final void r(int i3) {
            this.f1637e = i3;
        }

        public final void v(int i3) {
            this.f1634b = i3;
        }

        public final void x(int i3) {
            this.f1638f = i3;
        }

        public final void y(int i3) {
            this.f1636d = i3;
        }

        @Override // Q2.F, java.io.Closeable, java.lang.AutoCloseable
        public void close() {
        }
    }
}
