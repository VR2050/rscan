package J2;

import J2.d;
import java.io.Closeable;
import java.io.IOException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class j implements Closeable {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final Q2.i f1670b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private int f1671c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private boolean f1672d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final d.b f1673e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final Q2.j f1674f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final boolean f1675g;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    public static final a f1669i = new a(null);

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private static final Logger f1668h = Logger.getLogger(e.class.getName());

    public static final class a {
        private a() {
        }

        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    public j(Q2.j jVar, boolean z3) {
        t2.j.f(jVar, "sink");
        this.f1674f = jVar;
        this.f1675g = z3;
        Q2.i iVar = new Q2.i();
        this.f1670b = iVar;
        this.f1671c = 16384;
        this.f1673e = new d.b(0, false, iVar, 3, null);
    }

    private final void e0(int i3, long j3) {
        while (j3 > 0) {
            long jMin = Math.min(this.f1671c, j3);
            j3 -= jMin;
            v(i3, (int) jMin, 9, j3 == 0 ? 4 : 0);
            this.f1674f.m(this.f1670b, jMin);
        }
    }

    public final int A() {
        return this.f1671c;
    }

    public final synchronized void D(boolean z3, int i3, int i4) {
        if (this.f1672d) {
            throw new IOException("closed");
        }
        v(0, 8, 6, z3 ? 1 : 0);
        this.f1674f.E(i3);
        this.f1674f.E(i4);
        this.f1674f.flush();
    }

    public final synchronized void P(int i3, int i4, List list) {
        t2.j.f(list, "requestHeaders");
        if (this.f1672d) {
            throw new IOException("closed");
        }
        this.f1673e.g(list);
        long jF0 = this.f1670b.F0();
        int iMin = (int) Math.min(((long) this.f1671c) - 4, jF0);
        long j3 = iMin;
        v(i3, iMin + 4, 5, jF0 == j3 ? 4 : 0);
        this.f1674f.E(i4 & Integer.MAX_VALUE);
        this.f1674f.m(this.f1670b, j3);
        if (jF0 > j3) {
            e0(i3, jF0 - j3);
        }
    }

    public final synchronized void W(int i3, b bVar) {
        t2.j.f(bVar, "errorCode");
        if (this.f1672d) {
            throw new IOException("closed");
        }
        if (!(bVar.a() != -1)) {
            throw new IllegalArgumentException("Failed requirement.");
        }
        v(i3, 4, 3, 0);
        this.f1674f.E(bVar.a());
        this.f1674f.flush();
    }

    public final synchronized void Z(m mVar) {
        try {
            t2.j.f(mVar, "settings");
            if (this.f1672d) {
                throw new IOException("closed");
            }
            int i3 = 0;
            v(0, mVar.i() * 6, 4, 0);
            while (i3 < 10) {
                if (mVar.f(i3)) {
                    this.f1674f.w(i3 != 4 ? i3 != 7 ? i3 : 4 : 3);
                    this.f1674f.E(mVar.a(i3));
                }
                i3++;
            }
            this.f1674f.flush();
        } catch (Throwable th) {
            throw th;
        }
    }

    public final synchronized void b(m mVar) {
        try {
            t2.j.f(mVar, "peerSettings");
            if (this.f1672d) {
                throw new IOException("closed");
            }
            this.f1671c = mVar.e(this.f1671c);
            if (mVar.b() != -1) {
                this.f1673e.e(mVar.b());
            }
            v(0, 0, 4, 1);
            this.f1674f.flush();
        } catch (Throwable th) {
            throw th;
        }
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public synchronized void close() {
        this.f1672d = true;
        this.f1674f.close();
    }

    public final synchronized void d0(int i3, long j3) {
        if (this.f1672d) {
            throw new IOException("closed");
        }
        if (!(j3 != 0 && j3 <= 2147483647L)) {
            throw new IllegalArgumentException(("windowSizeIncrement == 0 || windowSizeIncrement > 0x7fffffffL: " + j3).toString());
        }
        v(i3, 4, 8, 0);
        this.f1674f.E((int) j3);
        this.f1674f.flush();
    }

    public final synchronized void flush() {
        if (this.f1672d) {
            throw new IOException("closed");
        }
        this.f1674f.flush();
    }

    public final synchronized void i() {
        try {
            if (this.f1672d) {
                throw new IOException("closed");
            }
            if (this.f1675g) {
                Logger logger = f1668h;
                if (logger.isLoggable(Level.FINE)) {
                    logger.fine(C2.c.q(">> CONNECTION " + e.f1506a.k(), new Object[0]));
                }
                this.f1674f.z(e.f1506a);
                this.f1674f.flush();
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    public final synchronized void p(boolean z3, int i3, Q2.i iVar, int i4) {
        if (this.f1672d) {
            throw new IOException("closed");
        }
        r(i3, z3 ? 1 : 0, iVar, i4);
    }

    public final void r(int i3, int i4, Q2.i iVar, int i5) {
        v(i3, i5, 0, i4);
        if (i5 > 0) {
            Q2.j jVar = this.f1674f;
            t2.j.c(iVar);
            jVar.m(iVar, i5);
        }
    }

    public final void v(int i3, int i4, int i5, int i6) {
        Logger logger = f1668h;
        if (logger.isLoggable(Level.FINE)) {
            logger.fine(e.f1510e.c(false, i3, i4, i5, i6));
        }
        if (!(i4 <= this.f1671c)) {
            throw new IllegalArgumentException(("FRAME_SIZE_ERROR length > " + this.f1671c + ": " + i4).toString());
        }
        if (!((((int) 2147483648L) & i3) == 0)) {
            throw new IllegalArgumentException(("reserved bit set: " + i3).toString());
        }
        C2.c.Y(this.f1674f, i4);
        this.f1674f.L(i5 & 255);
        this.f1674f.L(i6 & 255);
        this.f1674f.E(i3 & Integer.MAX_VALUE);
    }

    public final synchronized void x(int i3, b bVar, byte[] bArr) {
        try {
            t2.j.f(bVar, "errorCode");
            t2.j.f(bArr, "debugData");
            if (this.f1672d) {
                throw new IOException("closed");
            }
            boolean z3 = true;
            if (!(bVar.a() != -1)) {
                throw new IllegalArgumentException("errorCode.httpCode == -1");
            }
            v(0, bArr.length + 8, 7, 0);
            this.f1674f.E(i3);
            this.f1674f.E(bVar.a());
            if (bArr.length != 0) {
                z3 = false;
            }
            if (!z3) {
                this.f1674f.Q(bArr);
            }
            this.f1674f.flush();
        } finally {
        }
    }

    public final synchronized void y(boolean z3, int i3, List list) {
        t2.j.f(list, "headerBlock");
        if (this.f1672d) {
            throw new IOException("closed");
        }
        this.f1673e.g(list);
        long jF0 = this.f1670b.F0();
        long jMin = Math.min(this.f1671c, jF0);
        int i4 = jF0 == jMin ? 4 : 0;
        if (z3) {
            i4 |= 1;
        }
        v(i3, (int) jMin, 1, i4);
        this.f1674f.m(this.f1670b, jMin);
        if (jF0 > jMin) {
            e0(i3, jF0 - jMin);
        }
    }
}
