package P2;

import Q2.i;
import Q2.j;
import Q2.l;
import java.io.Closeable;
import java.io.IOException;
import java.util.Random;

/* JADX INFO: loaded from: classes.dex */
public final class h implements Closeable {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final i f2301b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final i f2302c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private boolean f2303d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private a f2304e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final byte[] f2305f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final i.a f2306g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final boolean f2307h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final j f2308i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final Random f2309j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private final boolean f2310k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private final boolean f2311l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private final long f2312m;

    public h(boolean z3, j jVar, Random random, boolean z4, boolean z5, long j3) {
        t2.j.f(jVar, "sink");
        t2.j.f(random, "random");
        this.f2307h = z3;
        this.f2308i = jVar;
        this.f2309j = random;
        this.f2310k = z4;
        this.f2311l = z5;
        this.f2312m = j3;
        this.f2301b = new i();
        this.f2302c = jVar.e();
        this.f2305f = z3 ? new byte[4] : null;
        this.f2306g = z3 ? new i.a() : null;
    }

    private final void i(int i3, l lVar) throws IOException {
        if (this.f2303d) {
            throw new IOException("closed");
        }
        int iV = lVar.v();
        if (!(((long) iV) <= 125)) {
            throw new IllegalArgumentException("Payload size must be less than or equal to 125");
        }
        this.f2302c.L(i3 | 128);
        if (this.f2307h) {
            this.f2302c.L(iV | 128);
            Random random = this.f2309j;
            byte[] bArr = this.f2305f;
            t2.j.c(bArr);
            random.nextBytes(bArr);
            this.f2302c.Q(this.f2305f);
            if (iV > 0) {
                long jF0 = this.f2302c.F0();
                this.f2302c.z(lVar);
                i iVar = this.f2302c;
                i.a aVar = this.f2306g;
                t2.j.c(aVar);
                iVar.x0(aVar);
                this.f2306g.p(jF0);
                f.f2284a.b(this.f2306g, this.f2305f);
                this.f2306g.close();
            }
        } else {
            this.f2302c.L(iV);
            this.f2302c.z(lVar);
        }
        this.f2308i.flush();
    }

    public final void b(int i3, l lVar) {
        l lVarZ0 = l.f2555e;
        if (i3 != 0 || lVar != null) {
            if (i3 != 0) {
                f.f2284a.c(i3);
            }
            i iVar = new i();
            iVar.w(i3);
            if (lVar != null) {
                iVar.z(lVar);
            }
            lVarZ0 = iVar.z0();
        }
        try {
            i(8, lVarZ0);
        } finally {
            this.f2303d = true;
        }
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public void close() throws Throwable {
        a aVar = this.f2304e;
        if (aVar != null) {
            aVar.close();
        }
    }

    public final void p(int i3, l lVar) throws IOException {
        t2.j.f(lVar, "data");
        if (this.f2303d) {
            throw new IOException("closed");
        }
        this.f2301b.z(lVar);
        int i4 = i3 | 128;
        if (this.f2310k && lVar.v() >= this.f2312m) {
            a aVar = this.f2304e;
            if (aVar == null) {
                aVar = new a(this.f2311l);
                this.f2304e = aVar;
            }
            aVar.b(this.f2301b);
            i4 = i3 | 192;
        }
        long jF0 = this.f2301b.F0();
        this.f2302c.L(i4);
        int i5 = this.f2307h ? 128 : 0;
        if (jF0 <= 125) {
            this.f2302c.L(i5 | ((int) jF0));
        } else if (jF0 <= 65535) {
            this.f2302c.L(i5 | 126);
            this.f2302c.w((int) jF0);
        } else {
            this.f2302c.L(i5 | 127);
            this.f2302c.Q0(jF0);
        }
        if (this.f2307h) {
            Random random = this.f2309j;
            byte[] bArr = this.f2305f;
            t2.j.c(bArr);
            random.nextBytes(bArr);
            this.f2302c.Q(this.f2305f);
            if (jF0 > 0) {
                i iVar = this.f2301b;
                i.a aVar2 = this.f2306g;
                t2.j.c(aVar2);
                iVar.x0(aVar2);
                this.f2306g.p(0L);
                f.f2284a.b(this.f2306g, this.f2305f);
                this.f2306g.close();
            }
        }
        this.f2302c.m(this.f2301b, jF0);
        this.f2308i.u();
    }

    public final void r(l lVar) throws IOException {
        t2.j.f(lVar, "payload");
        i(9, lVar);
    }

    public final void v(l lVar) throws IOException {
        t2.j.f(lVar, "payload");
        i(10, lVar);
    }
}
