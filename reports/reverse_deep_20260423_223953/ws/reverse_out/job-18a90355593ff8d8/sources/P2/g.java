package P2;

import Q2.i;
import Q2.k;
import Q2.l;
import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.net.ProtocolException;
import java.util.concurrent.TimeUnit;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class g implements Closeable {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private boolean f2285b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private int f2286c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private long f2287d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private boolean f2288e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private boolean f2289f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private boolean f2290g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final i f2291h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final i f2292i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private c f2293j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private final byte[] f2294k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private final i.a f2295l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private final boolean f2296m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private final k f2297n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private final a f2298o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private final boolean f2299p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private final boolean f2300q;

    public interface a {
        void a(l lVar);

        void d(l lVar);

        void f(l lVar);

        void g(String str);

        void h(int i3, String str);
    }

    public g(boolean z3, k kVar, a aVar, boolean z4, boolean z5) {
        j.f(kVar, "source");
        j.f(aVar, "frameCallback");
        this.f2296m = z3;
        this.f2297n = kVar;
        this.f2298o = aVar;
        this.f2299p = z4;
        this.f2300q = z5;
        this.f2291h = new i();
        this.f2292i = new i();
        this.f2294k = z3 ? null : new byte[4];
        this.f2295l = z3 ? null : new i.a();
    }

    private final void i() throws ProtocolException, EOFException {
        short sX;
        String strO;
        long j3 = this.f2287d;
        if (j3 > 0) {
            this.f2297n.J(this.f2291h, j3);
            if (!this.f2296m) {
                i iVar = this.f2291h;
                i.a aVar = this.f2295l;
                j.c(aVar);
                iVar.x0(aVar);
                this.f2295l.p(0L);
                f fVar = f.f2284a;
                i.a aVar2 = this.f2295l;
                byte[] bArr = this.f2294k;
                j.c(bArr);
                fVar.b(aVar2, bArr);
                this.f2295l.close();
            }
        }
        switch (this.f2286c) {
            case 8:
                long jF0 = this.f2291h.F0();
                if (jF0 == 1) {
                    throw new ProtocolException("Malformed close payload length of 1.");
                }
                if (jF0 != 0) {
                    sX = this.f2291h.X();
                    strO = this.f2291h.O();
                    String strA = f.f2284a.a(sX);
                    if (strA != null) {
                        throw new ProtocolException(strA);
                    }
                } else {
                    sX = 1005;
                    strO = "";
                }
                this.f2298o.h(sX, strO);
                this.f2285b = true;
                return;
            case 9:
                this.f2298o.d(this.f2291h.z0());
                return;
            case 10:
                this.f2298o.a(this.f2291h.z0());
                return;
            default:
                throw new ProtocolException("Unknown control opcode: " + C2.c.N(this.f2286c));
        }
    }

    private final void p() throws IOException {
        boolean z3;
        if (this.f2285b) {
            throw new IOException("closed");
        }
        long jH = this.f2297n.f().h();
        this.f2297n.f().b();
        try {
            int iB = C2.c.b(this.f2297n.r0(), 255);
            this.f2297n.f().g(jH, TimeUnit.NANOSECONDS);
            int i3 = iB & 15;
            this.f2286c = i3;
            boolean z4 = (iB & 128) != 0;
            this.f2288e = z4;
            boolean z5 = (iB & 8) != 0;
            this.f2289f = z5;
            if (z5 && !z4) {
                throw new ProtocolException("Control frames must be final.");
            }
            boolean z6 = (iB & 64) != 0;
            if (i3 == 1 || i3 == 2) {
                if (!z6) {
                    z3 = false;
                } else {
                    if (!this.f2299p) {
                        throw new ProtocolException("Unexpected rsv1 flag");
                    }
                    z3 = true;
                }
                this.f2290g = z3;
            } else if (z6) {
                throw new ProtocolException("Unexpected rsv1 flag");
            }
            if ((iB & 32) != 0) {
                throw new ProtocolException("Unexpected rsv2 flag");
            }
            if ((iB & 16) != 0) {
                throw new ProtocolException("Unexpected rsv3 flag");
            }
            int iB2 = C2.c.b(this.f2297n.r0(), 255);
            boolean z7 = (iB2 & 128) != 0;
            if (z7 == this.f2296m) {
                throw new ProtocolException(this.f2296m ? "Server-sent frames must not be masked." : "Client-sent frames must be masked.");
            }
            long j3 = iB2 & 127;
            this.f2287d = j3;
            if (j3 == 126) {
                this.f2287d = C2.c.c(this.f2297n.X(), 65535);
            } else if (j3 == 127) {
                long jG = this.f2297n.G();
                this.f2287d = jG;
                if (jG < 0) {
                    throw new ProtocolException("Frame length 0x" + C2.c.O(this.f2287d) + " > 0x7FFFFFFFFFFFFFFF");
                }
            }
            if (this.f2289f && this.f2287d > 125) {
                throw new ProtocolException("Control frame must be less than 125B.");
            }
            if (z7) {
                k kVar = this.f2297n;
                byte[] bArr = this.f2294k;
                j.c(bArr);
                kVar.l(bArr);
            }
        } catch (Throwable th) {
            this.f2297n.f().g(jH, TimeUnit.NANOSECONDS);
            throw th;
        }
    }

    private final void r() throws IOException {
        while (!this.f2285b) {
            long j3 = this.f2287d;
            if (j3 > 0) {
                this.f2297n.J(this.f2292i, j3);
                if (!this.f2296m) {
                    i iVar = this.f2292i;
                    i.a aVar = this.f2295l;
                    j.c(aVar);
                    iVar.x0(aVar);
                    this.f2295l.p(this.f2292i.F0() - this.f2287d);
                    f fVar = f.f2284a;
                    i.a aVar2 = this.f2295l;
                    byte[] bArr = this.f2294k;
                    j.c(bArr);
                    fVar.b(aVar2, bArr);
                    this.f2295l.close();
                }
            }
            if (this.f2288e) {
                return;
            }
            x();
            if (this.f2286c != 0) {
                throw new ProtocolException("Expected continuation opcode. Got: " + C2.c.N(this.f2286c));
            }
        }
        throw new IOException("closed");
    }

    private final void v() throws IOException {
        int i3 = this.f2286c;
        if (i3 != 1 && i3 != 2) {
            throw new ProtocolException("Unknown opcode: " + C2.c.N(i3));
        }
        r();
        if (this.f2290g) {
            c cVar = this.f2293j;
            if (cVar == null) {
                cVar = new c(this.f2300q);
                this.f2293j = cVar;
            }
            cVar.b(this.f2292i);
        }
        if (i3 == 1) {
            this.f2298o.g(this.f2292i.O());
        } else {
            this.f2298o.f(this.f2292i.z0());
        }
    }

    private final void x() throws IOException {
        while (!this.f2285b) {
            p();
            if (!this.f2289f) {
                return;
            } else {
                i();
            }
        }
    }

    public final void b() {
        p();
        if (this.f2289f) {
            i();
        } else {
            v();
        }
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        c cVar = this.f2293j;
        if (cVar != null) {
            cVar.close();
        }
    }
}
