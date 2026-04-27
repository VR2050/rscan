package N0;

import a0.InterfaceC0222h;
import android.graphics.ColorSpace;
import b0.AbstractC0311a;
import h2.C0563i;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;

/* JADX INFO: loaded from: classes.dex */
public class j implements Closeable {

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private static boolean f1883o;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final AbstractC0311a f1884b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final X.n f1885c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private C0.c f1886d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private int f1887e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private int f1888f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private int f1889g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private int f1890h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private int f1891i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private int f1892j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private H0.b f1893k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private ColorSpace f1894l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private String f1895m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private boolean f1896n;

    public j(AbstractC0311a abstractC0311a) {
        this.f1886d = C0.c.f565d;
        this.f1887e = -1;
        this.f1888f = 0;
        this.f1889g = -1;
        this.f1890h = -1;
        this.f1891i = 1;
        this.f1892j = -1;
        X.k.b(Boolean.valueOf(AbstractC0311a.d0(abstractC0311a)));
        this.f1884b = abstractC0311a.clone();
        this.f1885c = null;
    }

    private C0563i A0() {
        InputStream inputStreamP = P();
        if (inputStreamP == null) {
            return null;
        }
        C0563i c0563iF = Y0.k.f(inputStreamP);
        if (c0563iF != null) {
            this.f1889g = ((Integer) c0563iF.a()).intValue();
            this.f1890h = ((Integer) c0563iF.b()).intValue();
        }
        return c0563iF;
    }

    public static j i(j jVar) {
        if (jVar != null) {
            return jVar.b();
        }
        return null;
    }

    private void n0() {
        C0.c cVarD = C0.e.d(P());
        this.f1886d = cVarD;
        C0563i c0563iA0 = C0.b.b(cVarD) ? A0() : z0().b();
        if (cVarD == C0.b.f549b && this.f1887e == -1) {
            if (c0563iA0 != null) {
                int iB = Y0.h.b(P());
                this.f1888f = iB;
                this.f1887e = Y0.h.a(iB);
                return;
            }
            return;
        }
        if (cVarD == C0.b.f559l && this.f1887e == -1) {
            int iA = Y0.f.a(P());
            this.f1888f = iA;
            this.f1887e = Y0.h.a(iA);
        } else if (this.f1887e == -1) {
            this.f1887e = 0;
        }
    }

    public static void p(j jVar) {
        if (jVar != null) {
            jVar.close();
        }
    }

    public static boolean u0(j jVar) {
        return jVar.f1887e >= 0 && jVar.f1889g >= 0 && jVar.f1890h >= 0;
    }

    public static boolean w0(j jVar) {
        return jVar != null && jVar.v0();
    }

    private void y0() {
        if (this.f1889g < 0 || this.f1890h < 0) {
            x0();
        }
    }

    private Y0.g z0() throws Throwable {
        InputStream inputStreamP;
        try {
            inputStreamP = P();
        } catch (Throwable th) {
            th = th;
            inputStreamP = null;
        }
        try {
            Y0.g gVarE = Y0.e.e(inputStreamP);
            this.f1894l = gVarE.a();
            C0563i c0563iB = gVarE.b();
            if (c0563iB != null) {
                this.f1889g = ((Integer) c0563iB.a()).intValue();
                this.f1890h = ((Integer) c0563iB.b()).intValue();
            }
            if (inputStreamP != null) {
                try {
                    inputStreamP.close();
                } catch (IOException unused) {
                }
            }
            return gVarE;
        } catch (Throwable th2) {
            th = th2;
            if (inputStreamP != null) {
                try {
                    inputStreamP.close();
                } catch (IOException unused2) {
                }
            }
            throw th;
        }
    }

    public String A(int i3) {
        AbstractC0311a abstractC0311aV = v();
        if (abstractC0311aV == null) {
            return "";
        }
        int iMin = Math.min(d0(), i3);
        byte[] bArr = new byte[iMin];
        try {
            InterfaceC0222h interfaceC0222h = (InterfaceC0222h) abstractC0311aV.P();
            if (interfaceC0222h == null) {
                return "";
            }
            interfaceC0222h.c(0, bArr, 0, iMin);
            abstractC0311aV.close();
            StringBuilder sb = new StringBuilder(iMin * 2);
            for (int i4 = 0; i4 < iMin; i4++) {
                sb.append(String.format("%02X", Byte.valueOf(bArr[i4])));
            }
            return sb.toString();
        } finally {
            abstractC0311aV.close();
        }
    }

    public void B0(H0.b bVar) {
        this.f1893k = bVar;
    }

    public void C0(int i3) {
        this.f1888f = i3;
    }

    public C0.c D() {
        y0();
        return this.f1886d;
    }

    public void D0(int i3) {
        this.f1890h = i3;
    }

    public void E0(C0.c cVar) {
        this.f1886d = cVar;
    }

    public void F0(int i3) {
        this.f1887e = i3;
    }

    public void G0(int i3) {
        this.f1891i = i3;
    }

    public void H0(String str) {
        this.f1895m = str;
    }

    public void I0(int i3) {
        this.f1889g = i3;
    }

    public int N() {
        y0();
        return this.f1887e;
    }

    public InputStream P() {
        X.n nVar = this.f1885c;
        if (nVar != null) {
            return (InputStream) nVar.get();
        }
        AbstractC0311a abstractC0311aA = AbstractC0311a.A(this.f1884b);
        if (abstractC0311aA == null) {
            return null;
        }
        try {
            return new a0.j((InterfaceC0222h) abstractC0311aA.P());
        } finally {
            AbstractC0311a.D(abstractC0311aA);
        }
    }

    public InputStream W() {
        return (InputStream) X.k.g(P());
    }

    public int Z() {
        return this.f1891i;
    }

    public j b() {
        j jVar;
        X.n nVar = this.f1885c;
        if (nVar != null) {
            jVar = new j(nVar, this.f1892j);
        } else {
            AbstractC0311a abstractC0311aA = AbstractC0311a.A(this.f1884b);
            if (abstractC0311aA == null) {
                jVar = null;
            } else {
                try {
                    jVar = new j(abstractC0311aA);
                } finally {
                    AbstractC0311a.D(abstractC0311aA);
                }
            }
        }
        if (jVar != null) {
            jVar.r(this);
        }
        return jVar;
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        AbstractC0311a.D(this.f1884b);
    }

    public int d() {
        y0();
        return this.f1890h;
    }

    public int d0() {
        AbstractC0311a abstractC0311a = this.f1884b;
        return (abstractC0311a == null || abstractC0311a.P() == null) ? this.f1892j : ((InterfaceC0222h) this.f1884b.P()).size();
    }

    public String e0() {
        return this.f1895m;
    }

    protected boolean f0() {
        return this.f1896n;
    }

    public int h() {
        y0();
        return this.f1889g;
    }

    public void r(j jVar) {
        this.f1886d = jVar.D();
        this.f1889g = jVar.h();
        this.f1890h = jVar.d();
        this.f1887e = jVar.N();
        this.f1888f = jVar.s0();
        this.f1891i = jVar.Z();
        this.f1892j = jVar.d0();
        this.f1893k = jVar.x();
        this.f1894l = jVar.y();
        this.f1896n = jVar.f0();
    }

    public int s0() {
        y0();
        return this.f1888f;
    }

    public boolean t0(int i3) {
        C0.c cVar = this.f1886d;
        if ((cVar != C0.b.f549b && cVar != C0.b.f560m) || this.f1885c != null) {
            return true;
        }
        X.k.g(this.f1884b);
        InterfaceC0222h interfaceC0222h = (InterfaceC0222h) this.f1884b.P();
        if (i3 < 2) {
            return false;
        }
        return interfaceC0222h.g(i3 + (-2)) == -1 && interfaceC0222h.g(i3 - 1) == -39;
    }

    public AbstractC0311a v() {
        return AbstractC0311a.A(this.f1884b);
    }

    /* JADX WARN: Removed duplicated region for block: B:11:0x0012  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public synchronized boolean v0() {
        /*
            r1 = this;
            monitor-enter(r1)
            b0.a r0 = r1.f1884b     // Catch: java.lang.Throwable -> L10
            boolean r0 = b0.AbstractC0311a.d0(r0)     // Catch: java.lang.Throwable -> L10
            if (r0 != 0) goto L12
            X.n r0 = r1.f1885c     // Catch: java.lang.Throwable -> L10
            if (r0 == 0) goto Le
            goto L12
        Le:
            r0 = 0
            goto L13
        L10:
            r0 = move-exception
            goto L15
        L12:
            r0 = 1
        L13:
            monitor-exit(r1)
            return r0
        L15:
            monitor-exit(r1)     // Catch: java.lang.Throwable -> L10
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: N0.j.v0():boolean");
    }

    public H0.b x() {
        return this.f1893k;
    }

    public void x0() {
        if (!f1883o) {
            n0();
        } else {
            if (this.f1896n) {
                return;
            }
            n0();
            this.f1896n = true;
        }
    }

    public ColorSpace y() {
        y0();
        return this.f1894l;
    }

    public j(X.n nVar) {
        this.f1886d = C0.c.f565d;
        this.f1887e = -1;
        this.f1888f = 0;
        this.f1889g = -1;
        this.f1890h = -1;
        this.f1891i = 1;
        this.f1892j = -1;
        X.k.g(nVar);
        this.f1884b = null;
        this.f1885c = nVar;
    }

    public j(X.n nVar, int i3) {
        this(nVar);
        this.f1892j = i3;
    }
}
