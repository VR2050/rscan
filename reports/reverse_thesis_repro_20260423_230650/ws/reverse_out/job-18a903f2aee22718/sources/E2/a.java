package E2;

import B2.A;
import B2.B;
import B2.C0165c;
import B2.D;
import B2.E;
import B2.InterfaceC0167e;
import B2.r;
import B2.t;
import B2.v;
import E2.c;
import H2.f;
import H2.h;
import Q2.F;
import Q2.G;
import Q2.i;
import Q2.j;
import Q2.k;
import java.io.IOException;
import java.util.concurrent.TimeUnit;
import kotlin.jvm.internal.DefaultConstructorMarker;
import z2.g;

/* JADX INFO: loaded from: classes.dex */
public final class a implements v {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final C0014a f646b = new C0014a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final C0165c f647a;

    /* JADX INFO: renamed from: E2.a$a, reason: collision with other inner class name */
    public static final class C0014a {
        private C0014a() {
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final t c(t tVar, t tVar2) {
            t.a aVar = new t.a();
            int size = tVar.size();
            for (int i3 = 0; i3 < size; i3++) {
                String strB = tVar.b(i3);
                String strH = tVar.h(i3);
                if ((!g.j("Warning", strB, true) || !g.u(strH, "1", false, 2, null)) && (d(strB) || !e(strB) || tVar2.a(strB) == null)) {
                    aVar.c(strB, strH);
                }
            }
            int size2 = tVar2.size();
            for (int i4 = 0; i4 < size2; i4++) {
                String strB2 = tVar2.b(i4);
                if (!d(strB2) && e(strB2)) {
                    aVar.c(strB2, tVar2.h(i4));
                }
            }
            return aVar.e();
        }

        private final boolean d(String str) {
            return g.j("Content-Length", str, true) || g.j("Content-Encoding", str, true) || g.j("Content-Type", str, true);
        }

        private final boolean e(String str) {
            return (g.j("Connection", str, true) || g.j("Keep-Alive", str, true) || g.j("Proxy-Authenticate", str, true) || g.j("Proxy-Authorization", str, true) || g.j("TE", str, true) || g.j("Trailers", str, true) || g.j("Transfer-Encoding", str, true) || g.j("Upgrade", str, true)) ? false : true;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final D f(D d3) {
            return (d3 != null ? d3.r() : null) != null ? d3.u0().b(null).c() : d3;
        }

        public /* synthetic */ C0014a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    public static final class b implements F {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private boolean f648b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ k f649c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ E2.b f650d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        final /* synthetic */ j f651e;

        b(k kVar, E2.b bVar, j jVar) {
            this.f649c = kVar;
            this.f650d = bVar;
            this.f651e = jVar;
        }

        @Override // Q2.F
        public long R(i iVar, long j3) throws IOException {
            t2.j.f(iVar, "sink");
            try {
                long jR = this.f649c.R(iVar, j3);
                if (jR != -1) {
                    iVar.D(this.f651e.e(), iVar.F0() - jR, jR);
                    this.f651e.S();
                    return jR;
                }
                if (!this.f648b) {
                    this.f648b = true;
                    this.f651e.close();
                }
                return -1L;
            } catch (IOException e3) {
                if (!this.f648b) {
                    this.f648b = true;
                    this.f650d.b();
                }
                throw e3;
            }
        }

        @Override // Q2.F, java.io.Closeable, java.lang.AutoCloseable
        public void close() {
            if (!this.f648b && !C2.c.p(this, 100, TimeUnit.MILLISECONDS)) {
                this.f648b = true;
                this.f650d.b();
            }
            this.f649c.close();
        }

        @Override // Q2.F
        public G f() {
            return this.f649c.f();
        }
    }

    public a(C0165c c0165c) {
        this.f647a = c0165c;
    }

    private final D b(E2.b bVar, D d3) {
        if (bVar == null) {
            return d3;
        }
        Q2.D dA = bVar.a();
        E eR = d3.r();
        t2.j.c(eR);
        b bVar2 = new b(eR.y(), bVar, Q2.t.c(dA));
        return d3.u0().b(new h(D.d0(d3, "Content-Type", null, 2, null), d3.r().r(), Q2.t.d(bVar2))).c();
    }

    @Override // B2.v
    public D a(v.a aVar) {
        r rVarN;
        E eR;
        E eR2;
        t2.j.f(aVar, "chain");
        InterfaceC0167e interfaceC0167eCall = aVar.call();
        C0165c c0165c = this.f647a;
        D dI = c0165c != null ? c0165c.i(aVar.i()) : null;
        c cVarB = new c.b(System.currentTimeMillis(), aVar.i(), dI).b();
        B b3 = cVarB.b();
        D dA = cVarB.a();
        C0165c c0165c2 = this.f647a;
        if (c0165c2 != null) {
            c0165c2.P(cVarB);
        }
        G2.e eVar = (G2.e) (interfaceC0167eCall instanceof G2.e ? interfaceC0167eCall : null);
        if (eVar == null || (rVarN = eVar.n()) == null) {
            rVarN = r.f400a;
        }
        if (dI != null && dA == null && (eR2 = dI.r()) != null) {
            C2.c.j(eR2);
        }
        if (b3 == null && dA == null) {
            D dC = new D.a().r(aVar.i()).p(A.HTTP_1_1).g(504).m("Unsatisfiable Request (only-if-cached)").b(C2.c.f580c).s(-1L).q(System.currentTimeMillis()).c();
            rVarN.A(interfaceC0167eCall, dC);
            return dC;
        }
        if (b3 == null) {
            t2.j.c(dA);
            D dC2 = dA.u0().d(f646b.f(dA)).c();
            rVarN.b(interfaceC0167eCall, dC2);
            return dC2;
        }
        if (dA != null) {
            rVarN.a(interfaceC0167eCall, dA);
        } else if (this.f647a != null) {
            rVarN.c(interfaceC0167eCall);
        }
        try {
            D dA2 = aVar.a(b3);
            if (dA2 == null && dI != null && eR != null) {
            }
            if (dA != null) {
                if (dA2 != null && dA2.A() == 304) {
                    D.a aVarU0 = dA.u0();
                    C0014a c0014a = f646b;
                    D dC3 = aVarU0.k(c0014a.c(dA.e0(), dA2.e0())).s(dA2.z0()).q(dA2.x0()).d(c0014a.f(dA)).n(c0014a.f(dA2)).c();
                    E eR3 = dA2.r();
                    t2.j.c(eR3);
                    eR3.close();
                    C0165c c0165c3 = this.f647a;
                    t2.j.c(c0165c3);
                    c0165c3.D();
                    this.f647a.W(dA, dC3);
                    rVarN.b(interfaceC0167eCall, dC3);
                    return dC3;
                }
                E eR4 = dA.r();
                if (eR4 != null) {
                    C2.c.j(eR4);
                }
            }
            t2.j.c(dA2);
            D.a aVarU02 = dA2.u0();
            C0014a c0014a2 = f646b;
            D dC4 = aVarU02.d(c0014a2.f(dA)).n(c0014a2.f(dA2)).c();
            if (this.f647a != null) {
                if (H2.e.b(dC4) && c.f652c.a(dC4, b3)) {
                    D dB = b(this.f647a.v(dC4), dC4);
                    if (dA != null) {
                        rVarN.c(interfaceC0167eCall);
                    }
                    return dB;
                }
                if (f.f1078a.a(b3.h())) {
                    try {
                        this.f647a.x(b3);
                    } catch (IOException unused) {
                    }
                }
            }
            return dC4;
        } finally {
            if (dI != null && (eR = dI.r()) != null) {
                C2.c.j(eR);
            }
        }
    }
}
