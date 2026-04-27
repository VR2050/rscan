package H2;

import B2.B;
import B2.C;
import B2.D;
import B2.E;
import B2.v;
import Q2.t;
import java.io.IOException;
import java.net.ProtocolException;

/* JADX INFO: loaded from: classes.dex */
public final class b implements v {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final boolean f1072a;

    public b(boolean z3) {
        this.f1072a = z3;
    }

    @Override // B2.v
    public D a(v.a aVar) throws IOException {
        boolean z3;
        D.a aVarQ;
        t2.j.f(aVar, "chain");
        g gVar = (g) aVar;
        G2.c cVarF = gVar.f();
        t2.j.c(cVarF);
        B bH = gVar.h();
        C cA = bH.a();
        long jCurrentTimeMillis = System.currentTimeMillis();
        cVarF.v(bH);
        if (!f.b(bH.h()) || cA == null) {
            cVarF.o();
            z3 = true;
            aVarQ = null;
        } else {
            if (z2.g.j("100-continue", bH.d("Expect"), true)) {
                cVarF.f();
                aVarQ = cVarF.q(true);
                cVarF.s();
                z3 = false;
            } else {
                z3 = true;
                aVarQ = null;
            }
            if (aVarQ != null) {
                cVarF.o();
                if (!cVarF.h().v()) {
                    cVarF.n();
                }
            } else if (cA.f()) {
                cVarF.f();
                cA.h(t.c(cVarF.c(bH, true)));
            } else {
                Q2.j jVarC = t.c(cVarF.c(bH, false));
                cA.h(jVarC);
                jVarC.close();
            }
        }
        if (cA == null || !cA.f()) {
            cVarF.e();
        }
        if (aVarQ == null) {
            aVarQ = cVarF.q(false);
            t2.j.c(aVarQ);
            if (z3) {
                cVarF.s();
                z3 = false;
            }
        }
        D dC = aVarQ.r(bH).i(cVarF.h().r()).s(jCurrentTimeMillis).q(System.currentTimeMillis()).c();
        int iA = dC.A();
        if (iA == 100) {
            D.a aVarQ2 = cVarF.q(false);
            t2.j.c(aVarQ2);
            if (z3) {
                cVarF.s();
            }
            dC = aVarQ2.r(bH).i(cVarF.h().r()).s(jCurrentTimeMillis).q(System.currentTimeMillis()).c();
            iA = dC.A();
        }
        cVarF.r(dC);
        D dC2 = (this.f1072a && iA == 101) ? dC.u0().b(C2.c.f580c).c() : dC.u0().b(cVarF.p(dC)).c();
        if (z2.g.j("close", dC2.y0().d("Connection"), true) || z2.g.j("close", D.d0(dC2, "Connection", null, 2, null), true)) {
            cVarF.n();
        }
        if (iA == 204 || iA == 205) {
            E eR = dC2.r();
            if ((eR != null ? eR.r() : -1L) > 0) {
                StringBuilder sb = new StringBuilder();
                sb.append("HTTP ");
                sb.append(iA);
                sb.append(" had non-zero Content-Length: ");
                E eR2 = dC2.r();
                sb.append(eR2 != null ? Long.valueOf(eR2.r()) : null);
                throw new ProtocolException(sb.toString());
            }
        }
        return dC2;
    }
}
