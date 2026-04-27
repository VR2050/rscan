package H2;

import B2.B;
import B2.C;
import B2.D;
import B2.E;
import B2.m;
import B2.n;
import B2.v;
import B2.x;
import Q2.q;
import Q2.t;
import i2.AbstractC0586n;
import java.util.List;

/* JADX INFO: loaded from: classes.dex */
public final class a implements v {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final n f1071a;

    public a(n nVar) {
        t2.j.f(nVar, "cookieJar");
        this.f1071a = nVar;
    }

    private final String b(List list) {
        StringBuilder sb = new StringBuilder();
        int i3 = 0;
        for (Object obj : list) {
            int i4 = i3 + 1;
            if (i3 < 0) {
                AbstractC0586n.n();
            }
            m mVar = (m) obj;
            if (i3 > 0) {
                sb.append("; ");
            }
            sb.append(mVar.g());
            sb.append('=');
            sb.append(mVar.i());
            i3 = i4;
        }
        String string = sb.toString();
        t2.j.e(string, "StringBuilder().apply(builderAction).toString()");
        return string;
    }

    @Override // B2.v
    public D a(v.a aVar) {
        E eR;
        t2.j.f(aVar, "chain");
        B bI = aVar.i();
        B.a aVarI = bI.i();
        C cA = bI.a();
        if (cA != null) {
            x xVarB = cA.b();
            if (xVarB != null) {
                aVarI.e("Content-Type", xVarB.toString());
            }
            long jA = cA.a();
            if (jA != -1) {
                aVarI.e("Content-Length", String.valueOf(jA));
                aVarI.i("Transfer-Encoding");
            } else {
                aVarI.e("Transfer-Encoding", "chunked");
                aVarI.i("Content-Length");
            }
        }
        boolean z3 = false;
        if (bI.d("Host") == null) {
            aVarI.e("Host", C2.c.Q(bI.l(), false, 1, null));
        }
        if (bI.d("Connection") == null) {
            aVarI.e("Connection", "Keep-Alive");
        }
        if (bI.d("Accept-Encoding") == null && bI.d("Range") == null) {
            aVarI.e("Accept-Encoding", "gzip");
            z3 = true;
        }
        List listC = this.f1071a.c(bI.l());
        if (!listC.isEmpty()) {
            aVarI.e("Cookie", b(listC));
        }
        if (bI.d("User-Agent") == null) {
            aVarI.e("User-Agent", "okhttp/4.9.2");
        }
        D dA = aVar.a(aVarI.b());
        e.f(this.f1071a, bI.l(), dA.e0());
        D.a aVarR = dA.u0().r(bI);
        if (z3 && z2.g.j("gzip", D.d0(dA, "Content-Encoding", null, 2, null), true) && e.b(dA) && (eR = dA.r()) != null) {
            q qVar = new q(eR.y());
            aVarR.k(dA.e0().e().h("Content-Encoding").h("Content-Length").e());
            aVarR.b(new h(D.d0(dA, "Content-Type", null, 2, null), -1L, t.d(qVar)));
        }
        return aVarR.c();
    }
}
