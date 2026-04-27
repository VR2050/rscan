package G2;

import B2.C0163a;
import B2.F;
import B2.r;
import B2.u;
import B2.z;
import G2.k;
import J2.n;
import java.io.IOException;

/* JADX INFO: loaded from: classes.dex */
public final class d {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private k.b f895a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private k f896b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private int f897c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private int f898d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private int f899e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private F f900f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final h f901g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final C0163a f902h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final e f903i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final r f904j;

    public d(h hVar, C0163a c0163a, e eVar, r rVar) {
        t2.j.f(hVar, "connectionPool");
        t2.j.f(c0163a, "address");
        t2.j.f(eVar, "call");
        t2.j.f(rVar, "eventListener");
        this.f901g = hVar;
        this.f902h = c0163a;
        this.f903i = eVar;
        this.f904j = rVar;
    }

    /* JADX WARN: Removed duplicated region for block: B:59:0x0133  */
    /* JADX WARN: Removed duplicated region for block: B:61:0x014d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private final G2.f b(int r15, int r16, int r17, int r18, boolean r19) throws java.io.IOException {
        /*
            Method dump skipped, instruction units count: 381
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: G2.d.b(int, int, int, int, boolean):G2.f");
    }

    private final f c(int i3, int i4, int i5, int i6, boolean z3, boolean z4) throws IOException {
        while (true) {
            f fVarB = b(i3, i4, i5, i6, z3);
            if (fVarB.u(z4)) {
                return fVarB;
            }
            fVarB.z();
            if (this.f900f == null) {
                k.b bVar = this.f895a;
                if (bVar != null ? bVar.b() : true) {
                    continue;
                } else {
                    k kVar = this.f896b;
                    if (!(kVar != null ? kVar.b() : true)) {
                        throw new IOException("exhausted all routes");
                    }
                }
            }
        }
    }

    private final F f() {
        f fVarM;
        if (this.f897c > 1 || this.f898d > 1 || this.f899e > 0 || (fVarM = this.f903i.m()) == null) {
            return null;
        }
        synchronized (fVarM) {
            if (fVarM.q() != 0) {
                return null;
            }
            if (C2.c.g(fVarM.A().a().l(), this.f902h.l())) {
                return fVarM.A();
            }
            return null;
        }
    }

    public final H2.d a(z zVar, H2.g gVar) {
        t2.j.f(zVar, "client");
        t2.j.f(gVar, "chain");
        try {
            return c(gVar.e(), gVar.g(), gVar.j(), zVar.E(), zVar.K(), !t2.j.b(gVar.h().h(), "GET")).w(zVar, gVar);
        } catch (j e3) {
            h(e3.c());
            throw e3;
        } catch (IOException e4) {
            h(e4);
            throw new j(e4);
        }
    }

    public final C0163a d() {
        return this.f902h;
    }

    public final boolean e() {
        k kVar;
        if (this.f897c == 0 && this.f898d == 0 && this.f899e == 0) {
            return false;
        }
        if (this.f900f != null) {
            return true;
        }
        F f3 = f();
        if (f3 != null) {
            this.f900f = f3;
            return true;
        }
        k.b bVar = this.f895a;
        if ((bVar == null || !bVar.b()) && (kVar = this.f896b) != null) {
            return kVar.b();
        }
        return true;
    }

    public final boolean g(u uVar) {
        t2.j.f(uVar, "url");
        u uVarL = this.f902h.l();
        return uVar.l() == uVarL.l() && t2.j.b(uVar.h(), uVarL.h());
    }

    public final void h(IOException iOException) {
        t2.j.f(iOException, "e");
        this.f900f = null;
        if ((iOException instanceof n) && ((n) iOException).f1688b == J2.b.REFUSED_STREAM) {
            this.f897c++;
        } else if (iOException instanceof J2.a) {
            this.f898d++;
        } else {
            this.f899e++;
        }
    }
}
