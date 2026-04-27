package I0;

import G0.InterfaceC0172a;
import G0.x;
import a0.InterfaceC0218d;
import android.content.Context;
import com.facebook.imagepipeline.producers.p0;
import com.facebook.imagepipeline.producers.q0;
import java.util.Set;

/* JADX INFO: loaded from: classes.dex */
public class y {

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private static final Class f1402o = y.class;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private static y f1403p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private static C0194t f1404q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private static boolean f1405r;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final p0 f1406a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final InterfaceC0196v f1407b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final C0176a f1408c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final X.n f1409d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private G0.n f1410e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private G0.u f1411f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private G0.n f1412g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private G0.u f1413h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private L0.c f1414i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private V0.d f1415j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private C f1416k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private W f1417l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private F0.b f1418m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private R0.f f1419n;

    public y(InterfaceC0196v interfaceC0196v) {
        if (U0.b.d()) {
            U0.b.a("ImagePipelineConfig()");
        }
        InterfaceC0196v interfaceC0196v2 = (InterfaceC0196v) X.k.g(interfaceC0196v);
        this.f1407b = interfaceC0196v2;
        this.f1406a = interfaceC0196v2.G().F() ? new com.facebook.imagepipeline.producers.B(interfaceC0196v.I().b()) : new q0(interfaceC0196v.I().b());
        this.f1408c = new C0176a(interfaceC0196v.o());
        if (U0.b.d()) {
            U0.b.b();
        }
        this.f1409d = interfaceC0196v2.k();
        if (interfaceC0196v2.G().z()) {
            C0.e.e().g(true);
        }
    }

    private C0194t a() {
        W wP = p();
        Set setU = this.f1407b.u();
        Set setI = this.f1407b.i();
        X.n nVarM = this.f1407b.m();
        G0.u uVarE = e();
        G0.u uVarH = h();
        X.n nVar = this.f1409d;
        G0.k kVarA = this.f1407b.A();
        p0 p0Var = this.f1406a;
        X.n nVarT = this.f1407b.G().t();
        X.n nVarH = this.f1407b.G().H();
        this.f1407b.C();
        return new C0194t(wP, setU, setI, nVarM, uVarE, uVarH, nVar, kVarA, p0Var, nVarT, nVarH, null, this.f1407b);
    }

    private D0.a c() {
        F0.b bVarM = m();
        InterfaceC0191p interfaceC0191pI = this.f1407b.I();
        G0.n nVarD = d();
        boolean zJ = this.f1407b.G().j();
        boolean zV = this.f1407b.G().v();
        int iC = this.f1407b.G().c();
        int iD = this.f1407b.G().d();
        this.f1407b.n();
        D0.b.a(bVarM, interfaceC0191pI, nVarD, zJ, zV, iC, iD, null);
        return null;
    }

    private L0.c i() {
        if (this.f1414i == null) {
            if (this.f1407b.E() != null) {
                this.f1414i = this.f1407b.E();
            } else {
                c();
                L0.c cVarR = r();
                this.f1407b.x();
                this.f1414i = new L0.b(null, null, cVarR, n());
            }
        }
        return this.f1414i;
    }

    private V0.d k() {
        if (this.f1415j == null) {
            if (this.f1407b.v() == null && this.f1407b.s() == null && this.f1407b.G().I()) {
                this.f1415j = new V0.h(this.f1407b.G().m());
            } else {
                this.f1415j = new V0.f(this.f1407b.G().m(), this.f1407b.G().x(), this.f1407b.v(), this.f1407b.s(), this.f1407b.G().E());
            }
        }
        return this.f1415j;
    }

    public static y l() {
        return (y) X.k.h(f1403p, "ImagePipelineFactory was not initialized!");
    }

    private C o() {
        if (this.f1416k == null) {
            this.f1416k = this.f1407b.G().p().a(this.f1407b.c(), this.f1407b.d().i(), i(), this.f1407b.e(), this.f1407b.B(), this.f1407b.F(), this.f1407b.G().A(), this.f1407b.I(), this.f1407b.d().g(this.f1407b.j()), this.f1407b.d().h(), e(), h(), this.f1409d, this.f1407b.A(), m(), this.f1407b.G().g(), this.f1407b.G().f(), this.f1407b.G().e(), this.f1407b.G().m(), f(), this.f1407b.G().l(), this.f1407b.G().u());
        }
        return this.f1416k;
    }

    private W p() {
        boolean zW = this.f1407b.G().w();
        if (this.f1417l == null) {
            this.f1417l = new W(this.f1407b.c().getApplicationContext().getContentResolver(), o(), this.f1407b.q(), this.f1407b.F(), this.f1407b.G().K(), this.f1406a, this.f1407b.B(), zW, this.f1407b.G().J(), this.f1407b.y(), k(), this.f1407b.G().D(), this.f1407b.G().B(), this.f1407b.G().a(), this.f1407b.K());
        }
        return this.f1417l;
    }

    public static synchronized void s(InterfaceC0196v interfaceC0196v) {
        if (f1403p != null) {
            Y.a.E(f1402o, "ImagePipelineFactory has already been initialized! `ImagePipelineFactory.initialize(...)` should only be called once to avoid unexpected behavior.");
            if (f1405r) {
                return;
            }
        }
        f1403p = new y(interfaceC0196v);
    }

    public static synchronized void t(Context context) {
        try {
            if (U0.b.d()) {
                U0.b.a("ImagePipelineFactory#initialize");
            }
            s(C0195u.L(context).a());
            if (U0.b.d()) {
                U0.b.b();
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    public M0.a b(Context context) {
        c();
        return null;
    }

    public G0.n d() {
        if (this.f1410e == null) {
            InterfaceC0172a interfaceC0172aP = this.f1407b.p();
            X.n nVarD = this.f1407b.D();
            InterfaceC0218d interfaceC0218dW = this.f1407b.w();
            x.a aVarJ = this.f1407b.J();
            boolean zR = this.f1407b.G().r();
            boolean zQ = this.f1407b.G().q();
            this.f1407b.l();
            this.f1410e = interfaceC0172aP.a(nVarD, interfaceC0218dW, aVarJ, zR, zQ, null);
        }
        return this.f1410e;
    }

    public G0.u e() {
        if (this.f1411f == null) {
            this.f1411f = G0.v.a(d(), this.f1407b.h());
        }
        return this.f1411f;
    }

    public C0176a f() {
        return this.f1408c;
    }

    public G0.n g() {
        if (this.f1412g == null) {
            this.f1412g = G0.r.a(this.f1407b.H(), this.f1407b.w(), this.f1407b.z());
        }
        return this.f1412g;
    }

    public G0.u h() {
        if (this.f1413h == null) {
            this.f1413h = G0.s.a(this.f1407b.r() != null ? this.f1407b.r() : g(), this.f1407b.h());
        }
        return this.f1413h;
    }

    public C0194t j() {
        if (f1404q == null) {
            f1404q = a();
        }
        return f1404q;
    }

    public F0.b m() {
        if (this.f1418m == null) {
            this.f1418m = F0.c.a(this.f1407b.d(), n(), f());
        }
        return this.f1418m;
    }

    public R0.f n() {
        if (this.f1419n == null) {
            this.f1419n = R0.g.a(this.f1407b.d(), this.f1407b.G().G(), this.f1407b.G().s(), this.f1407b.G().o());
        }
        return this.f1419n;
    }

    public M0.a q() {
        if (this.f1407b.G().z()) {
            return new X0.a();
        }
        return null;
    }

    public L0.c r() {
        if (this.f1407b.G().z()) {
            return new X0.b(this.f1407b.c().getApplicationContext().getResources());
        }
        return null;
    }
}
