package H2;

import B2.B;
import B2.D;
import B2.InterfaceC0167e;
import B2.v;
import java.util.List;

/* JADX INFO: loaded from: classes.dex */
public final class g implements v.a {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private int f1079a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final G2.e f1080b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final List f1081c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final int f1082d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final G2.c f1083e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final B f1084f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final int f1085g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final int f1086h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final int f1087i;

    public g(G2.e eVar, List list, int i3, G2.c cVar, B b3, int i4, int i5, int i6) {
        t2.j.f(eVar, "call");
        t2.j.f(list, "interceptors");
        t2.j.f(b3, "request");
        this.f1080b = eVar;
        this.f1081c = list;
        this.f1082d = i3;
        this.f1083e = cVar;
        this.f1084f = b3;
        this.f1085g = i4;
        this.f1086h = i5;
        this.f1087i = i6;
    }

    public static /* synthetic */ g c(g gVar, int i3, G2.c cVar, B b3, int i4, int i5, int i6, int i7, Object obj) {
        if ((i7 & 1) != 0) {
            i3 = gVar.f1082d;
        }
        if ((i7 & 2) != 0) {
            cVar = gVar.f1083e;
        }
        G2.c cVar2 = cVar;
        if ((i7 & 4) != 0) {
            b3 = gVar.f1084f;
        }
        B b4 = b3;
        if ((i7 & 8) != 0) {
            i4 = gVar.f1085g;
        }
        int i8 = i4;
        if ((i7 & 16) != 0) {
            i5 = gVar.f1086h;
        }
        int i9 = i5;
        if ((i7 & 32) != 0) {
            i6 = gVar.f1087i;
        }
        return gVar.b(i3, cVar2, b4, i8, i9, i6);
    }

    @Override // B2.v.a
    public D a(B b3) {
        t2.j.f(b3, "request");
        if (!(this.f1082d < this.f1081c.size())) {
            throw new IllegalStateException("Check failed.");
        }
        this.f1079a++;
        G2.c cVar = this.f1083e;
        if (cVar != null) {
            if (!cVar.j().g(b3.l())) {
                throw new IllegalStateException(("network interceptor " + ((v) this.f1081c.get(this.f1082d - 1)) + " must retain the same host and port").toString());
            }
            if (!(this.f1079a == 1)) {
                throw new IllegalStateException(("network interceptor " + ((v) this.f1081c.get(this.f1082d - 1)) + " must call proceed() exactly once").toString());
            }
        }
        g gVarC = c(this, this.f1082d + 1, null, b3, 0, 0, 0, 58, null);
        v vVar = (v) this.f1081c.get(this.f1082d);
        D dA = vVar.a(gVarC);
        if (dA == null) {
            throw new NullPointerException("interceptor " + vVar + " returned null");
        }
        if (this.f1083e != null) {
            if (!(this.f1082d + 1 >= this.f1081c.size() || gVarC.f1079a == 1)) {
                throw new IllegalStateException(("network interceptor " + vVar + " must call proceed() exactly once").toString());
            }
        }
        if (dA.r() != null) {
            return dA;
        }
        throw new IllegalStateException(("interceptor " + vVar + " returned a response with no body").toString());
    }

    public final g b(int i3, G2.c cVar, B b3, int i4, int i5, int i6) {
        t2.j.f(b3, "request");
        return new g(this.f1080b, this.f1081c, i3, cVar, b3, i4, i5, i6);
    }

    @Override // B2.v.a
    public InterfaceC0167e call() {
        return this.f1080b;
    }

    public final G2.e d() {
        return this.f1080b;
    }

    public final int e() {
        return this.f1085g;
    }

    public final G2.c f() {
        return this.f1083e;
    }

    public final int g() {
        return this.f1086h;
    }

    public final B h() {
        return this.f1084f;
    }

    @Override // B2.v.a
    public B i() {
        return this.f1084f;
    }

    public final int j() {
        return this.f1087i;
    }

    public int k() {
        return this.f1086h;
    }
}
