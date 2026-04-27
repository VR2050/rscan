package L0;

import N0.j;
import N0.o;
import X.k;
import X.n;
import android.graphics.ColorSpace;
import b0.AbstractC0311a;
import java.io.InputStream;
import java.util.Map;

/* JADX INFO: loaded from: classes.dex */
public class b implements c {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final c f1696a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final c f1697b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final c f1698c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final R0.f f1699d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final n f1700e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final c f1701f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final Map f1702g;

    class a implements c {
        a() {
        }

        @Override // L0.c
        public N0.d a(j jVar, int i3, o oVar, H0.d dVar) {
            ColorSpace colorSpaceY;
            C0.c cVarD = jVar.D();
            if (((Boolean) b.this.f1700e.get()).booleanValue()) {
                colorSpaceY = dVar.f1000k;
                if (colorSpaceY == null) {
                    colorSpaceY = jVar.y();
                }
            } else {
                colorSpaceY = dVar.f1000k;
            }
            ColorSpace colorSpace = colorSpaceY;
            if (cVarD == C0.b.f549b) {
                return b.this.f(jVar, i3, oVar, dVar, colorSpace);
            }
            if (cVarD == C0.b.f551d) {
                return b.this.e(jVar, i3, oVar, dVar);
            }
            if (cVarD == C0.b.f558k) {
                return b.this.d(jVar, i3, oVar, dVar);
            }
            if (cVarD == C0.b.f561n) {
                return b.this.h(jVar, i3, oVar, dVar);
            }
            if (cVarD != C0.c.f565d) {
                return b.this.g(jVar, dVar);
            }
            throw new L0.a("unknown image format", jVar);
        }
    }

    public b(c cVar, c cVar2, c cVar3, R0.f fVar) {
        this(cVar, cVar2, cVar3, fVar, null);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public N0.d h(j jVar, int i3, o oVar, H0.d dVar) {
        c cVar = this.f1698c;
        if (cVar != null) {
            return cVar.a(jVar, i3, oVar, dVar);
        }
        return null;
    }

    @Override // L0.c
    public N0.d a(j jVar, int i3, o oVar, H0.d dVar) {
        InputStream inputStreamP;
        c cVar;
        c cVar2 = dVar.f999j;
        if (cVar2 != null) {
            return cVar2.a(jVar, i3, oVar, dVar);
        }
        C0.c cVarD = jVar.D();
        if ((cVarD == null || cVarD == C0.c.f565d) && (inputStreamP = jVar.P()) != null) {
            cVarD = C0.e.d(inputStreamP);
            jVar.E0(cVarD);
        }
        Map map = this.f1702g;
        return (map == null || (cVar = (c) map.get(cVarD)) == null) ? this.f1701f.a(jVar, i3, oVar, dVar) : cVar.a(jVar, i3, oVar, dVar);
    }

    public N0.d d(j jVar, int i3, o oVar, H0.d dVar) {
        c cVar;
        return (dVar.f996g || (cVar = this.f1697b) == null) ? g(jVar, dVar) : cVar.a(jVar, i3, oVar, dVar);
    }

    public N0.d e(j jVar, int i3, o oVar, H0.d dVar) {
        c cVar;
        if (jVar.h() == -1 || jVar.d() == -1) {
            throw new L0.a("image width or height is incorrect", jVar);
        }
        return (dVar.f996g || (cVar = this.f1696a) == null) ? g(jVar, dVar) : cVar.a(jVar, i3, oVar, dVar);
    }

    public N0.e f(j jVar, int i3, o oVar, H0.d dVar, ColorSpace colorSpace) {
        AbstractC0311a abstractC0311aA = this.f1699d.a(jVar, dVar.f997h, null, i3, colorSpace);
        try {
            W0.b.a(null, abstractC0311aA);
            k.g(abstractC0311aA);
            N0.e eVarA0 = N0.e.a0(abstractC0311aA, oVar, jVar.N(), jVar.s0());
            eVarA0.A("is_rounded", false);
            return eVarA0;
        } finally {
            AbstractC0311a.D(abstractC0311aA);
        }
    }

    public N0.e g(j jVar, H0.d dVar) {
        AbstractC0311a abstractC0311aB = this.f1699d.b(jVar, dVar.f997h, null, dVar.f1000k);
        try {
            W0.b.a(null, abstractC0311aB);
            k.g(abstractC0311aB);
            N0.e eVarA0 = N0.e.a0(abstractC0311aB, N0.n.f1902d, jVar.N(), jVar.s0());
            eVarA0.A("is_rounded", false);
            return eVarA0;
        } finally {
            AbstractC0311a.D(abstractC0311aB);
        }
    }

    public b(c cVar, c cVar2, c cVar3, R0.f fVar, Map map) {
        this(cVar, cVar2, cVar3, fVar, map, X.o.f2853b);
    }

    public b(c cVar, c cVar2, c cVar3, R0.f fVar, Map map, n nVar) {
        this.f1701f = new a();
        this.f1696a = cVar;
        this.f1697b = cVar2;
        this.f1698c = cVar3;
        this.f1699d = fVar;
        this.f1702g = map;
        this.f1700e = nVar;
    }
}
