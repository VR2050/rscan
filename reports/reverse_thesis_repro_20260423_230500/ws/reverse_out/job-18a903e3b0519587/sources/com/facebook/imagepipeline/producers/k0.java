package com.facebook.imagepipeline.producers;

import a0.InterfaceC0223i;
import b0.AbstractC0311a;
import com.facebook.imagepipeline.producers.G;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executor;

/* JADX INFO: loaded from: classes.dex */
public class k0 implements d0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Executor f6292a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final InterfaceC0223i f6293b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final d0 f6294c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final boolean f6295d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final V0.d f6296e;

    private class a extends AbstractC0374t {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final boolean f6297c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final V0.d f6298d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private final e0 f6299e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private boolean f6300f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        private final G f6301g;

        /* JADX INFO: renamed from: com.facebook.imagepipeline.producers.k0$a$a, reason: collision with other inner class name */
        class C0099a implements G.d {

            /* JADX INFO: renamed from: a, reason: collision with root package name */
            final /* synthetic */ k0 f6303a;

            C0099a(k0 k0Var) {
                this.f6303a = k0Var;
            }

            @Override // com.facebook.imagepipeline.producers.G.d
            public void a(N0.j jVar, int i3) throws Throwable {
                if (jVar == null) {
                    a.this.p().d(null, i3);
                } else {
                    a aVar = a.this;
                    aVar.w(jVar, i3, (V0.c) X.k.g(aVar.f6298d.createImageTranscoder(jVar.D(), a.this.f6297c)));
                }
            }
        }

        class b extends AbstractC0361f {

            /* JADX INFO: renamed from: a, reason: collision with root package name */
            final /* synthetic */ k0 f6305a;

            /* JADX INFO: renamed from: b, reason: collision with root package name */
            final /* synthetic */ InterfaceC0369n f6306b;

            b(k0 k0Var, InterfaceC0369n interfaceC0369n) {
                this.f6305a = k0Var;
                this.f6306b = interfaceC0369n;
            }

            @Override // com.facebook.imagepipeline.producers.f0
            public void a() {
                a.this.f6301g.c();
                a.this.f6300f = true;
                this.f6306b.b();
            }

            @Override // com.facebook.imagepipeline.producers.AbstractC0361f, com.facebook.imagepipeline.producers.f0
            public void b() {
                if (a.this.f6299e.d0()) {
                    a.this.f6301g.h();
                }
            }
        }

        a(InterfaceC0369n interfaceC0369n, e0 e0Var, boolean z3, V0.d dVar) {
            super(interfaceC0369n);
            this.f6300f = false;
            this.f6299e = e0Var;
            Boolean boolS = e0Var.W().s();
            this.f6297c = boolS != null ? boolS.booleanValue() : z3;
            this.f6298d = dVar;
            this.f6301g = new G(k0.this.f6292a, new C0099a(k0.this), 100);
            e0Var.Z(new b(k0.this, interfaceC0369n));
        }

        private N0.j A(N0.j jVar) {
            H0.h hVarT = this.f6299e.W().t();
            return (hVarT.h() || !hVarT.g()) ? jVar : y(jVar, hVarT.f());
        }

        private N0.j B(N0.j jVar) {
            return (this.f6299e.W().t().d() || jVar.N() == 0 || jVar.N() == -1) ? jVar : y(jVar, 0);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void w(N0.j jVar, int i3, V0.c cVar) throws Throwable {
            this.f6299e.P().g(this.f6299e, "ResizeAndRotateProducer");
            T0.b bVarW = this.f6299e.W();
            a0.k kVarB = k0.this.f6293b.b();
            try {
                V0.b bVarC = cVar.c(jVar, kVarB, bVarW.t(), bVarW.r(), null, 85, jVar.y());
                if (bVarC.a() == 2) {
                    throw new RuntimeException("Error while transcoding the image");
                }
                Map mapZ = z(jVar, bVarW.r(), bVarC, cVar.b());
                AbstractC0311a abstractC0311aE0 = AbstractC0311a.e0(kVarB.b());
                try {
                    N0.j jVar2 = new N0.j(abstractC0311aE0);
                    jVar2.E0(C0.b.f549b);
                    try {
                        jVar2.x0();
                        this.f6299e.P().d(this.f6299e, "ResizeAndRotateProducer", mapZ);
                        if (bVarC.a() != 1) {
                            i3 |= 16;
                        }
                        p().d(jVar2, i3);
                    } finally {
                        N0.j.p(jVar2);
                    }
                } finally {
                    AbstractC0311a.D(abstractC0311aE0);
                }
            } catch (Exception e3) {
                this.f6299e.P().i(this.f6299e, "ResizeAndRotateProducer", e3, null);
                if (AbstractC0358c.e(i3)) {
                    p().a(e3);
                }
            } finally {
                kVarB.close();
            }
        }

        private void x(N0.j jVar, int i3, C0.c cVar) {
            p().d((cVar == C0.b.f549b || cVar == C0.b.f559l) ? B(jVar) : A(jVar), i3);
        }

        private N0.j y(N0.j jVar, int i3) {
            N0.j jVarI = N0.j.i(jVar);
            if (jVarI != null) {
                jVarI.F0(i3);
            }
            return jVarI;
        }

        private Map z(N0.j jVar, H0.g gVar, V0.b bVar, String str) {
            String str2;
            if (!this.f6299e.P().j(this.f6299e, "ResizeAndRotateProducer")) {
                return null;
            }
            String str3 = jVar.h() + "x" + jVar.d();
            if (gVar != null) {
                str2 = gVar.f1021a + "x" + gVar.f1022b;
            } else {
                str2 = "Unspecified";
            }
            HashMap map = new HashMap();
            map.put("Image format", String.valueOf(jVar.D()));
            map.put("Original size", str3);
            map.put("Requested size", str2);
            map.put("queueTime", String.valueOf(this.f6301g.f()));
            map.put("Transcoder id", str);
            map.put("Transcoding result", String.valueOf(bVar));
            return X.g.a(map);
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.facebook.imagepipeline.producers.AbstractC0358c
        /* JADX INFO: renamed from: C, reason: merged with bridge method [inline-methods] */
        public void i(N0.j jVar, int i3) {
            if (this.f6300f) {
                return;
            }
            boolean zE = AbstractC0358c.e(i3);
            if (jVar == null) {
                if (zE) {
                    p().d(null, 1);
                    return;
                }
                return;
            }
            C0.c cVarD = jVar.D();
            f0.e eVarH = k0.h(this.f6299e.W(), jVar, (V0.c) X.k.g(this.f6298d.createImageTranscoder(cVarD, this.f6297c)));
            if (zE || eVarH != f0.e.UNSET) {
                if (eVarH != f0.e.YES) {
                    x(jVar, i3, cVarD);
                } else if (this.f6301g.k(jVar, i3)) {
                    if (zE || this.f6299e.d0()) {
                        this.f6301g.h();
                    }
                }
            }
        }
    }

    public k0(Executor executor, InterfaceC0223i interfaceC0223i, d0 d0Var, boolean z3, V0.d dVar) {
        this.f6292a = (Executor) X.k.g(executor);
        this.f6293b = (InterfaceC0223i) X.k.g(interfaceC0223i);
        this.f6294c = (d0) X.k.g(d0Var);
        this.f6296e = (V0.d) X.k.g(dVar);
        this.f6295d = z3;
    }

    private static boolean f(H0.h hVar, N0.j jVar) {
        return !hVar.d() && (V0.e.e(hVar, jVar) != 0 || g(hVar, jVar));
    }

    private static boolean g(H0.h hVar, N0.j jVar) {
        if (hVar.g() && !hVar.d()) {
            return V0.e.f2813b.contains(Integer.valueOf(jVar.s0()));
        }
        jVar.C0(0);
        return false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static f0.e h(T0.b bVar, N0.j jVar, V0.c cVar) {
        if (jVar == null || jVar.D() == C0.c.f565d) {
            return f0.e.UNSET;
        }
        if (cVar.d(jVar.D())) {
            return f0.e.c(f(bVar.t(), jVar) || cVar.a(jVar, bVar.t(), bVar.r()));
        }
        return f0.e.NO;
    }

    @Override // com.facebook.imagepipeline.producers.d0
    public void a(InterfaceC0369n interfaceC0369n, e0 e0Var) {
        this.f6294c.a(new a(interfaceC0369n, e0Var, this.f6295d, this.f6296e), e0Var);
    }
}
