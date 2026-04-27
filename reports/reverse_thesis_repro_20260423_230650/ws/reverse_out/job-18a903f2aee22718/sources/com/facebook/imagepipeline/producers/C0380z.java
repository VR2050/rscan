package com.facebook.imagepipeline.producers;

import T0.b;
import b0.AbstractC0311a;

/* JADX INFO: renamed from: com.facebook.imagepipeline.producers.z, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0380z implements d0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final G0.x f6397a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final G0.k f6398b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final d0 f6399c;

    /* JADX INFO: renamed from: com.facebook.imagepipeline.producers.z$a */
    private static class a extends AbstractC0374t {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final G0.x f6400c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final R.d f6401d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private final boolean f6402e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private final boolean f6403f;

        public a(InterfaceC0369n interfaceC0369n, G0.x xVar, R.d dVar, boolean z3, boolean z4) {
            super(interfaceC0369n);
            this.f6400c = xVar;
            this.f6401d = dVar;
            this.f6402e = z3;
            this.f6403f = z4;
        }

        @Override // com.facebook.imagepipeline.producers.AbstractC0358c
        /* JADX INFO: renamed from: q, reason: merged with bridge method [inline-methods] */
        public void i(N0.j jVar, int i3) {
            try {
                if (U0.b.d()) {
                    U0.b.a("EncodedMemoryCacheProducer#onNewResultImpl");
                }
                if (!AbstractC0358c.f(i3) && jVar != null && !AbstractC0358c.m(i3, 10) && jVar.D() != C0.c.f565d) {
                    AbstractC0311a abstractC0311aV = jVar.v();
                    if (abstractC0311aV != null) {
                        try {
                            AbstractC0311a abstractC0311aB = (this.f6403f && this.f6402e) ? this.f6400c.b(this.f6401d, abstractC0311aV) : null;
                            if (abstractC0311aB != null) {
                                try {
                                    N0.j jVar2 = new N0.j(abstractC0311aB);
                                    jVar2.r(jVar);
                                    try {
                                        p().c(1.0f);
                                        p().d(jVar2, i3);
                                        if (U0.b.d()) {
                                            U0.b.b();
                                            return;
                                        }
                                        return;
                                    } finally {
                                        N0.j.p(jVar2);
                                    }
                                } finally {
                                    AbstractC0311a.D(abstractC0311aB);
                                }
                            }
                        } finally {
                            AbstractC0311a.D(abstractC0311aV);
                        }
                    }
                    p().d(jVar, i3);
                    if (U0.b.d()) {
                        U0.b.b();
                        return;
                    }
                    return;
                }
                p().d(jVar, i3);
                if (U0.b.d()) {
                    U0.b.b();
                }
            } catch (Throwable th) {
                if (U0.b.d()) {
                    U0.b.b();
                }
                throw th;
            }
        }
    }

    public C0380z(G0.x xVar, G0.k kVar, d0 d0Var) {
        this.f6397a = xVar;
        this.f6398b = kVar;
        this.f6399c = d0Var;
    }

    @Override // com.facebook.imagepipeline.producers.d0
    public void a(InterfaceC0369n interfaceC0369n, e0 e0Var) {
        try {
            if (U0.b.d()) {
                U0.b.a("EncodedMemoryCacheProducer#produceResults");
            }
            g0 g0VarP = e0Var.P();
            g0VarP.g(e0Var, "EncodedMemoryCacheProducer");
            R.d dVarA = this.f6398b.a(e0Var.W(), e0Var.i());
            AbstractC0311a abstractC0311a = e0Var.W().y(4) ? this.f6397a.get(dVarA) : null;
            try {
                if (abstractC0311a != null) {
                    N0.j jVar = new N0.j(abstractC0311a);
                    try {
                        g0VarP.d(e0Var, "EncodedMemoryCacheProducer", g0VarP.j(e0Var, "EncodedMemoryCacheProducer") ? X.g.of("cached_value_found", "true") : null);
                        g0VarP.e(e0Var, "EncodedMemoryCacheProducer", true);
                        e0Var.D("memory_encoded");
                        interfaceC0369n.c(1.0f);
                        interfaceC0369n.d(jVar, 1);
                        N0.j.p(jVar);
                        if (U0.b.d()) {
                            U0.b.b();
                            return;
                        }
                        return;
                    } catch (Throwable th) {
                        N0.j.p(jVar);
                        throw th;
                    }
                }
                if (e0Var.e0().b() < b.c.ENCODED_MEMORY_CACHE.b()) {
                    a aVar = new a(interfaceC0369n, this.f6397a, dVarA, e0Var.W().y(8), e0Var.f0().G().C());
                    g0VarP.d(e0Var, "EncodedMemoryCacheProducer", g0VarP.j(e0Var, "EncodedMemoryCacheProducer") ? X.g.of("cached_value_found", "false") : null);
                    this.f6399c.a(aVar, e0Var);
                    if (U0.b.d()) {
                        U0.b.b();
                        return;
                    }
                    return;
                }
                g0VarP.d(e0Var, "EncodedMemoryCacheProducer", g0VarP.j(e0Var, "EncodedMemoryCacheProducer") ? X.g.of("cached_value_found", "false") : null);
                g0VarP.e(e0Var, "EncodedMemoryCacheProducer", false);
                e0Var.n0("memory_encoded", "nil-result");
                interfaceC0369n.d(null, 1);
                if (U0.b.d()) {
                    U0.b.b();
                }
            } finally {
                AbstractC0311a.D(abstractC0311a);
            }
        } catch (Throwable th2) {
            if (U0.b.d()) {
                U0.b.b();
            }
            throw th2;
        }
    }
}
