package com.facebook.imagepipeline.producers;

import b0.AbstractC0311a;

/* JADX INFO: loaded from: classes.dex */
public class a0 implements d0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final G0.x f6223a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final G0.k f6224b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final d0 f6225c;

    public static class a extends AbstractC0374t {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final R.d f6226c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final boolean f6227d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private final G0.x f6228e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private final boolean f6229f;

        public a(InterfaceC0369n interfaceC0369n, R.d dVar, boolean z3, G0.x xVar, boolean z4) {
            super(interfaceC0369n);
            this.f6226c = dVar;
            this.f6227d = z3;
            this.f6228e = xVar;
            this.f6229f = z4;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.facebook.imagepipeline.producers.AbstractC0358c
        /* JADX INFO: renamed from: q, reason: merged with bridge method [inline-methods] */
        public void i(AbstractC0311a abstractC0311a, int i3) {
            if (abstractC0311a == null) {
                if (AbstractC0358c.e(i3)) {
                    p().d(null, i3);
                }
            } else if (!AbstractC0358c.f(i3) || this.f6227d) {
                AbstractC0311a abstractC0311aB = this.f6229f ? this.f6228e.b(this.f6226c, abstractC0311a) : null;
                try {
                    p().c(1.0f);
                    InterfaceC0369n interfaceC0369nP = p();
                    if (abstractC0311aB != null) {
                        abstractC0311a = abstractC0311aB;
                    }
                    interfaceC0369nP.d(abstractC0311a, i3);
                } finally {
                    AbstractC0311a.D(abstractC0311aB);
                }
            }
        }
    }

    public a0(G0.x xVar, G0.k kVar, d0 d0Var) {
        this.f6223a = xVar;
        this.f6224b = kVar;
        this.f6225c = d0Var;
    }

    @Override // com.facebook.imagepipeline.producers.d0
    public void a(InterfaceC0369n interfaceC0369n, e0 e0Var) {
        g0 g0VarP = e0Var.P();
        T0.b bVarW = e0Var.W();
        Object objI = e0Var.i();
        T0.d dVarL = bVarW.l();
        if (dVarL == null || dVarL.b() == null) {
            this.f6225c.a(interfaceC0369n, e0Var);
            return;
        }
        g0VarP.g(e0Var, c());
        R.d dVarB = this.f6224b.b(bVarW, objI);
        AbstractC0311a abstractC0311a = e0Var.W().y(1) ? this.f6223a.get(dVarB) : null;
        if (abstractC0311a == null) {
            a aVar = new a(interfaceC0369n, dVarB, false, this.f6223a, e0Var.W().y(2));
            g0VarP.d(e0Var, c(), g0VarP.j(e0Var, c()) ? X.g.of("cached_value_found", "false") : null);
            this.f6225c.a(aVar, e0Var);
        } else {
            g0VarP.d(e0Var, c(), g0VarP.j(e0Var, c()) ? X.g.of("cached_value_found", "true") : null);
            g0VarP.e(e0Var, "PostprocessedBitmapMemoryCacheProducer", true);
            e0Var.n0("memory_bitmap", "postprocessed");
            interfaceC0369n.c(1.0f);
            interfaceC0369n.d(abstractC0311a, 1);
            abstractC0311a.close();
        }
    }

    protected String c() {
        return "PostprocessedBitmapMemoryCacheProducer";
    }
}
