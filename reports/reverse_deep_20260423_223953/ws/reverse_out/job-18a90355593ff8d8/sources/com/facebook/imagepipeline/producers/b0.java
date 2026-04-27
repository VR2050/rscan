package com.facebook.imagepipeline.producers;

import b0.AbstractC0311a;
import java.util.Map;
import java.util.concurrent.Executor;

/* JADX INFO: loaded from: classes.dex */
public class b0 implements d0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final d0 f6230a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final F0.b f6231b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final Executor f6232c;

    private class a extends AbstractC0374t {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final g0 f6233c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final e0 f6234d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private final T0.d f6235e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private boolean f6236f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        private AbstractC0311a f6237g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        private int f6238h;

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        private boolean f6239i;

        /* JADX INFO: renamed from: j, reason: collision with root package name */
        private boolean f6240j;

        /* JADX INFO: renamed from: com.facebook.imagepipeline.producers.b0$a$a, reason: collision with other inner class name */
        class C0098a extends AbstractC0361f {

            /* JADX INFO: renamed from: a, reason: collision with root package name */
            final /* synthetic */ b0 f6242a;

            C0098a(b0 b0Var) {
                this.f6242a = b0Var;
            }

            @Override // com.facebook.imagepipeline.producers.f0
            public void a() {
                a.this.C();
            }
        }

        class b implements Runnable {
            b() {
            }

            @Override // java.lang.Runnable
            public void run() {
                AbstractC0311a abstractC0311a;
                int i3;
                synchronized (a.this) {
                    abstractC0311a = a.this.f6237g;
                    i3 = a.this.f6238h;
                    a.this.f6237g = null;
                    a.this.f6239i = false;
                }
                if (AbstractC0311a.d0(abstractC0311a)) {
                    try {
                        a.this.z(abstractC0311a, i3);
                    } finally {
                        AbstractC0311a.D(abstractC0311a);
                    }
                }
                a.this.x();
            }
        }

        public a(InterfaceC0369n interfaceC0369n, g0 g0Var, T0.d dVar, e0 e0Var) {
            super(interfaceC0369n);
            this.f6237g = null;
            this.f6238h = 0;
            this.f6239i = false;
            this.f6240j = false;
            this.f6233c = g0Var;
            this.f6235e = dVar;
            this.f6234d = e0Var;
            e0Var.Z(new C0098a(b0.this));
        }

        private Map A(g0 g0Var, e0 e0Var, T0.d dVar) {
            if (g0Var.j(e0Var, "PostprocessorProducer")) {
                return X.g.of("Postprocessor", dVar.getName());
            }
            return null;
        }

        private synchronized boolean B() {
            return this.f6236f;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void C() {
            if (y()) {
                p().b();
            }
        }

        private void D(Throwable th) {
            if (y()) {
                p().a(th);
            }
        }

        private void E(AbstractC0311a abstractC0311a, int i3) {
            boolean zE = AbstractC0358c.e(i3);
            if ((zE || B()) && !(zE && y())) {
                return;
            }
            p().d(abstractC0311a, i3);
        }

        private AbstractC0311a G(N0.d dVar) {
            N0.e eVar = (N0.e) dVar;
            AbstractC0311a abstractC0311aA = this.f6235e.a(eVar.C(), b0.this.f6231b);
            try {
                N0.e eVarA0 = N0.e.a0(abstractC0311aA, dVar.k(), eVar.N(), eVar.s0());
                eVarA0.r(eVar.b());
                return AbstractC0311a.e0(eVarA0);
            } finally {
                AbstractC0311a.D(abstractC0311aA);
            }
        }

        private synchronized boolean H() {
            if (this.f6236f || !this.f6239i || this.f6240j || !AbstractC0311a.d0(this.f6237g)) {
                return false;
            }
            this.f6240j = true;
            return true;
        }

        private boolean I(N0.d dVar) {
            return dVar instanceof N0.e;
        }

        private void J() {
            b0.this.f6232c.execute(new b());
        }

        private void K(AbstractC0311a abstractC0311a, int i3) {
            synchronized (this) {
                try {
                    if (this.f6236f) {
                        return;
                    }
                    AbstractC0311a abstractC0311a2 = this.f6237g;
                    this.f6237g = AbstractC0311a.A(abstractC0311a);
                    this.f6238h = i3;
                    this.f6239i = true;
                    boolean zH = H();
                    AbstractC0311a.D(abstractC0311a2);
                    if (zH) {
                        J();
                    }
                } catch (Throwable th) {
                    throw th;
                }
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void x() {
            boolean zH;
            synchronized (this) {
                this.f6240j = false;
                zH = H();
            }
            if (zH) {
                J();
            }
        }

        private boolean y() {
            synchronized (this) {
                try {
                    if (this.f6236f) {
                        return false;
                    }
                    AbstractC0311a abstractC0311a = this.f6237g;
                    this.f6237g = null;
                    this.f6236f = true;
                    AbstractC0311a.D(abstractC0311a);
                    return true;
                } catch (Throwable th) {
                    throw th;
                }
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void z(AbstractC0311a abstractC0311a, int i3) {
            X.k.b(Boolean.valueOf(AbstractC0311a.d0(abstractC0311a)));
            if (!I((N0.d) abstractC0311a.P())) {
                E(abstractC0311a, i3);
                return;
            }
            this.f6233c.g(this.f6234d, "PostprocessorProducer");
            try {
                try {
                    AbstractC0311a abstractC0311aG = G((N0.d) abstractC0311a.P());
                    g0 g0Var = this.f6233c;
                    e0 e0Var = this.f6234d;
                    g0Var.d(e0Var, "PostprocessorProducer", A(g0Var, e0Var, this.f6235e));
                    E(abstractC0311aG, i3);
                    AbstractC0311a.D(abstractC0311aG);
                } catch (Exception e3) {
                    g0 g0Var2 = this.f6233c;
                    e0 e0Var2 = this.f6234d;
                    g0Var2.i(e0Var2, "PostprocessorProducer", e3, A(g0Var2, e0Var2, this.f6235e));
                    D(e3);
                    AbstractC0311a.D(null);
                }
            } catch (Throwable th) {
                AbstractC0311a.D(null);
                throw th;
            }
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.facebook.imagepipeline.producers.AbstractC0358c
        /* JADX INFO: renamed from: F, reason: merged with bridge method [inline-methods] */
        public void i(AbstractC0311a abstractC0311a, int i3) {
            if (AbstractC0311a.d0(abstractC0311a)) {
                K(abstractC0311a, i3);
            } else if (AbstractC0358c.e(i3)) {
                E(null, i3);
            }
        }

        @Override // com.facebook.imagepipeline.producers.AbstractC0374t, com.facebook.imagepipeline.producers.AbstractC0358c
        protected void g() {
            C();
        }

        @Override // com.facebook.imagepipeline.producers.AbstractC0374t, com.facebook.imagepipeline.producers.AbstractC0358c
        protected void h(Throwable th) {
            D(th);
        }
    }

    class b extends AbstractC0374t {
        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.facebook.imagepipeline.producers.AbstractC0358c
        /* JADX INFO: renamed from: q, reason: merged with bridge method [inline-methods] */
        public void i(AbstractC0311a abstractC0311a, int i3) {
            if (AbstractC0358c.f(i3)) {
                return;
            }
            p().d(abstractC0311a, i3);
        }

        private b(a aVar) {
            super(aVar);
        }
    }

    public b0(d0 d0Var, F0.b bVar, Executor executor) {
        this.f6230a = (d0) X.k.g(d0Var);
        this.f6231b = bVar;
        this.f6232c = (Executor) X.k.g(executor);
    }

    @Override // com.facebook.imagepipeline.producers.d0
    public void a(InterfaceC0369n interfaceC0369n, e0 e0Var) {
        g0 g0VarP = e0Var.P();
        T0.d dVarL = e0Var.W().l();
        X.k.g(dVarL);
        this.f6230a.a(new b(new a(interfaceC0369n, g0VarP, dVarL, e0Var)), e0Var);
    }
}
