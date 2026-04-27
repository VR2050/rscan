package com.facebook.imagepipeline.producers;

import G0.C0175d;
import I0.InterfaceC0178c;
import T0.b;

/* JADX INFO: loaded from: classes.dex */
public class A implements d0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final X.n f6083a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final G0.k f6084b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final d0 f6085c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final C0175d f6086d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final C0175d f6087e;

    private static class a extends AbstractC0374t {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final e0 f6088c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final X.n f6089d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private final G0.k f6090e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private final C0175d f6091f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        private final C0175d f6092g;

        public a(InterfaceC0369n interfaceC0369n, e0 e0Var, X.n nVar, G0.k kVar, C0175d c0175d, C0175d c0175d2) {
            super(interfaceC0369n);
            this.f6088c = e0Var;
            this.f6089d = nVar;
            this.f6090e = kVar;
            this.f6091f = c0175d;
            this.f6092g = c0175d2;
        }

        @Override // com.facebook.imagepipeline.producers.AbstractC0358c
        /* JADX INFO: renamed from: q, reason: merged with bridge method [inline-methods] */
        public void i(N0.j jVar, int i3) {
            try {
                if (U0.b.d()) {
                    U0.b.a("EncodedProbeProducer#onNewResultImpl");
                }
                if (!AbstractC0358c.f(i3) && jVar != null && !AbstractC0358c.m(i3, 10) && jVar.D() != C0.c.f565d) {
                    T0.b bVarW = this.f6088c.W();
                    R.d dVarA = this.f6090e.a(bVarW, this.f6088c.i());
                    this.f6091f.a(dVarA);
                    if ("memory_encoded".equals(this.f6088c.x("origin"))) {
                        if (!this.f6092g.b(dVarA)) {
                            boolean z3 = bVarW.c() == b.EnumC0041b.SMALL;
                            InterfaceC0178c interfaceC0178c = (InterfaceC0178c) this.f6089d.get();
                            (z3 ? interfaceC0178c.c() : interfaceC0178c.a()).f(dVarA);
                            this.f6092g.a(dVarA);
                        }
                    } else if ("disk".equals(this.f6088c.x("origin"))) {
                        this.f6092g.a(dVarA);
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

    public A(X.n nVar, G0.k kVar, C0175d c0175d, C0175d c0175d2, d0 d0Var) {
        this.f6083a = nVar;
        this.f6084b = kVar;
        this.f6086d = c0175d;
        this.f6087e = c0175d2;
        this.f6085c = d0Var;
    }

    @Override // com.facebook.imagepipeline.producers.d0
    public void a(InterfaceC0369n interfaceC0369n, e0 e0Var) {
        try {
            if (U0.b.d()) {
                U0.b.a("EncodedProbeProducer#produceResults");
            }
            g0 g0VarP = e0Var.P();
            g0VarP.g(e0Var, c());
            a aVar = new a(interfaceC0369n, e0Var, this.f6083a, this.f6084b, this.f6086d, this.f6087e);
            g0VarP.d(e0Var, "EncodedProbeProducer", null);
            if (U0.b.d()) {
                U0.b.a("mInputProducer.produceResult");
            }
            this.f6085c.a(aVar, e0Var);
            if (U0.b.d()) {
                U0.b.b();
            }
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

    protected String c() {
        return "EncodedProbeProducer";
    }
}
