package com.facebook.imagepipeline.producers;

import G0.C0175d;
import I0.InterfaceC0178c;
import T0.b;
import b0.AbstractC0311a;

/* JADX INFO: renamed from: com.facebook.imagepipeline.producers.k, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0366k implements d0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final G0.x f6280a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final X.n f6281b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final G0.k f6282c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final d0 f6283d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final C0175d f6284e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final C0175d f6285f;

    /* JADX INFO: renamed from: com.facebook.imagepipeline.producers.k$a */
    private static class a extends AbstractC0374t {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final e0 f6286c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final G0.x f6287d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private final X.n f6288e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private final G0.k f6289f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        private final C0175d f6290g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        private final C0175d f6291h;

        public a(InterfaceC0369n interfaceC0369n, e0 e0Var, G0.x xVar, X.n nVar, G0.k kVar, C0175d c0175d, C0175d c0175d2) {
            super(interfaceC0369n);
            this.f6286c = e0Var;
            this.f6287d = xVar;
            this.f6288e = nVar;
            this.f6289f = kVar;
            this.f6290g = c0175d;
            this.f6291h = c0175d2;
        }

        @Override // com.facebook.imagepipeline.producers.AbstractC0358c
        /* JADX INFO: renamed from: q, reason: merged with bridge method [inline-methods] */
        public void i(AbstractC0311a abstractC0311a, int i3) {
            try {
                if (U0.b.d()) {
                    U0.b.a("BitmapProbeProducer#onNewResultImpl");
                }
                if (!AbstractC0358c.f(i3) && abstractC0311a != null && !AbstractC0358c.m(i3, 8)) {
                    T0.b bVarW = this.f6286c.W();
                    R.d dVarA = this.f6289f.a(bVarW, this.f6286c.i());
                    String str = (String) this.f6286c.x("origin");
                    if (str != null && str.equals("memory_bitmap")) {
                        if (this.f6286c.f0().G().D() && !this.f6290g.b(dVarA)) {
                            this.f6287d.c(dVarA);
                            this.f6290g.a(dVarA);
                        }
                        if (this.f6286c.f0().G().B() && !this.f6291h.b(dVarA)) {
                            boolean z3 = bVarW.c() == b.EnumC0041b.SMALL;
                            InterfaceC0178c interfaceC0178c = (InterfaceC0178c) this.f6288e.get();
                            (z3 ? interfaceC0178c.c() : interfaceC0178c.a()).f(dVarA);
                            this.f6291h.a(dVarA);
                        }
                    }
                    p().d(abstractC0311a, i3);
                    if (U0.b.d()) {
                        U0.b.b();
                        return;
                    }
                    return;
                }
                p().d(abstractC0311a, i3);
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

    public C0366k(G0.x xVar, X.n nVar, G0.k kVar, C0175d c0175d, C0175d c0175d2, d0 d0Var) {
        this.f6280a = xVar;
        this.f6281b = nVar;
        this.f6282c = kVar;
        this.f6284e = c0175d;
        this.f6285f = c0175d2;
        this.f6283d = d0Var;
    }

    @Override // com.facebook.imagepipeline.producers.d0
    public void a(InterfaceC0369n interfaceC0369n, e0 e0Var) {
        try {
            if (U0.b.d()) {
                U0.b.a("BitmapProbeProducer#produceResults");
            }
            g0 g0VarP = e0Var.P();
            g0VarP.g(e0Var, c());
            a aVar = new a(interfaceC0369n, e0Var, this.f6280a, this.f6281b, this.f6282c, this.f6284e, this.f6285f);
            g0VarP.d(e0Var, "BitmapProbeProducer", null);
            if (U0.b.d()) {
                U0.b.a("mInputProducer.produceResult");
            }
            this.f6283d.a(aVar, e0Var);
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
        return "BitmapProbeProducer";
    }
}
