package com.facebook.imagepipeline.producers;

import I0.InterfaceC0178c;
import T0.b;
import com.facebook.imagepipeline.producers.C0375u;

/* JADX INFO: renamed from: com.facebook.imagepipeline.producers.w, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0377w implements d0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final X.n f6390a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final G0.k f6391b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final d0 f6392c;

    /* JADX INFO: renamed from: com.facebook.imagepipeline.producers.w$a */
    private static class a extends AbstractC0374t {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final e0 f6393c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final X.n f6394d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private final G0.k f6395e;

        @Override // com.facebook.imagepipeline.producers.AbstractC0358c
        /* JADX INFO: renamed from: q, reason: merged with bridge method [inline-methods] */
        public void i(N0.j jVar, int i3) {
            this.f6393c.P().g(this.f6393c, "DiskCacheWriteProducer");
            if (AbstractC0358c.f(i3) || jVar == null || AbstractC0358c.m(i3, 10) || jVar.D() == C0.c.f565d) {
                this.f6393c.P().d(this.f6393c, "DiskCacheWriteProducer", null);
                p().d(jVar, i3);
                return;
            }
            T0.b bVarW = this.f6393c.W();
            R.d dVarA = this.f6395e.a(bVarW, this.f6393c.i());
            InterfaceC0178c interfaceC0178c = (InterfaceC0178c) this.f6394d.get();
            G0.j jVarA = C0375u.a(bVarW, interfaceC0178c.c(), interfaceC0178c.a(), interfaceC0178c.b());
            if (jVarA != null) {
                jVarA.p(dVarA, jVar);
                this.f6393c.P().d(this.f6393c, "DiskCacheWriteProducer", null);
                p().d(jVar, i3);
                return;
            }
            this.f6393c.P().i(this.f6393c, "DiskCacheWriteProducer", new C0375u.a("Got no disk cache for CacheChoice: " + Integer.valueOf(bVarW.c().ordinal()).toString()), null);
            p().d(jVar, i3);
        }

        private a(InterfaceC0369n interfaceC0369n, e0 e0Var, X.n nVar, G0.k kVar) {
            super(interfaceC0369n);
            this.f6393c = e0Var;
            this.f6394d = nVar;
            this.f6395e = kVar;
        }
    }

    public C0377w(X.n nVar, G0.k kVar, d0 d0Var) {
        this.f6390a = nVar;
        this.f6391b = kVar;
        this.f6392c = d0Var;
    }

    private void c(InterfaceC0369n interfaceC0369n, e0 e0Var) {
        if (e0Var.e0().b() >= b.c.DISK_CACHE.b()) {
            e0Var.n0("disk", "nil-result_write");
            interfaceC0369n.d(null, 1);
        } else {
            if (e0Var.W().y(32)) {
                interfaceC0369n = new a(interfaceC0369n, e0Var, this.f6390a, this.f6391b);
            }
            this.f6392c.a(interfaceC0369n, e0Var);
        }
    }

    @Override // com.facebook.imagepipeline.producers.d0
    public void a(InterfaceC0369n interfaceC0369n, e0 e0Var) {
        c(interfaceC0369n, e0Var);
    }
}
