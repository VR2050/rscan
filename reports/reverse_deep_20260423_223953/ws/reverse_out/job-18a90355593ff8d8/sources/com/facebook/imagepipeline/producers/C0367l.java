package com.facebook.imagepipeline.producers;

/* JADX INFO: renamed from: com.facebook.imagepipeline.producers.l, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0367l implements d0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final d0 f6308a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final d0 f6309b;

    /* JADX INFO: renamed from: com.facebook.imagepipeline.producers.l$a */
    private class a extends AbstractC0374t {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private e0 f6310c;

        @Override // com.facebook.imagepipeline.producers.AbstractC0374t, com.facebook.imagepipeline.producers.AbstractC0358c
        protected void h(Throwable th) {
            C0367l.this.f6309b.a(p(), this.f6310c);
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.facebook.imagepipeline.producers.AbstractC0358c
        /* JADX INFO: renamed from: q, reason: merged with bridge method [inline-methods] */
        public void i(N0.j jVar, int i3) {
            T0.b bVarW = this.f6310c.W();
            boolean zE = AbstractC0358c.e(i3);
            boolean zC = v0.c(jVar, bVarW.r());
            if (jVar != null && (zC || bVarW.j())) {
                if (zE && zC) {
                    p().d(jVar, i3);
                } else {
                    p().d(jVar, AbstractC0358c.o(i3, 1));
                }
            }
            if (!zE || zC || bVarW.i()) {
                return;
            }
            N0.j.p(jVar);
            C0367l.this.f6309b.a(p(), this.f6310c);
        }

        private a(InterfaceC0369n interfaceC0369n, e0 e0Var) {
            super(interfaceC0369n);
            this.f6310c = e0Var;
        }
    }

    public C0367l(d0 d0Var, d0 d0Var2) {
        this.f6308a = d0Var;
        this.f6309b = d0Var2;
    }

    @Override // com.facebook.imagepipeline.producers.d0
    public void a(InterfaceC0369n interfaceC0369n, e0 e0Var) {
        this.f6308a.a(new a(interfaceC0369n, e0Var), e0Var);
    }
}
