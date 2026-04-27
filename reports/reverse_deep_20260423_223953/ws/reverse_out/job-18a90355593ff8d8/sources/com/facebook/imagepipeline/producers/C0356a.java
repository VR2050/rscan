package com.facebook.imagepipeline.producers;

/* JADX INFO: renamed from: com.facebook.imagepipeline.producers.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0356a implements d0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final d0 f6222a;

    /* JADX INFO: renamed from: com.facebook.imagepipeline.producers.a$a, reason: collision with other inner class name */
    private static class C0097a extends AbstractC0374t {
        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.facebook.imagepipeline.producers.AbstractC0358c
        /* JADX INFO: renamed from: q, reason: merged with bridge method [inline-methods] */
        public void i(N0.j jVar, int i3) {
            if (jVar == null) {
                p().d(null, i3);
                return;
            }
            if (!N0.j.u0(jVar)) {
                jVar.x0();
            }
            p().d(jVar, i3);
        }

        private C0097a(InterfaceC0369n interfaceC0369n) {
            super(interfaceC0369n);
        }
    }

    public C0356a(d0 d0Var) {
        this.f6222a = d0Var;
    }

    @Override // com.facebook.imagepipeline.producers.d0
    public void a(InterfaceC0369n interfaceC0369n, e0 e0Var) {
        this.f6222a.a(new C0097a(interfaceC0369n), e0Var);
    }
}
