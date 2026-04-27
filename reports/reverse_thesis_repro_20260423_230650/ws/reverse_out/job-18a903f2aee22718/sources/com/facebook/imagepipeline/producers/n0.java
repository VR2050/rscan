package com.facebook.imagepipeline.producers;

/* JADX INFO: loaded from: classes.dex */
public class n0 implements d0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final d0 f6316a;

    class a extends AbstractC0374t {
        a(InterfaceC0369n interfaceC0369n) {
            super(interfaceC0369n);
        }

        @Override // com.facebook.imagepipeline.producers.AbstractC0358c
        protected void i(Object obj, int i3) {
            if (AbstractC0358c.e(i3)) {
                p().d(null, i3);
            }
        }
    }

    public n0(d0 d0Var) {
        this.f6316a = d0Var;
    }

    @Override // com.facebook.imagepipeline.producers.d0
    public void a(InterfaceC0369n interfaceC0369n, e0 e0Var) {
        this.f6316a.a(new a(interfaceC0369n), e0Var);
    }
}
