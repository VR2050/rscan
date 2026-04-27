package com.facebook.imagepipeline.producers;

import b0.AbstractC0311a;

/* JADX INFO: loaded from: classes.dex */
public final class j0 implements d0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final d0 f6278a;

    private final class a extends AbstractC0374t {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ j0 f6279c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public a(j0 j0Var, InterfaceC0369n interfaceC0369n) {
            super(interfaceC0369n);
            t2.j.f(interfaceC0369n, "consumer");
            this.f6279c = j0Var;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.facebook.imagepipeline.producers.AbstractC0358c
        /* JADX INFO: renamed from: q, reason: merged with bridge method [inline-methods] */
        public void i(N0.j jVar, int i3) {
            AbstractC0311a abstractC0311aV = null;
            try {
                if (N0.j.w0(jVar) && jVar != null) {
                    abstractC0311aV = jVar.v();
                }
                p().d(abstractC0311aV, i3);
                AbstractC0311a.D(abstractC0311aV);
            } catch (Throwable th) {
                AbstractC0311a.D(abstractC0311aV);
                throw th;
            }
        }
    }

    public j0(d0 d0Var) {
        t2.j.f(d0Var, "inputProducer");
        this.f6278a = d0Var;
    }

    @Override // com.facebook.imagepipeline.producers.d0
    public void a(InterfaceC0369n interfaceC0369n, e0 e0Var) {
        t2.j.f(interfaceC0369n, "consumer");
        t2.j.f(e0Var, "context");
        this.f6278a.a(new a(this, interfaceC0369n), e0Var);
    }
}
