package com.facebook.imagepipeline.producers;

/* JADX INFO: loaded from: classes.dex */
public class t0 implements d0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final u0[] f6374a;

    private class a extends AbstractC0374t {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final e0 f6375c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final int f6376d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private final H0.g f6377e;

        public a(InterfaceC0369n interfaceC0369n, e0 e0Var, int i3) {
            super(interfaceC0369n);
            this.f6375c = e0Var;
            this.f6376d = i3;
            this.f6377e = e0Var.W().r();
        }

        @Override // com.facebook.imagepipeline.producers.AbstractC0374t, com.facebook.imagepipeline.producers.AbstractC0358c
        protected void h(Throwable th) {
            if (t0.this.e(this.f6376d + 1, p(), this.f6375c)) {
                return;
            }
            p().a(th);
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.facebook.imagepipeline.producers.AbstractC0358c
        /* JADX INFO: renamed from: q, reason: merged with bridge method [inline-methods] */
        public void i(N0.j jVar, int i3) {
            if (jVar != null && (AbstractC0358c.f(i3) || v0.c(jVar, this.f6377e))) {
                p().d(jVar, i3);
            } else if (AbstractC0358c.e(i3)) {
                N0.j.p(jVar);
                if (t0.this.e(this.f6376d + 1, p(), this.f6375c)) {
                    return;
                }
                p().d(null, 1);
            }
        }
    }

    public t0(u0... u0VarArr) {
        u0[] u0VarArr2 = (u0[]) X.k.g(u0VarArr);
        this.f6374a = u0VarArr2;
        X.k.e(0, u0VarArr2.length);
    }

    private int d(int i3, H0.g gVar) {
        while (true) {
            u0[] u0VarArr = this.f6374a;
            if (i3 >= u0VarArr.length) {
                return -1;
            }
            if (u0VarArr[i3].b(gVar)) {
                return i3;
            }
            i3++;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean e(int i3, InterfaceC0369n interfaceC0369n, e0 e0Var) {
        int iD = d(i3, e0Var.W().r());
        if (iD == -1) {
            return false;
        }
        this.f6374a[iD].a(new a(interfaceC0369n, e0Var, iD), e0Var);
        return true;
    }

    @Override // com.facebook.imagepipeline.producers.d0
    public void a(InterfaceC0369n interfaceC0369n, e0 e0Var) {
        if (e0Var.W().r() == null) {
            interfaceC0369n.d(null, 1);
        } else {
            if (e(0, interfaceC0369n, e0Var)) {
                return;
            }
            interfaceC0369n.d(null, 1);
        }
    }
}
