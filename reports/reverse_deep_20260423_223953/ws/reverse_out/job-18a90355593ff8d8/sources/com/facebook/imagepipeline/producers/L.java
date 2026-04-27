package com.facebook.imagepipeline.producers;

import a0.InterfaceC0223i;
import b0.AbstractC0311a;
import java.io.InputStream;
import java.util.concurrent.Executor;

/* JADX INFO: loaded from: classes.dex */
public abstract class L implements d0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Executor f6147a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final InterfaceC0223i f6148b;

    class a extends m0 {

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        final /* synthetic */ T0.b f6149g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        final /* synthetic */ g0 f6150h;

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        final /* synthetic */ e0 f6151i;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        a(InterfaceC0369n interfaceC0369n, g0 g0Var, e0 e0Var, String str, T0.b bVar, g0 g0Var2, e0 e0Var2) {
            super(interfaceC0369n, g0Var, e0Var, str);
            this.f6149g = bVar;
            this.f6150h = g0Var2;
            this.f6151i = e0Var2;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // V.e
        /* JADX INFO: renamed from: j, reason: merged with bridge method [inline-methods] */
        public void b(N0.j jVar) {
            N0.j.p(jVar);
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // V.e
        /* JADX INFO: renamed from: k, reason: merged with bridge method [inline-methods] */
        public N0.j c() {
            N0.j jVarD = L.this.d(this.f6149g);
            if (jVarD == null) {
                this.f6150h.e(this.f6151i, L.this.f(), false);
                this.f6151i.n0("local", "fetch");
                return null;
            }
            jVarD.x0();
            this.f6150h.e(this.f6151i, L.this.f(), true);
            this.f6151i.n0("local", "fetch");
            this.f6151i.A("image_color_space", jVarD.y());
            return jVarD;
        }
    }

    class b extends AbstractC0361f {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ m0 f6153a;

        b(m0 m0Var) {
            this.f6153a = m0Var;
        }

        @Override // com.facebook.imagepipeline.producers.f0
        public void a() {
            this.f6153a.a();
        }
    }

    protected L(Executor executor, InterfaceC0223i interfaceC0223i) {
        this.f6147a = executor;
        this.f6148b = interfaceC0223i;
    }

    @Override // com.facebook.imagepipeline.producers.d0
    public void a(InterfaceC0369n interfaceC0369n, e0 e0Var) {
        g0 g0VarP = e0Var.P();
        T0.b bVarW = e0Var.W();
        e0Var.n0("local", "fetch");
        a aVar = new a(interfaceC0369n, g0VarP, e0Var, f(), bVarW, g0VarP, e0Var);
        e0Var.Z(new b(aVar));
        this.f6147a.execute(aVar);
    }

    protected N0.j c(InputStream inputStream, int i3) {
        AbstractC0311a abstractC0311aE0 = null;
        try {
            abstractC0311aE0 = i3 <= 0 ? AbstractC0311a.e0(this.f6148b.d(inputStream)) : AbstractC0311a.e0(this.f6148b.a(inputStream, i3));
            N0.j jVar = new N0.j(abstractC0311aE0);
            X.b.b(inputStream);
            AbstractC0311a.D(abstractC0311aE0);
            return jVar;
        } catch (Throwable th) {
            X.b.b(inputStream);
            AbstractC0311a.D(abstractC0311aE0);
            throw th;
        }
    }

    protected abstract N0.j d(T0.b bVar);

    protected N0.j e(InputStream inputStream, int i3) {
        return c(inputStream, i3);
    }

    protected abstract String f();
}
