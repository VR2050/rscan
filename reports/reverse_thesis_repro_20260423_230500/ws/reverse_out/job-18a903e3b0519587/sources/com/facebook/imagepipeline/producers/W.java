package com.facebook.imagepipeline.producers;

import a0.InterfaceC0215a;
import a0.InterfaceC0223i;
import android.os.SystemClock;
import b0.AbstractC0311a;
import com.facebook.imagepipeline.producers.X;
import java.io.InputStream;
import java.util.Map;

/* JADX INFO: loaded from: classes.dex */
public class W implements d0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    protected final InterfaceC0223i f6199a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final InterfaceC0215a f6200b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final X f6201c;

    class a implements X.a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ C f6202a;

        a(C c3) {
            this.f6202a = c3;
        }

        @Override // com.facebook.imagepipeline.producers.X.a
        public void a(Throwable th) {
            W.this.l(this.f6202a, th);
        }

        @Override // com.facebook.imagepipeline.producers.X.a
        public void b() {
            W.this.k(this.f6202a);
        }

        @Override // com.facebook.imagepipeline.producers.X.a
        public void c(InputStream inputStream, int i3) throws Throwable {
            if (U0.b.d()) {
                U0.b.a("NetworkFetcher->onResponse");
            }
            W.this.m(this.f6202a, inputStream, i3);
            if (U0.b.d()) {
                U0.b.b();
            }
        }
    }

    public W(InterfaceC0223i interfaceC0223i, InterfaceC0215a interfaceC0215a, X x3) {
        this.f6199a = interfaceC0223i;
        this.f6200b = interfaceC0215a;
        this.f6201c = x3;
    }

    protected static float e(int i3, int i4) {
        return i4 > 0 ? i3 / i4 : 1.0f - ((float) Math.exp(((double) (-i3)) / 50000.0d));
    }

    private Map f(C c3, int i3) {
        if (c3.d().j(c3.b(), "NetworkFetchProducer")) {
            return this.f6201c.e(c3, i3);
        }
        return null;
    }

    protected static void j(a0.k kVar, int i3, H0.b bVar, InterfaceC0369n interfaceC0369n, e0 e0Var) throws Throwable {
        N0.j jVar;
        AbstractC0311a abstractC0311aE0 = AbstractC0311a.e0(kVar.b());
        N0.j jVar2 = null;
        try {
            jVar = new N0.j(abstractC0311aE0);
        } catch (Throwable th) {
            th = th;
        }
        try {
            jVar.B0(bVar);
            jVar.x0();
            interfaceC0369n.d(jVar, i3);
            N0.j.p(jVar);
            AbstractC0311a.D(abstractC0311aE0);
        } catch (Throwable th2) {
            th = th2;
            jVar2 = jVar;
            N0.j.p(jVar2);
            AbstractC0311a.D(abstractC0311aE0);
            throw th;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void k(C c3) {
        c3.d().f(c3.b(), "NetworkFetchProducer", null);
        c3.a().b();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void l(C c3, Throwable th) {
        c3.d().i(c3.b(), "NetworkFetchProducer", th, null);
        c3.d().e(c3.b(), "NetworkFetchProducer", false);
        c3.b().D("network");
        c3.a().a(th);
    }

    private boolean n(C c3, e0 e0Var) {
        L0.e eVarE = e0Var.f0().e();
        if (eVarE != null && eVarE.c() && c3.b().d0()) {
            return this.f6201c.d(c3);
        }
        return false;
    }

    @Override // com.facebook.imagepipeline.producers.d0
    public void a(InterfaceC0369n interfaceC0369n, e0 e0Var) {
        e0Var.P().g(e0Var, "NetworkFetchProducer");
        C c3 = this.f6201c.c(interfaceC0369n, e0Var);
        this.f6201c.b(c3, new a(c3));
    }

    protected long g() {
        return SystemClock.uptimeMillis();
    }

    protected void h(a0.k kVar, C c3) throws Throwable {
        Map mapF = f(c3, kVar.size());
        g0 g0VarD = c3.d();
        g0VarD.d(c3.b(), "NetworkFetchProducer", mapF);
        g0VarD.e(c3.b(), "NetworkFetchProducer", true);
        c3.b().D("network");
        j(kVar, c3.e() | 1, c3.f(), c3.a(), c3.b());
    }

    protected void i(a0.k kVar, C c3) throws Throwable {
        if (n(c3, c3.b())) {
            long jG = g();
            if (jG - c3.c() >= 100) {
                c3.h(jG);
                c3.d().b(c3.b(), "NetworkFetchProducer", "intermediate_result");
                j(kVar, c3.e(), c3.f(), c3.a(), c3.b());
            }
        }
    }

    protected void m(C c3, InputStream inputStream, int i3) throws Throwable {
        a0.k kVarE = i3 > 0 ? this.f6199a.e(i3) : this.f6199a.b();
        byte[] bArr = (byte[]) this.f6200b.get(16384);
        while (true) {
            try {
                int i4 = inputStream.read(bArr);
                if (i4 < 0) {
                    this.f6201c.a(c3, kVarE.size());
                    h(kVarE, c3);
                    this.f6200b.a(bArr);
                    kVarE.close();
                    return;
                }
                if (i4 > 0) {
                    kVarE.write(bArr, 0, i4);
                    i(kVarE, c3);
                    c3.a().c(e(kVarE.size(), i3));
                }
            } catch (Throwable th) {
                this.f6200b.a(bArr);
                kVarE.close();
                throw th;
            }
        }
    }
}
