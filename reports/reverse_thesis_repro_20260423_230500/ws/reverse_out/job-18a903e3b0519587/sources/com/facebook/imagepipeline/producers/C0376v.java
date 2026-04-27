package com.facebook.imagepipeline.producers;

import I0.InterfaceC0178c;
import T0.b;
import com.facebook.imagepipeline.producers.C0375u;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicBoolean;

/* JADX INFO: renamed from: com.facebook.imagepipeline.producers.v, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0376v implements d0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final X.n f6380a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final G0.k f6381b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final d0 f6382c;

    /* JADX INFO: renamed from: com.facebook.imagepipeline.producers.v$a */
    class a implements N.d {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ g0 f6383a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ e0 f6384b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ InterfaceC0369n f6385c;

        a(g0 g0Var, e0 e0Var, InterfaceC0369n interfaceC0369n) {
            this.f6383a = g0Var;
            this.f6384b = e0Var;
            this.f6385c = interfaceC0369n;
        }

        @Override // N.d
        /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
        public Void a(N.f fVar) {
            if (C0376v.f(fVar)) {
                this.f6383a.f(this.f6384b, "DiskCacheProducer", null);
                this.f6385c.b();
            } else if (fVar.n()) {
                this.f6383a.i(this.f6384b, "DiskCacheProducer", fVar.i(), null);
                C0376v.this.f6382c.a(this.f6385c, this.f6384b);
            } else {
                N0.j jVar = (N0.j) fVar.j();
                if (jVar != null) {
                    g0 g0Var = this.f6383a;
                    e0 e0Var = this.f6384b;
                    g0Var.d(e0Var, "DiskCacheProducer", C0376v.e(g0Var, e0Var, true, jVar.d0()));
                    this.f6383a.e(this.f6384b, "DiskCacheProducer", true);
                    this.f6384b.D("disk");
                    this.f6385c.c(1.0f);
                    this.f6385c.d(jVar, 1);
                    jVar.close();
                } else {
                    g0 g0Var2 = this.f6383a;
                    e0 e0Var2 = this.f6384b;
                    g0Var2.d(e0Var2, "DiskCacheProducer", C0376v.e(g0Var2, e0Var2, false, 0));
                    C0376v.this.f6382c.a(this.f6385c, this.f6384b);
                }
            }
            return null;
        }
    }

    /* JADX INFO: renamed from: com.facebook.imagepipeline.producers.v$b */
    class b extends AbstractC0361f {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ AtomicBoolean f6387a;

        b(AtomicBoolean atomicBoolean) {
            this.f6387a = atomicBoolean;
        }

        @Override // com.facebook.imagepipeline.producers.f0
        public void a() {
            this.f6387a.set(true);
        }
    }

    public C0376v(X.n nVar, G0.k kVar, d0 d0Var) {
        this.f6380a = nVar;
        this.f6381b = kVar;
        this.f6382c = d0Var;
    }

    static Map e(g0 g0Var, e0 e0Var, boolean z3, int i3) {
        if (g0Var.j(e0Var, "DiskCacheProducer")) {
            return z3 ? X.g.of("cached_value_found", String.valueOf(z3), "encodedImageSize", String.valueOf(i3)) : X.g.of("cached_value_found", String.valueOf(z3));
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static boolean f(N.f fVar) {
        return fVar.l() || (fVar.n() && (fVar.i() instanceof CancellationException));
    }

    private void g(InterfaceC0369n interfaceC0369n, e0 e0Var) {
        if (e0Var.e0().b() < b.c.DISK_CACHE.b()) {
            this.f6382c.a(interfaceC0369n, e0Var);
        } else {
            e0Var.n0("disk", "nil-result_read");
            interfaceC0369n.d(null, 1);
        }
    }

    private N.d h(InterfaceC0369n interfaceC0369n, e0 e0Var) {
        return new a(e0Var.P(), e0Var, interfaceC0369n);
    }

    private void i(AtomicBoolean atomicBoolean, e0 e0Var) {
        e0Var.Z(new b(atomicBoolean));
    }

    @Override // com.facebook.imagepipeline.producers.d0
    public void a(InterfaceC0369n interfaceC0369n, e0 e0Var) {
        T0.b bVarW = e0Var.W();
        if (!e0Var.W().y(16)) {
            g(interfaceC0369n, e0Var);
            return;
        }
        e0Var.P().g(e0Var, "DiskCacheProducer");
        R.d dVarA = this.f6381b.a(bVarW, e0Var.i());
        InterfaceC0178c interfaceC0178c = (InterfaceC0178c) this.f6380a.get();
        G0.j jVarA = C0375u.a(bVarW, interfaceC0178c.c(), interfaceC0178c.a(), interfaceC0178c.b());
        if (jVarA != null) {
            AtomicBoolean atomicBoolean = new AtomicBoolean(false);
            jVarA.m(dVarA, atomicBoolean).e(h(interfaceC0369n, e0Var));
            i(atomicBoolean, e0Var);
        } else {
            e0Var.P().i(e0Var, "DiskCacheProducer", new C0375u.a("Got no disk cache for CacheChoice: " + Integer.valueOf(bVarW.c().ordinal()).toString()), null);
            g(interfaceC0369n, e0Var);
        }
    }
}
