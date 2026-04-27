package com.facebook.imagepipeline.producers;

import T0.b;
import b0.AbstractC0311a;

/* JADX INFO: renamed from: com.facebook.imagepipeline.producers.i, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0364i implements d0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final G0.x f6264a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final G0.k f6265b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final d0 f6266c;

    /* JADX INFO: renamed from: com.facebook.imagepipeline.producers.i$a */
    class a extends AbstractC0374t {

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ R.d f6267c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ boolean f6268d;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        a(InterfaceC0369n interfaceC0369n, R.d dVar, boolean z3) {
            super(interfaceC0369n);
            this.f6267c = dVar;
            this.f6268d = z3;
        }

        @Override // com.facebook.imagepipeline.producers.AbstractC0358c
        /* JADX INFO: renamed from: q, reason: merged with bridge method [inline-methods] */
        public void i(AbstractC0311a abstractC0311a, int i3) {
            AbstractC0311a abstractC0311a2;
            try {
                if (U0.b.d()) {
                    U0.b.a("BitmapMemoryCacheProducer#onNewResultImpl");
                }
                boolean zE = AbstractC0358c.e(i3);
                if (abstractC0311a == null) {
                    if (zE) {
                        p().d(null, i3);
                    }
                    if (U0.b.d()) {
                        U0.b.b();
                        return;
                    }
                    return;
                }
                if (!((N0.d) abstractC0311a.P()).m0() && !AbstractC0358c.n(i3, 8)) {
                    if (!zE && (abstractC0311a2 = C0364i.this.f6264a.get(this.f6267c)) != null) {
                        try {
                            N0.o oVarK = ((N0.d) abstractC0311a.P()).k();
                            N0.o oVarK2 = ((N0.d) abstractC0311a2.P()).k();
                            if (oVarK2.a() || oVarK2.c() >= oVarK.c()) {
                                p().d(abstractC0311a2, i3);
                                if (U0.b.d()) {
                                    U0.b.b();
                                    return;
                                }
                                return;
                            }
                        } finally {
                            AbstractC0311a.D(abstractC0311a2);
                        }
                    }
                    AbstractC0311a abstractC0311aB = this.f6268d ? C0364i.this.f6264a.b(this.f6267c, abstractC0311a) : null;
                    if (zE) {
                        try {
                            p().c(1.0f);
                        } catch (Throwable th) {
                            AbstractC0311a.D(abstractC0311aB);
                            throw th;
                        }
                    }
                    InterfaceC0369n interfaceC0369nP = p();
                    if (abstractC0311aB != null) {
                        abstractC0311a = abstractC0311aB;
                    }
                    interfaceC0369nP.d(abstractC0311a, i3);
                    AbstractC0311a.D(abstractC0311aB);
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
            } catch (Throwable th2) {
                if (U0.b.d()) {
                    U0.b.b();
                }
                throw th2;
            }
        }
    }

    public C0364i(G0.x xVar, G0.k kVar, d0 d0Var) {
        this.f6264a = xVar;
        this.f6265b = kVar;
        this.f6266c = d0Var;
    }

    private static void f(N0.k kVar, e0 e0Var) {
        e0Var.r(kVar.b());
    }

    @Override // com.facebook.imagepipeline.producers.d0
    public void a(InterfaceC0369n interfaceC0369n, e0 e0Var) {
        try {
            if (U0.b.d()) {
                U0.b.a("BitmapMemoryCacheProducer#produceResults");
            }
            g0 g0VarP = e0Var.P();
            g0VarP.g(e0Var, e());
            R.d dVarC = this.f6265b.c(e0Var.W(), e0Var.i());
            AbstractC0311a abstractC0311a = e0Var.W().y(1) ? this.f6264a.get(dVarC) : null;
            if (abstractC0311a != null) {
                f((N0.k) abstractC0311a.P(), e0Var);
                boolean zA = ((N0.d) abstractC0311a.P()).k().a();
                if (zA) {
                    g0VarP.d(e0Var, e(), g0VarP.j(e0Var, e()) ? X.g.of("cached_value_found", "true") : null);
                    g0VarP.e(e0Var, e(), true);
                    e0Var.n0("memory_bitmap", d());
                    interfaceC0369n.c(1.0f);
                }
                interfaceC0369n.d(abstractC0311a, AbstractC0358c.l(zA));
                abstractC0311a.close();
                if (zA) {
                    if (U0.b.d()) {
                        U0.b.b();
                        return;
                    }
                    return;
                }
            }
            if (e0Var.e0().b() >= b.c.BITMAP_MEMORY_CACHE.b()) {
                g0VarP.d(e0Var, e(), g0VarP.j(e0Var, e()) ? X.g.of("cached_value_found", "false") : null);
                g0VarP.e(e0Var, e(), false);
                e0Var.n0("memory_bitmap", d());
                interfaceC0369n.d(null, 1);
                if (U0.b.d()) {
                    U0.b.b();
                    return;
                }
                return;
            }
            InterfaceC0369n interfaceC0369nG = g(interfaceC0369n, dVarC, e0Var.W().y(2));
            g0VarP.d(e0Var, e(), g0VarP.j(e0Var, e()) ? X.g.of("cached_value_found", "false") : null);
            if (U0.b.d()) {
                U0.b.a("mInputProducer.produceResult");
            }
            this.f6266c.a(interfaceC0369nG, e0Var);
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

    protected String d() {
        return "pipe_bg";
    }

    protected String e() {
        return "BitmapMemoryCacheProducer";
    }

    protected InterfaceC0369n g(InterfaceC0369n interfaceC0369n, R.d dVar, boolean z3) {
        return new a(interfaceC0369n, dVar, z3);
    }
}
