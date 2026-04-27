package com.facebook.imagepipeline.producers;

import android.os.Looper;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class o0 implements d0 {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final a f6318c = new a(null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final d0 f6319a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final p0 f6320b;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final String c(e0 e0Var) {
            if (!O0.a.b()) {
                return null;
            }
            return "ThreadHandoffProducer_produceResults_" + e0Var.getId();
        }

        /* JADX INFO: Access modifiers changed from: private */
        public final boolean d(e0 e0Var) {
            return e0Var.f0().G().k() && Looper.getMainLooper().getThread() != Thread.currentThread();
        }

        private a() {
        }
    }

    public static final class b extends AbstractC0361f {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ m0 f6321a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ o0 f6322b;

        b(m0 m0Var, o0 o0Var) {
            this.f6321a = m0Var;
            this.f6322b = o0Var;
        }

        @Override // com.facebook.imagepipeline.producers.f0
        public void a() {
            this.f6321a.a();
            this.f6322b.d().b(this.f6321a);
        }
    }

    public static final class c extends m0 {

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        final /* synthetic */ InterfaceC0369n f6323g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        final /* synthetic */ g0 f6324h;

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        final /* synthetic */ e0 f6325i;

        /* JADX INFO: renamed from: j, reason: collision with root package name */
        final /* synthetic */ o0 f6326j;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        c(InterfaceC0369n interfaceC0369n, g0 g0Var, e0 e0Var, o0 o0Var) {
            super(interfaceC0369n, g0Var, e0Var, "BackgroundThreadHandoffProducer");
            this.f6323g = interfaceC0369n;
            this.f6324h = g0Var;
            this.f6325i = e0Var;
            this.f6326j = o0Var;
        }

        @Override // V.e
        protected void b(Object obj) {
        }

        @Override // V.e
        protected Object c() {
            return null;
        }

        @Override // com.facebook.imagepipeline.producers.m0, V.e
        protected void f(Object obj) {
            this.f6324h.d(this.f6325i, "BackgroundThreadHandoffProducer", null);
            this.f6326j.c().a(this.f6323g, this.f6325i);
        }
    }

    public o0(d0 d0Var, p0 p0Var) {
        t2.j.f(d0Var, "inputProducer");
        t2.j.f(p0Var, "threadHandoffProducerQueue");
        this.f6319a = d0Var;
        this.f6320b = p0Var;
    }

    @Override // com.facebook.imagepipeline.producers.d0
    public void a(InterfaceC0369n interfaceC0369n, e0 e0Var) {
        t2.j.f(interfaceC0369n, "consumer");
        t2.j.f(e0Var, "context");
        if (!U0.b.d()) {
            g0 g0VarP = e0Var.P();
            a aVar = f6318c;
            if (aVar.d(e0Var)) {
                g0VarP.g(e0Var, "BackgroundThreadHandoffProducer");
                g0VarP.d(e0Var, "BackgroundThreadHandoffProducer", null);
                this.f6319a.a(interfaceC0369n, e0Var);
                return;
            } else {
                c cVar = new c(interfaceC0369n, g0VarP, e0Var, this);
                e0Var.Z(new b(cVar, this));
                this.f6320b.a(O0.a.a(cVar, aVar.c(e0Var)));
                return;
            }
        }
        U0.b.a("ThreadHandoffProducer#produceResults");
        try {
            g0 g0VarP2 = e0Var.P();
            a aVar2 = f6318c;
            if (aVar2.d(e0Var)) {
                g0VarP2.g(e0Var, "BackgroundThreadHandoffProducer");
                g0VarP2.d(e0Var, "BackgroundThreadHandoffProducer", null);
                this.f6319a.a(interfaceC0369n, e0Var);
            } else {
                c cVar2 = new c(interfaceC0369n, g0VarP2, e0Var, this);
                e0Var.Z(new b(cVar2, this));
                this.f6320b.a(O0.a.a(cVar2, aVar2.c(e0Var)));
                h2.r rVar = h2.r.f9288a;
            }
        } finally {
            U0.b.b();
        }
    }

    public final d0 c() {
        return this.f6319a;
    }

    public final p0 d() {
        return this.f6320b;
    }
}
