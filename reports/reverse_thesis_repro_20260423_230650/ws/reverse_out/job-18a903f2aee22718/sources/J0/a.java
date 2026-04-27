package J0;

import P0.d;
import X.k;
import com.facebook.imagepipeline.producers.AbstractC0358c;
import com.facebook.imagepipeline.producers.InterfaceC0369n;
import com.facebook.imagepipeline.producers.d0;
import com.facebook.imagepipeline.producers.e0;
import com.facebook.imagepipeline.producers.l0;
import h0.AbstractC0545a;
import h2.r;
import java.util.Map;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public abstract class a extends AbstractC0545a {

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final l0 f1451h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final d f1452i;

    /* JADX INFO: renamed from: J0.a$a, reason: collision with other inner class name */
    public static final class C0021a extends AbstractC0358c {
        C0021a() {
        }

        @Override // com.facebook.imagepipeline.producers.AbstractC0358c
        protected void g() {
            a.this.E();
        }

        @Override // com.facebook.imagepipeline.producers.AbstractC0358c
        protected void h(Throwable th) {
            j.f(th, "throwable");
            a.this.F(th);
        }

        @Override // com.facebook.imagepipeline.producers.AbstractC0358c
        protected void i(Object obj, int i3) {
            a aVar = a.this;
            aVar.G(obj, i3, aVar.D());
        }

        @Override // com.facebook.imagepipeline.producers.AbstractC0358c
        protected void j(float f3) {
            a.this.t(f3);
        }
    }

    protected a(d0 d0Var, l0 l0Var, d dVar) {
        j.f(d0Var, "producer");
        j.f(l0Var, "settableProducerContext");
        j.f(dVar, "requestListener");
        this.f1451h = l0Var;
        this.f1452i = dVar;
        if (!U0.b.d()) {
            p(l0Var.b());
            if (U0.b.d()) {
                U0.b.a("AbstractProducerToDataSourceAdapter()->onRequestStart");
                try {
                    dVar.c(l0Var);
                    r rVar = r.f9288a;
                } finally {
                }
            } else {
                dVar.c(l0Var);
            }
            if (!U0.b.d()) {
                d0Var.a(B(), l0Var);
                return;
            }
            U0.b.a("AbstractProducerToDataSourceAdapter()->produceResult");
            try {
                d0Var.a(B(), l0Var);
                r rVar2 = r.f9288a;
                return;
            } finally {
            }
        }
        U0.b.a("AbstractProducerToDataSourceAdapter()");
        try {
            p(l0Var.b());
            if (U0.b.d()) {
                U0.b.a("AbstractProducerToDataSourceAdapter()->onRequestStart");
                try {
                    dVar.c(l0Var);
                    r rVar3 = r.f9288a;
                    U0.b.b();
                } finally {
                }
            } else {
                dVar.c(l0Var);
            }
            if (U0.b.d()) {
                U0.b.a("AbstractProducerToDataSourceAdapter()->produceResult");
                try {
                    d0Var.a(B(), l0Var);
                    r rVar4 = r.f9288a;
                    U0.b.b();
                } finally {
                }
            } else {
                d0Var.a(B(), l0Var);
            }
            r rVar5 = r.f9288a;
        } catch (Throwable th) {
            throw th;
        }
    }

    private final InterfaceC0369n B() {
        return new C0021a();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final synchronized void E() {
        k.i(l());
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void F(Throwable th) {
        if (super.r(th, C(this.f1451h))) {
            this.f1452i.k(this.f1451h, th);
        }
    }

    protected final Map C(e0 e0Var) {
        j.f(e0Var, "producerContext");
        return e0Var.b();
    }

    public final l0 D() {
        return this.f1451h;
    }

    protected void G(Object obj, int i3, e0 e0Var) {
        j.f(e0Var, "producerContext");
        boolean zE = AbstractC0358c.e(i3);
        if (super.v(obj, zE, C(e0Var)) && zE) {
            this.f1452i.h(this.f1451h);
        }
    }

    @Override // h0.AbstractC0545a, h0.InterfaceC0547c
    public boolean close() {
        if (!super.close()) {
            return false;
        }
        if (super.e()) {
            return true;
        }
        this.f1452i.a(this.f1451h);
        this.f1451h.j();
        return true;
    }
}
