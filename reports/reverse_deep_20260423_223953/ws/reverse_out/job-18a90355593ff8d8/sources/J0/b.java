package J0;

import P0.d;
import b0.AbstractC0311a;
import com.facebook.imagepipeline.producers.d0;
import com.facebook.imagepipeline.producers.e0;
import com.facebook.imagepipeline.producers.l0;
import h0.InterfaceC0547c;

/* JADX INFO: loaded from: classes.dex */
public class b extends a {
    private b(d0 d0Var, l0 l0Var, d dVar) {
        super(d0Var, l0Var, dVar);
    }

    public static InterfaceC0547c I(d0 d0Var, l0 l0Var, d dVar) {
        if (U0.b.d()) {
            U0.b.a("CloseableProducerToDataSourceAdapter#create");
        }
        b bVar = new b(d0Var, l0Var, dVar);
        if (U0.b.d()) {
            U0.b.b();
        }
        return bVar;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // h0.AbstractC0545a
    /* JADX INFO: renamed from: H, reason: merged with bridge method [inline-methods] */
    public void i(AbstractC0311a abstractC0311a) {
        AbstractC0311a.D(abstractC0311a);
    }

    @Override // h0.AbstractC0545a, h0.InterfaceC0547c
    /* JADX INFO: renamed from: J, reason: merged with bridge method [inline-methods] */
    public AbstractC0311a a() {
        return AbstractC0311a.A((AbstractC0311a) super.a());
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // J0.a
    /* JADX INFO: renamed from: K, reason: merged with bridge method [inline-methods] */
    public void G(AbstractC0311a abstractC0311a, int i3, e0 e0Var) {
        super.G(AbstractC0311a.A(abstractC0311a), i3, e0Var);
    }
}
