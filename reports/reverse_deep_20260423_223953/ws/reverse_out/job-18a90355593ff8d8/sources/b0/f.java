package b0;

import X.k;
import b0.AbstractC0311a;

/* JADX INFO: loaded from: classes.dex */
public class f extends AbstractC0311a {
    private f(h hVar, AbstractC0311a.c cVar, Throwable th) {
        super(hVar, cVar, th);
    }

    @Override // b0.AbstractC0311a
    /* JADX INFO: renamed from: x */
    public AbstractC0311a clone() {
        k.i(Z());
        return new f(this.f5394c, this.f5395d, this.f5396e);
    }

    f(Object obj, g gVar, AbstractC0311a.c cVar, Throwable th) {
        super(obj, gVar, cVar, th, false);
    }
}
