package b0;

import X.k;
import b0.AbstractC0311a;

/* JADX INFO: loaded from: classes.dex */
public class b extends AbstractC0311a {
    private b(h hVar, AbstractC0311a.c cVar, Throwable th) {
        super(hVar, cVar, th);
    }

    protected void finalize() throws Throwable {
        try {
            synchronized (this) {
                if (this.f5393b) {
                    super.finalize();
                    return;
                }
                Object objF = this.f5394c.f();
                Y.a.K("DefaultCloseableReference", "Finalized without closing: %x %x (type = %s)", Integer.valueOf(System.identityHashCode(this)), Integer.valueOf(System.identityHashCode(this.f5394c)), objF == null ? null : objF.getClass().getName());
                AbstractC0311a.c cVar = this.f5395d;
                if (cVar != null) {
                    cVar.b(this.f5394c, this.f5396e);
                }
                close();
                super.finalize();
            }
        } catch (Throwable th) {
            super.finalize();
            throw th;
        }
    }

    @Override // b0.AbstractC0311a
    /* JADX INFO: renamed from: x, reason: merged with bridge method [inline-methods] */
    public AbstractC0311a clone() {
        k.i(Z());
        return new b(this.f5394c, this.f5395d, this.f5396e != null ? new Throwable() : null);
    }

    b(Object obj, g gVar, AbstractC0311a.c cVar, Throwable th) {
        super(obj, gVar, cVar, th, true);
    }
}
