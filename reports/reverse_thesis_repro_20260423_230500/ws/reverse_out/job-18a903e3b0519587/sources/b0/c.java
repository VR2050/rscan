package b0;

import b0.AbstractC0311a;

/* JADX INFO: loaded from: classes.dex */
public class c extends AbstractC0311a {
    c(Object obj, g gVar, AbstractC0311a.c cVar, Throwable th) {
        super(obj, gVar, cVar, th, true);
    }

    protected void finalize() throws Throwable {
        try {
            synchronized (this) {
                if (this.f5393b) {
                    return;
                }
                Object objF = this.f5394c.f();
                Y.a.K("FinalizerCloseableReference", "Finalized without closing: %x %x (type = %s)", Integer.valueOf(System.identityHashCode(this)), Integer.valueOf(System.identityHashCode(this.f5394c)), objF == null ? null : objF.getClass().getName());
                this.f5394c.d();
            }
        } finally {
            super.finalize();
        }
    }

    @Override // b0.AbstractC0311a, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
    }

    @Override // b0.AbstractC0311a
    /* JADX INFO: renamed from: x */
    public AbstractC0311a clone() {
        return this;
    }
}
