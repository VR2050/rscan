package Q2;

/* JADX INFO: loaded from: classes.dex */
public abstract class n implements D {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final D f2563b;

    public n(D d3) {
        t2.j.f(d3, "delegate");
        this.f2563b = d3;
    }

    @Override // Q2.D, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        this.f2563b.close();
    }

    @Override // Q2.D
    public G f() {
        return this.f2563b.f();
    }

    @Override // Q2.D, java.io.Flushable
    public void flush() {
        this.f2563b.flush();
    }

    @Override // Q2.D
    public void m(i iVar, long j3) {
        t2.j.f(iVar, "source");
        this.f2563b.m(iVar, j3);
    }

    public String toString() {
        return getClass().getSimpleName() + '(' + this.f2563b + ')';
    }
}
