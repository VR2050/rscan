package Q2;

/* JADX INFO: loaded from: classes.dex */
public abstract class o implements F {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final F f2564b;

    public o(F f3) {
        t2.j.f(f3, "delegate");
        this.f2564b = f3;
    }

    @Override // Q2.F
    public long R(i iVar, long j3) {
        t2.j.f(iVar, "sink");
        return this.f2564b.R(iVar, j3);
    }

    public final F b() {
        return this.f2564b;
    }

    @Override // Q2.F, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        this.f2564b.close();
    }

    @Override // Q2.F
    public G f() {
        return this.f2564b.f();
    }

    public String toString() {
        return getClass().getSimpleName() + '(' + this.f2564b + ')';
    }
}
