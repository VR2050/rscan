package Q2;

import java.io.InterruptedIOException;
import java.util.concurrent.TimeUnit;

/* JADX INFO: loaded from: classes.dex */
public class p extends G {

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private G f2565f;

    public p(G g3) {
        t2.j.f(g3, "delegate");
        this.f2565f = g3;
    }

    @Override // Q2.G
    public G a() {
        return this.f2565f.a();
    }

    @Override // Q2.G
    public G b() {
        return this.f2565f.b();
    }

    @Override // Q2.G
    public long c() {
        return this.f2565f.c();
    }

    @Override // Q2.G
    public G d(long j3) {
        return this.f2565f.d(j3);
    }

    @Override // Q2.G
    public boolean e() {
        return this.f2565f.e();
    }

    @Override // Q2.G
    public void f() throws InterruptedIOException {
        this.f2565f.f();
    }

    @Override // Q2.G
    public G g(long j3, TimeUnit timeUnit) {
        t2.j.f(timeUnit, "unit");
        return this.f2565f.g(j3, timeUnit);
    }

    @Override // Q2.G
    public long h() {
        return this.f2565f.h();
    }

    public final G i() {
        return this.f2565f;
    }

    public final p j(G g3) {
        t2.j.f(g3, "delegate");
        this.f2565f = g3;
        return this;
    }
}
