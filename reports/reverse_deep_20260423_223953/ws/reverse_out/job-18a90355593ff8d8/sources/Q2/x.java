package Q2;

import java.io.IOException;
import java.io.OutputStream;

/* JADX INFO: loaded from: classes.dex */
final class x implements D {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final OutputStream f2581b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final G f2582c;

    public x(OutputStream outputStream, G g3) {
        t2.j.f(outputStream, "out");
        t2.j.f(g3, "timeout");
        this.f2581b = outputStream;
        this.f2582c = g3;
    }

    @Override // Q2.D, java.io.Closeable, java.lang.AutoCloseable
    public void close() throws IOException {
        this.f2581b.close();
    }

    @Override // Q2.D
    public G f() {
        return this.f2582c;
    }

    @Override // Q2.D, java.io.Flushable
    public void flush() throws IOException {
        this.f2581b.flush();
    }

    @Override // Q2.D
    public void m(i iVar, long j3) throws IOException {
        t2.j.f(iVar, "source");
        AbstractC0210f.b(iVar.F0(), 0L, j3);
        while (j3 > 0) {
            this.f2582c.f();
            A a3 = iVar.f2544b;
            t2.j.c(a3);
            int iMin = (int) Math.min(j3, a3.f2509c - a3.f2508b);
            this.f2581b.write(a3.f2507a, a3.f2508b, iMin);
            a3.f2508b += iMin;
            long j4 = iMin;
            j3 -= j4;
            iVar.E0(iVar.F0() - j4);
            if (a3.f2508b == a3.f2509c) {
                iVar.f2544b = a3.b();
                B.b(a3);
            }
        }
    }

    public String toString() {
        return "sink(" + this.f2581b + ')';
    }
}
