package Q2;

import java.io.IOException;
import java.io.InputStream;

/* JADX INFO: loaded from: classes.dex */
final class s implements F {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final InputStream f2575b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final G f2576c;

    public s(InputStream inputStream, G g3) {
        t2.j.f(inputStream, "input");
        t2.j.f(g3, "timeout");
        this.f2575b = inputStream;
        this.f2576c = g3;
    }

    @Override // Q2.F
    public long R(i iVar, long j3) throws IOException {
        t2.j.f(iVar, "sink");
        if (j3 == 0) {
            return 0L;
        }
        if (!(j3 >= 0)) {
            throw new IllegalArgumentException(("byteCount < 0: " + j3).toString());
        }
        try {
            this.f2576c.f();
            A aI0 = iVar.I0(1);
            int i3 = this.f2575b.read(aI0.f2507a, aI0.f2509c, (int) Math.min(j3, 8192 - aI0.f2509c));
            if (i3 != -1) {
                aI0.f2509c += i3;
                long j4 = i3;
                iVar.E0(iVar.F0() + j4);
                return j4;
            }
            if (aI0.f2508b != aI0.f2509c) {
                return -1L;
            }
            iVar.f2544b = aI0.b();
            B.b(aI0);
            return -1L;
        } catch (AssertionError e3) {
            if (t.e(e3)) {
                throw new IOException(e3);
            }
            throw e3;
        }
    }

    @Override // Q2.F, java.io.Closeable, java.lang.AutoCloseable
    public void close() throws IOException {
        this.f2575b.close();
    }

    @Override // Q2.F
    public G f() {
        return this.f2576c;
    }

    public String toString() {
        return "source(" + this.f2575b + ')';
    }
}
