package Q2;

import java.io.EOFException;

/* JADX INFO: renamed from: Q2.h, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
final class C0212h implements D {
    @Override // Q2.D
    public G f() {
        return G.f2522d;
    }

    @Override // Q2.D
    public void m(i iVar, long j3) throws EOFException {
        t2.j.f(iVar, "source");
        iVar.t(j3);
    }

    @Override // Q2.D, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
    }

    @Override // Q2.D, java.io.Flushable
    public void flush() {
    }
}
