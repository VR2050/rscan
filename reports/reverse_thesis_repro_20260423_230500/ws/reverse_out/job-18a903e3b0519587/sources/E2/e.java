package E2;

import Q2.D;
import Q2.i;
import Q2.n;
import java.io.EOFException;
import java.io.IOException;
import s2.l;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public class e extends n {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private boolean f726c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final l f727d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(D d3, l lVar) {
        super(d3);
        j.f(d3, "delegate");
        j.f(lVar, "onException");
        this.f727d = lVar;
    }

    @Override // Q2.n, Q2.D, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        if (this.f726c) {
            return;
        }
        try {
            super.close();
        } catch (IOException e3) {
            this.f726c = true;
            this.f727d.d(e3);
        }
    }

    @Override // Q2.n, Q2.D, java.io.Flushable
    public void flush() {
        if (this.f726c) {
            return;
        }
        try {
            super.flush();
        } catch (IOException e3) {
            this.f726c = true;
            this.f727d.d(e3);
        }
    }

    @Override // Q2.n, Q2.D
    public void m(i iVar, long j3) throws EOFException {
        j.f(iVar, "source");
        if (this.f726c) {
            iVar.t(j3);
            return;
        }
        try {
            super.m(iVar, j3);
        } catch (IOException e3) {
            this.f726c = true;
            this.f727d.d(e3);
        }
    }
}
