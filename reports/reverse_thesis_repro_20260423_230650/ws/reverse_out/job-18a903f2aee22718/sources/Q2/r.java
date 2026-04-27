package Q2;

import java.io.EOFException;
import java.io.IOException;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/* JADX INFO: loaded from: classes.dex */
public final class r implements F {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private int f2571b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private boolean f2572c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final k f2573d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final Inflater f2574e;

    public r(k kVar, Inflater inflater) {
        t2.j.f(kVar, "source");
        t2.j.f(inflater, "inflater");
        this.f2573d = kVar;
        this.f2574e = inflater;
    }

    private final void p() {
        int i3 = this.f2571b;
        if (i3 == 0) {
            return;
        }
        int remaining = i3 - this.f2574e.getRemaining();
        this.f2571b -= remaining;
        this.f2573d.t(remaining);
    }

    @Override // Q2.F
    public long R(i iVar, long j3) throws IOException {
        t2.j.f(iVar, "sink");
        do {
            long jB = b(iVar, j3);
            if (jB > 0) {
                return jB;
            }
            if (this.f2574e.finished() || this.f2574e.needsDictionary()) {
                return -1L;
            }
        } while (!this.f2573d.K());
        throw new EOFException("source exhausted prematurely");
    }

    public final long b(i iVar, long j3) throws IOException {
        t2.j.f(iVar, "sink");
        if (!(j3 >= 0)) {
            throw new IllegalArgumentException(("byteCount < 0: " + j3).toString());
        }
        if (this.f2572c) {
            throw new IllegalStateException("closed");
        }
        if (j3 == 0) {
            return 0L;
        }
        try {
            A aI0 = iVar.I0(1);
            int iMin = (int) Math.min(j3, 8192 - aI0.f2509c);
            i();
            int iInflate = this.f2574e.inflate(aI0.f2507a, aI0.f2509c, iMin);
            p();
            if (iInflate > 0) {
                aI0.f2509c += iInflate;
                long j4 = iInflate;
                iVar.E0(iVar.F0() + j4);
                return j4;
            }
            if (aI0.f2508b == aI0.f2509c) {
                iVar.f2544b = aI0.b();
                B.b(aI0);
            }
            return 0L;
        } catch (DataFormatException e3) {
            throw new IOException(e3);
        }
    }

    @Override // Q2.F, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        if (this.f2572c) {
            return;
        }
        this.f2574e.end();
        this.f2572c = true;
        this.f2573d.close();
    }

    @Override // Q2.F
    public G f() {
        return this.f2573d.f();
    }

    public final boolean i() {
        if (!this.f2574e.needsInput()) {
            return false;
        }
        if (this.f2573d.K()) {
            return true;
        }
        A a3 = this.f2573d.e().f2544b;
        t2.j.c(a3);
        int i3 = a3.f2509c;
        int i4 = a3.f2508b;
        int i5 = i3 - i4;
        this.f2571b = i5;
        this.f2574e.setInput(a3.f2507a, i4, i5);
        return false;
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public r(F f3, Inflater inflater) {
        this(t.d(f3), inflater);
        t2.j.f(f3, "source");
        t2.j.f(inflater, "inflater");
    }
}
