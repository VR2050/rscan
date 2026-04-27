package Q2;

import java.util.zip.Deflater;

/* JADX INFO: loaded from: classes.dex */
public final class m implements D {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private boolean f2560b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final j f2561c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final Deflater f2562d;

    public m(j jVar, Deflater deflater) {
        t2.j.f(jVar, "sink");
        t2.j.f(deflater, "deflater");
        this.f2561c = jVar;
        this.f2562d = deflater;
    }

    private final void b(boolean z3) {
        A aI0;
        int iDeflate;
        i iVarE = this.f2561c.e();
        while (true) {
            aI0 = iVarE.I0(1);
            if (z3) {
                Deflater deflater = this.f2562d;
                byte[] bArr = aI0.f2507a;
                int i3 = aI0.f2509c;
                iDeflate = deflater.deflate(bArr, i3, 8192 - i3, 2);
            } else {
                Deflater deflater2 = this.f2562d;
                byte[] bArr2 = aI0.f2507a;
                int i4 = aI0.f2509c;
                iDeflate = deflater2.deflate(bArr2, i4, 8192 - i4);
            }
            if (iDeflate > 0) {
                aI0.f2509c += iDeflate;
                iVarE.E0(iVarE.F0() + ((long) iDeflate));
                this.f2561c.S();
            } else if (this.f2562d.needsInput()) {
                break;
            }
        }
        if (aI0.f2508b == aI0.f2509c) {
            iVarE.f2544b = aI0.b();
            B.b(aI0);
        }
    }

    @Override // Q2.D, java.io.Closeable, java.lang.AutoCloseable
    public void close() throws Throwable {
        if (this.f2560b) {
            return;
        }
        try {
            i();
            th = null;
        } catch (Throwable th) {
            th = th;
        }
        try {
            this.f2562d.end();
        } catch (Throwable th2) {
            if (th == null) {
                th = th2;
            }
        }
        try {
            this.f2561c.close();
        } catch (Throwable th3) {
            if (th == null) {
                th = th3;
            }
        }
        this.f2560b = true;
        if (th != null) {
            throw th;
        }
    }

    @Override // Q2.D
    public G f() {
        return this.f2561c.f();
    }

    @Override // Q2.D, java.io.Flushable
    public void flush() {
        b(true);
        this.f2561c.flush();
    }

    public final void i() {
        this.f2562d.finish();
        b(false);
    }

    @Override // Q2.D
    public void m(i iVar, long j3) {
        t2.j.f(iVar, "source");
        AbstractC0210f.b(iVar.F0(), 0L, j3);
        while (j3 > 0) {
            A a3 = iVar.f2544b;
            t2.j.c(a3);
            int iMin = (int) Math.min(j3, a3.f2509c - a3.f2508b);
            this.f2562d.setInput(a3.f2507a, a3.f2508b, iMin);
            b(false);
            long j4 = iMin;
            iVar.E0(iVar.F0() - j4);
            int i3 = a3.f2508b + iMin;
            a3.f2508b = i3;
            if (i3 == a3.f2509c) {
                iVar.f2544b = a3.b();
                B.b(a3);
            }
            j3 -= j4;
        }
    }

    public String toString() {
        return "DeflaterSink(" + this.f2561c + ')';
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public m(D d3, Deflater deflater) {
        this(t.c(d3), deflater);
        t2.j.f(d3, "sink");
        t2.j.f(deflater, "deflater");
    }
}
