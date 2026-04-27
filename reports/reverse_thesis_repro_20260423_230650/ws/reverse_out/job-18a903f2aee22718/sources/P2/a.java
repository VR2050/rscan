package P2;

import Q2.D;
import Q2.i;
import Q2.l;
import Q2.m;
import java.io.Closeable;
import java.io.IOException;
import java.util.zip.Deflater;
import q2.AbstractC0663a;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class a implements Closeable {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final i f2213b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final Deflater f2214c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final m f2215d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final boolean f2216e;

    public a(boolean z3) {
        this.f2216e = z3;
        i iVar = new i();
        this.f2213b = iVar;
        Deflater deflater = new Deflater(-1, true);
        this.f2214c = deflater;
        this.f2215d = new m((D) iVar, deflater);
    }

    private final boolean i(i iVar, l lVar) {
        return iVar.u0(iVar.F0() - ((long) lVar.v()), lVar);
    }

    public final void b(i iVar) throws IOException {
        j.f(iVar, "buffer");
        if (!(this.f2213b.F0() == 0)) {
            throw new IllegalArgumentException("Failed requirement.");
        }
        if (this.f2216e) {
            this.f2214c.reset();
        }
        this.f2215d.m(iVar, iVar.F0());
        this.f2215d.flush();
        if (i(this.f2213b, b.f2217a)) {
            long jF0 = this.f2213b.F0() - ((long) 4);
            i.a aVarY0 = i.y0(this.f2213b, null, 1, null);
            try {
                aVarY0.i(jF0);
                AbstractC0663a.a(aVarY0, null);
            } finally {
            }
        } else {
            this.f2213b.L(0);
        }
        i iVar2 = this.f2213b;
        iVar.m(iVar2, iVar2.F0());
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public void close() throws Throwable {
        this.f2215d.close();
    }
}
