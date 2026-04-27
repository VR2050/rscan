package P2;

import Q2.F;
import Q2.i;
import Q2.r;
import java.io.Closeable;
import java.io.IOException;
import java.util.zip.Inflater;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class c implements Closeable {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final i f2218b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final Inflater f2219c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final r f2220d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final boolean f2221e;

    public c(boolean z3) {
        this.f2221e = z3;
        i iVar = new i();
        this.f2218b = iVar;
        Inflater inflater = new Inflater(true);
        this.f2219c = inflater;
        this.f2220d = new r((F) iVar, inflater);
    }

    public final void b(i iVar) throws IOException {
        j.f(iVar, "buffer");
        if (!(this.f2218b.F0() == 0)) {
            throw new IllegalArgumentException("Failed requirement.");
        }
        if (this.f2221e) {
            this.f2219c.reset();
        }
        this.f2218b.o(iVar);
        this.f2218b.E(65535);
        long bytesRead = this.f2219c.getBytesRead() + this.f2218b.F0();
        do {
            this.f2220d.b(iVar, Long.MAX_VALUE);
        } while (this.f2219c.getBytesRead() < bytesRead);
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        this.f2220d.close();
    }
}
