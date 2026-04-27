package H2;

import B2.E;
import B2.x;

/* JADX INFO: loaded from: classes.dex */
public final class h extends E {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final String f1088c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final long f1089d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final Q2.k f1090e;

    public h(String str, long j3, Q2.k kVar) {
        t2.j.f(kVar, "source");
        this.f1088c = str;
        this.f1089d = j3;
        this.f1090e = kVar;
    }

    @Override // B2.E
    public long r() {
        return this.f1089d;
    }

    @Override // B2.E
    public x v() {
        String str = this.f1088c;
        if (str != null) {
            return x.f437g.c(str);
        }
        return null;
    }

    @Override // B2.E
    public Q2.k y() {
        return this.f1090e;
    }
}
