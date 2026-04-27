package B2;

import java.util.concurrent.TimeUnit;

/* JADX INFO: loaded from: classes.dex */
public final class k {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final G2.h f349a;

    public k(G2.h hVar) {
        t2.j.f(hVar, "delegate");
        this.f349a = hVar;
    }

    public final G2.h a() {
        return this.f349a;
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public k(int i3, long j3, TimeUnit timeUnit) {
        this(new G2.h(F2.e.f751h, i3, j3, timeUnit));
        t2.j.f(timeUnit, "timeUnit");
    }

    public k() {
        this(5, 5L, TimeUnit.MINUTES);
    }
}
