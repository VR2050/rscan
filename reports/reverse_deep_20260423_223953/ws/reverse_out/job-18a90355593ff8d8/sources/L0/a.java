package L0;

import N0.j;

/* JADX INFO: loaded from: classes.dex */
public final class a extends RuntimeException {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final j f1695b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(String str, j jVar) {
        super(str);
        t2.j.f(jVar, "encodedImage");
        this.f1695b = jVar;
    }

    public final j a() {
        return this.f1695b;
    }
}
