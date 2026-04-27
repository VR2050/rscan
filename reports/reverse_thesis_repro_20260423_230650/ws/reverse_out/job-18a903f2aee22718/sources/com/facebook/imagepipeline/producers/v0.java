package com.facebook.imagepipeline.producers;

/* JADX INFO: loaded from: classes.dex */
public final class v0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final v0 f6389a = new v0();

    private v0() {
    }

    public static final int a(int i3) {
        return (int) (i3 * 1.3333334f);
    }

    public static final boolean b(int i3, int i4, H0.g gVar) {
        if (gVar == null) {
            if (a(i3) < 2048.0f || a(i4) < 2048) {
                return false;
            }
        } else if (a(i3) < gVar.f1021a || a(i4) < gVar.f1022b) {
            return false;
        }
        return true;
    }

    public static final boolean c(N0.j jVar, H0.g gVar) {
        if (jVar == null) {
            return false;
        }
        int iN = jVar.N();
        return (iN == 90 || iN == 270) ? b(jVar.d(), jVar.h(), gVar) : b(jVar.h(), jVar.d(), gVar);
    }
}
