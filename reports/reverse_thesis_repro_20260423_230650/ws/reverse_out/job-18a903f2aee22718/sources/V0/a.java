package V0;

import N0.j;

/* JADX INFO: loaded from: classes.dex */
public final class a {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final a f2810a = new a();

    private a() {
    }

    public static final float a(H0.h hVar, H0.g gVar, j jVar) {
        t2.j.f(hVar, "rotationOptions");
        t2.j.f(jVar, "encodedImage");
        if (!j.u0(jVar)) {
            throw new IllegalStateException("Check failed.");
        }
        if (gVar == null || gVar.f1022b <= 0 || gVar.f1021a <= 0 || jVar.h() == 0 || jVar.d() == 0) {
            return 1.0f;
        }
        int iD = f2810a.d(hVar, jVar);
        boolean z3 = iD == 90 || iD == 270;
        int iD2 = z3 ? jVar.d() : jVar.h();
        int iH = z3 ? jVar.h() : jVar.d();
        float f3 = gVar.f1021a / iD2;
        float f4 = gVar.f1022b / iH;
        float fB = w2.d.b(f3, f4);
        Y.a.D("DownsampleUtil", "Downsample - Specified size: %dx%d, image size: %dx%d ratio: %.1f x %.1f, ratio: %.3f", Integer.valueOf(gVar.f1021a), Integer.valueOf(gVar.f1022b), Integer.valueOf(iD2), Integer.valueOf(iH), Float.valueOf(f3), Float.valueOf(f4), Float.valueOf(fB));
        return fB;
    }

    public static final int b(H0.h hVar, H0.g gVar, j jVar, int i3) {
        t2.j.f(hVar, "rotationOptions");
        t2.j.f(jVar, "encodedImage");
        if (!j.u0(jVar)) {
            return 1;
        }
        float fA = a(hVar, gVar, jVar);
        int iF = jVar.D() == C0.b.f549b ? f(fA) : e(fA);
        int iMax = Math.max(jVar.d(), jVar.h());
        float f3 = gVar != null ? gVar.f1023c : i3;
        while (iMax / iF > f3) {
            iF = jVar.D() == C0.b.f549b ? iF * 2 : iF + 1;
        }
        return iF;
    }

    public static final int c(j jVar, int i3, int i4) {
        t2.j.f(jVar, "encodedImage");
        int iZ = jVar.Z();
        while ((((jVar.h() * jVar.d()) * i3) / iZ) / iZ > i4) {
            iZ *= 2;
        }
        return iZ;
    }

    private final int d(H0.h hVar, j jVar) {
        if (!hVar.h()) {
            return 0;
        }
        int iN = jVar.N();
        if (iN == 0 || iN == 90 || iN == 180 || iN == 270) {
            return iN;
        }
        throw new IllegalStateException("Check failed.");
    }

    public static final int e(float f3) {
        if (f3 > 0.6666667f) {
            return 1;
        }
        int i3 = 2;
        while (true) {
            double d3 = i3;
            if ((1.0d / d3) + ((1.0d / (Math.pow(d3, 2.0d) - d3)) * ((double) 0.33333334f)) <= f3) {
                return i3 - 1;
            }
            i3++;
        }
    }

    public static final int f(float f3) {
        if (f3 > 0.6666667f) {
            return 1;
        }
        int i3 = 2;
        while (true) {
            int i4 = i3 * 2;
            double d3 = 1.0d / ((double) i4);
            if (d3 + (((double) 0.33333334f) * d3) <= f3) {
                return i3;
            }
            i3 = i4;
        }
    }
}
