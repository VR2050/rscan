package V0;

import android.graphics.Matrix;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class e {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final e f2812a = new e();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final X.f f2813b;

    static {
        X.f fVarC = X.f.c(2, 7, 4, 5);
        j.e(fVarC, "of(...)");
        f2813b = fVarC;
    }

    private e() {
    }

    public static final int a(int i3) {
        return Math.max(1, 8 / i3);
    }

    public static final float b(H0.g gVar, int i3, int i4) {
        if (gVar == null) {
            return 1.0f;
        }
        float f3 = i3;
        float f4 = i4;
        float fMax = Math.max(gVar.f1021a / f3, gVar.f1022b / f4);
        float f5 = f3 * fMax;
        float f6 = gVar.f1023c;
        if (f5 > f6) {
            fMax = f6 / f3;
        }
        return f4 * fMax > f6 ? f6 / f4 : fMax;
    }

    private final int c(N0.j jVar) {
        int iN = jVar.N();
        if (iN == 90 || iN == 180 || iN == 270) {
            return jVar.N();
        }
        return 0;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static final int d(H0.h hVar, N0.j jVar) {
        j.f(hVar, "rotationOptions");
        j.f(jVar, "encodedImage");
        int iS0 = jVar.s0();
        X.f fVar = f2813b;
        int iIndexOf = fVar.indexOf(Integer.valueOf(iS0));
        if (iIndexOf < 0) {
            throw new IllegalArgumentException("Only accepts inverted exif orientations");
        }
        E e3 = fVar.get((iIndexOf + ((!hVar.h() ? hVar.f() : 0) / 90)) % fVar.size());
        j.e(e3, "get(...)");
        return ((Number) e3).intValue();
    }

    public static final int e(H0.h hVar, N0.j jVar) {
        j.f(hVar, "rotationOptions");
        j.f(jVar, "encodedImage");
        if (!hVar.g()) {
            return 0;
        }
        int iC = f2812a.c(jVar);
        return hVar.h() ? iC : (iC + hVar.f()) % 360;
    }

    public static final int f(H0.h hVar, H0.g gVar, N0.j jVar, boolean z3) {
        j.f(hVar, "rotationOptions");
        j.f(jVar, "encodedImage");
        if (!z3 || gVar == null) {
            return 8;
        }
        int iE = e(hVar, jVar);
        int iD = f2813b.contains(Integer.valueOf(jVar.s0())) ? d(hVar, jVar) : 0;
        boolean z4 = iE == 90 || iE == 270 || iD == 5 || iD == 7;
        int iK = k(b(gVar, z4 ? jVar.d() : jVar.h(), z4 ? jVar.h() : jVar.d()), gVar.f1024d);
        if (iK > 8) {
            return 8;
        }
        if (iK < 1) {
            return 1;
        }
        return iK;
    }

    public static final Matrix g(N0.j jVar, H0.h hVar) {
        j.f(jVar, "encodedImage");
        j.f(hVar, "rotationOptions");
        if (f2813b.contains(Integer.valueOf(jVar.s0()))) {
            return f2812a.h(d(hVar, jVar));
        }
        int iE = e(hVar, jVar);
        if (iE == 0) {
            return null;
        }
        Matrix matrix = new Matrix();
        matrix.setRotate(iE);
        return matrix;
    }

    private final Matrix h(int i3) {
        Matrix matrix = new Matrix();
        if (i3 == 2) {
            matrix.setScale(-1.0f, 1.0f);
        } else if (i3 == 7) {
            matrix.setRotate(-90.0f);
            matrix.postScale(-1.0f, 1.0f);
        } else if (i3 == 4) {
            matrix.setRotate(180.0f);
            matrix.postScale(-1.0f, 1.0f);
        } else {
            if (i3 != 5) {
                return null;
            }
            matrix.setRotate(90.0f);
            matrix.postScale(-1.0f, 1.0f);
        }
        return matrix;
    }

    public static final boolean i(int i3) {
        switch (i3) {
            case 1:
            case 2:
            case 3:
            case 4:
            case 5:
            case 6:
            case 7:
            case 8:
                return true;
            default:
                return false;
        }
    }

    public static final boolean j(int i3) {
        return i3 >= 0 && i3 <= 270 && i3 % 90 == 0;
    }

    public static final int k(float f3, float f4) {
        return (int) (f4 + (f3 * 8));
    }
}
