package p005b.p199l.p200a.p201a.p251q1.p252s;

import android.opengl.Matrix;
import p005b.p199l.p200a.p201a.p250p1.C2340b0;

/* renamed from: b.l.a.a.q1.s.c */
/* loaded from: classes.dex */
public final class C2389c {

    /* renamed from: a */
    public final float[] f6275a = new float[16];

    /* renamed from: b */
    public final float[] f6276b = new float[16];

    /* renamed from: c */
    public final C2340b0<float[]> f6277c = new C2340b0<>();

    /* renamed from: d */
    public boolean f6278d;

    /* renamed from: a */
    public static void m2643a(float[] fArr, float[] fArr2) {
        Matrix.setIdentityM(fArr, 0);
        float sqrt = (float) Math.sqrt((fArr2[8] * fArr2[8]) + (fArr2[10] * fArr2[10]));
        fArr[0] = fArr2[10] / sqrt;
        fArr[2] = fArr2[8] / sqrt;
        fArr[8] = (-fArr2[8]) / sqrt;
        fArr[10] = fArr2[10] / sqrt;
    }
}
