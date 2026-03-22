package androidx.transition;

import android.animation.TypeEvaluator;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public class FloatArrayEvaluator implements TypeEvaluator<float[]> {
    private float[] mArray;

    public FloatArrayEvaluator(float[] fArr) {
        this.mArray = fArr;
    }

    @Override // android.animation.TypeEvaluator
    public float[] evaluate(float f2, float[] fArr, float[] fArr2) {
        float[] fArr3 = this.mArray;
        if (fArr3 == null) {
            fArr3 = new float[fArr.length];
        }
        for (int i2 = 0; i2 < fArr3.length; i2++) {
            float f3 = fArr[i2];
            fArr3[i2] = C1499a.m627m(fArr2[i2], f3, f2, f3);
        }
        return fArr3;
    }
}
