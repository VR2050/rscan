package androidx.interpolator.view.animation;

import android.view.animation.Interpolator;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public abstract class LookupTableInterpolator implements Interpolator {
    private final float mStepSize;
    private final float[] mValues;

    public LookupTableInterpolator(float[] fArr) {
        this.mValues = fArr;
        this.mStepSize = 1.0f / (fArr.length - 1);
    }

    @Override // android.animation.TimeInterpolator
    public float getInterpolation(float f2) {
        if (f2 >= 1.0f) {
            return 1.0f;
        }
        if (f2 <= 0.0f) {
            return 0.0f;
        }
        float[] fArr = this.mValues;
        int min = Math.min((int) ((fArr.length - 1) * f2), fArr.length - 2);
        float f3 = this.mStepSize;
        float f4 = (f2 - (min * f3)) / f3;
        float[] fArr2 = this.mValues;
        return C1499a.m627m(fArr2[min + 1], fArr2[min], f4, fArr2[min]);
    }
}
