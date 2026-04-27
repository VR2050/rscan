package C;

import android.view.animation.Interpolator;

/* JADX INFO: loaded from: classes.dex */
abstract class b implements Interpolator {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final float[] f526a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final float f527b;

    protected b(float[] fArr) {
        this.f526a = fArr;
        this.f527b = 1.0f / (fArr.length - 1);
    }

    @Override // android.animation.TimeInterpolator
    public float getInterpolation(float f3) {
        if (f3 >= 1.0f) {
            return 1.0f;
        }
        if (f3 <= 0.0f) {
            return 0.0f;
        }
        float[] fArr = this.f526a;
        int iMin = Math.min((int) ((fArr.length - 1) * f3), fArr.length - 2);
        float f4 = this.f527b;
        float f5 = (f3 - (iMin * f4)) / f4;
        float[] fArr2 = this.f526a;
        float f6 = fArr2[iMin];
        return f6 + (f5 * (fArr2[iMin + 1] - f6));
    }
}
