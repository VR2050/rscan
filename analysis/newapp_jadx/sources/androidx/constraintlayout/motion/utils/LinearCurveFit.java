package androidx.constraintlayout.motion.utils;

import com.google.android.material.shadow.ShadowDrawableWrapper;

/* loaded from: classes.dex */
public class LinearCurveFit extends CurveFit {
    private static final String TAG = "LinearCurveFit";

    /* renamed from: mT */
    private double[] f126mT;
    private double mTotalLength;

    /* renamed from: mY */
    private double[][] f127mY;

    public LinearCurveFit(double[] dArr, double[][] dArr2) {
        this.mTotalLength = Double.NaN;
        int length = dArr.length;
        int length2 = dArr2[0].length;
        this.f126mT = dArr;
        this.f127mY = dArr2;
        if (length2 > 2) {
            double d2 = 0.0d;
            double d3 = 0.0d;
            int i2 = 0;
            while (i2 < dArr.length) {
                double d4 = dArr2[i2][0];
                double d5 = dArr2[i2][0];
                if (i2 > 0) {
                    Math.hypot(d4 - d2, d5 - d3);
                }
                i2++;
                d2 = d4;
                d3 = d5;
            }
            this.mTotalLength = ShadowDrawableWrapper.COS_45;
        }
    }

    private double getLength2D(double d2) {
        if (Double.isNaN(this.mTotalLength)) {
            return ShadowDrawableWrapper.COS_45;
        }
        double[] dArr = this.f126mT;
        int length = dArr.length;
        if (d2 <= dArr[0]) {
            return ShadowDrawableWrapper.COS_45;
        }
        int i2 = length - 1;
        if (d2 >= dArr[i2]) {
            return this.mTotalLength;
        }
        double d3 = 0.0d;
        double d4 = 0.0d;
        double d5 = 0.0d;
        int i3 = 0;
        while (i3 < i2) {
            double[][] dArr2 = this.f127mY;
            double d6 = dArr2[i3][0];
            double d7 = dArr2[i3][1];
            if (i3 > 0) {
                d3 += Math.hypot(d6 - d4, d7 - d5);
            }
            double[] dArr3 = this.f126mT;
            if (d2 == dArr3[i3]) {
                return d3;
            }
            int i4 = i3 + 1;
            if (d2 < dArr3[i4]) {
                double d8 = (d2 - dArr3[i3]) / (dArr3[i4] - dArr3[i3]);
                double[][] dArr4 = this.f127mY;
                double d9 = dArr4[i3][0];
                double d10 = dArr4[i4][0];
                double d11 = 1.0d - d8;
                return Math.hypot(d7 - ((dArr4[i4][1] * d8) + (dArr4[i3][1] * d11)), d6 - ((d10 * d8) + (d9 * d11))) + d3;
            }
            i3 = i4;
            d4 = d6;
            d5 = d7;
        }
        return ShadowDrawableWrapper.COS_45;
    }

    @Override // androidx.constraintlayout.motion.utils.CurveFit
    public void getPos(double d2, double[] dArr) {
        double[] dArr2 = this.f126mT;
        int length = dArr2.length;
        int i2 = 0;
        int length2 = this.f127mY[0].length;
        if (d2 <= dArr2[0]) {
            for (int i3 = 0; i3 < length2; i3++) {
                dArr[i3] = this.f127mY[0][i3];
            }
            return;
        }
        int i4 = length - 1;
        if (d2 >= dArr2[i4]) {
            while (i2 < length2) {
                dArr[i2] = this.f127mY[i4][i2];
                i2++;
            }
            return;
        }
        int i5 = 0;
        while (i5 < i4) {
            if (d2 == this.f126mT[i5]) {
                for (int i6 = 0; i6 < length2; i6++) {
                    dArr[i6] = this.f127mY[i5][i6];
                }
            }
            double[] dArr3 = this.f126mT;
            int i7 = i5 + 1;
            if (d2 < dArr3[i7]) {
                double d3 = (d2 - dArr3[i5]) / (dArr3[i7] - dArr3[i5]);
                while (i2 < length2) {
                    double[][] dArr4 = this.f127mY;
                    dArr[i2] = (dArr4[i7][i2] * d3) + ((1.0d - d3) * dArr4[i5][i2]);
                    i2++;
                }
                return;
            }
            i5 = i7;
        }
    }

    @Override // androidx.constraintlayout.motion.utils.CurveFit
    public void getSlope(double d2, double[] dArr) {
        double[] dArr2 = this.f126mT;
        int length = dArr2.length;
        int length2 = this.f127mY[0].length;
        if (d2 <= dArr2[0]) {
            d2 = dArr2[0];
        } else {
            int i2 = length - 1;
            if (d2 >= dArr2[i2]) {
                d2 = dArr2[i2];
            }
        }
        int i3 = 0;
        while (i3 < length - 1) {
            double[] dArr3 = this.f126mT;
            int i4 = i3 + 1;
            if (d2 <= dArr3[i4]) {
                double d3 = dArr3[i4] - dArr3[i3];
                double d4 = dArr3[i3];
                for (int i5 = 0; i5 < length2; i5++) {
                    double[][] dArr4 = this.f127mY;
                    dArr[i5] = (dArr4[i4][i5] - dArr4[i3][i5]) / d3;
                }
                return;
            }
            i3 = i4;
        }
    }

    @Override // androidx.constraintlayout.motion.utils.CurveFit
    public double[] getTimePoints() {
        return this.f126mT;
    }

    @Override // androidx.constraintlayout.motion.utils.CurveFit
    public double getSlope(double d2, int i2) {
        double[] dArr = this.f126mT;
        int length = dArr.length;
        int i3 = 0;
        if (d2 < dArr[0]) {
            d2 = dArr[0];
        } else {
            int i4 = length - 1;
            if (d2 >= dArr[i4]) {
                d2 = dArr[i4];
            }
        }
        while (i3 < length - 1) {
            double[] dArr2 = this.f126mT;
            int i5 = i3 + 1;
            if (d2 <= dArr2[i5]) {
                double d3 = dArr2[i5] - dArr2[i3];
                double d4 = dArr2[i3];
                double[][] dArr3 = this.f127mY;
                return (dArr3[i5][i2] - dArr3[i3][i2]) / d3;
            }
            i3 = i5;
        }
        return ShadowDrawableWrapper.COS_45;
    }

    @Override // androidx.constraintlayout.motion.utils.CurveFit
    public void getPos(double d2, float[] fArr) {
        double[] dArr = this.f126mT;
        int length = dArr.length;
        int i2 = 0;
        int length2 = this.f127mY[0].length;
        if (d2 <= dArr[0]) {
            for (int i3 = 0; i3 < length2; i3++) {
                fArr[i3] = (float) this.f127mY[0][i3];
            }
            return;
        }
        int i4 = length - 1;
        if (d2 >= dArr[i4]) {
            while (i2 < length2) {
                fArr[i2] = (float) this.f127mY[i4][i2];
                i2++;
            }
            return;
        }
        int i5 = 0;
        while (i5 < i4) {
            if (d2 == this.f126mT[i5]) {
                for (int i6 = 0; i6 < length2; i6++) {
                    fArr[i6] = (float) this.f127mY[i5][i6];
                }
            }
            double[] dArr2 = this.f126mT;
            int i7 = i5 + 1;
            if (d2 < dArr2[i7]) {
                double d3 = (d2 - dArr2[i5]) / (dArr2[i7] - dArr2[i5]);
                while (i2 < length2) {
                    double[][] dArr3 = this.f127mY;
                    fArr[i2] = (float) ((dArr3[i7][i2] * d3) + ((1.0d - d3) * dArr3[i5][i2]));
                    i2++;
                }
                return;
            }
            i5 = i7;
        }
    }

    @Override // androidx.constraintlayout.motion.utils.CurveFit
    public double getPos(double d2, int i2) {
        double[] dArr = this.f126mT;
        int length = dArr.length;
        int i3 = 0;
        if (d2 <= dArr[0]) {
            return this.f127mY[0][i2];
        }
        int i4 = length - 1;
        if (d2 >= dArr[i4]) {
            return this.f127mY[i4][i2];
        }
        while (i3 < i4) {
            double[] dArr2 = this.f126mT;
            if (d2 == dArr2[i3]) {
                return this.f127mY[i3][i2];
            }
            int i5 = i3 + 1;
            if (d2 < dArr2[i5]) {
                double d3 = (d2 - dArr2[i3]) / (dArr2[i5] - dArr2[i3]);
                double[][] dArr3 = this.f127mY;
                return (dArr3[i5][i2] * d3) + ((1.0d - d3) * dArr3[i3][i2]);
            }
            i3 = i5;
        }
        return ShadowDrawableWrapper.COS_45;
    }
}
