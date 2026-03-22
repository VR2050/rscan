package androidx.constraintlayout.motion.utils;

import com.google.android.material.shadow.ShadowDrawableWrapper;
import java.lang.reflect.Array;

/* loaded from: classes.dex */
public class MonotonicCurveFit extends CurveFit {
    private static final String TAG = "MonotonicCurveFit";

    /* renamed from: mT */
    private double[] f128mT;
    private double[][] mTangent;

    /* renamed from: mY */
    private double[][] f129mY;

    public MonotonicCurveFit(double[] dArr, double[][] dArr2) {
        int length = dArr.length;
        int length2 = dArr2[0].length;
        int i2 = length - 1;
        double[][] dArr3 = (double[][]) Array.newInstance((Class<?>) double.class, i2, length2);
        double[][] dArr4 = (double[][]) Array.newInstance((Class<?>) double.class, length, length2);
        for (int i3 = 0; i3 < length2; i3++) {
            int i4 = 0;
            while (i4 < i2) {
                int i5 = i4 + 1;
                dArr3[i4][i3] = (dArr2[i5][i3] - dArr2[i4][i3]) / (dArr[i5] - dArr[i4]);
                if (i4 == 0) {
                    dArr4[i4][i3] = dArr3[i4][i3];
                } else {
                    dArr4[i4][i3] = (dArr3[i4 - 1][i3] + dArr3[i4][i3]) * 0.5d;
                }
                i4 = i5;
            }
            dArr4[i2][i3] = dArr3[length - 2][i3];
        }
        for (int i6 = 0; i6 < i2; i6++) {
            for (int i7 = 0; i7 < length2; i7++) {
                if (dArr3[i6][i7] == ShadowDrawableWrapper.COS_45) {
                    dArr4[i6][i7] = 0.0d;
                    dArr4[i6 + 1][i7] = 0.0d;
                } else {
                    double d2 = dArr4[i6][i7] / dArr3[i6][i7];
                    int i8 = i6 + 1;
                    double d3 = dArr4[i8][i7] / dArr3[i6][i7];
                    double hypot = Math.hypot(d2, d3);
                    if (hypot > 9.0d) {
                        double d4 = 3.0d / hypot;
                        dArr4[i6][i7] = d2 * d4 * dArr3[i6][i7];
                        dArr4[i8][i7] = d4 * d3 * dArr3[i6][i7];
                    }
                }
            }
        }
        this.f128mT = dArr;
        this.f129mY = dArr2;
        this.mTangent = dArr4;
    }

    private static double diff(double d2, double d3, double d4, double d5, double d6, double d7) {
        double d8 = d3 * d3;
        double d9 = d3 * 6.0d;
        double d10 = 6.0d * d8 * d4;
        double d11 = 3.0d * d2;
        return (d2 * d6) + (((((d11 * d6) * d8) + (((d11 * d7) * d8) + ((d10 + ((d9 * d5) + (((-6.0d) * d8) * d5))) - (d9 * d4)))) - (((2.0d * d2) * d7) * d3)) - (((4.0d * d2) * d6) * d3));
    }

    private static double interpolate(double d2, double d3, double d4, double d5, double d6, double d7) {
        double d8 = d3 * d3;
        double d9 = d8 * d3;
        double d10 = 3.0d * d8;
        double d11 = d9 * 2.0d * d4;
        double d12 = ((d11 + ((d10 * d5) + (((-2.0d) * d9) * d5))) - (d10 * d4)) + d4;
        double d13 = d2 * d7;
        double d14 = (d13 * d9) + d12;
        double d15 = d2 * d6;
        return (d15 * d3) + ((((d9 * d15) + d14) - (d13 * d8)) - (((2.0d * d2) * d6) * d8));
    }

    @Override // androidx.constraintlayout.motion.utils.CurveFit
    public void getPos(double d2, double[] dArr) {
        double[] dArr2 = this.f128mT;
        int length = dArr2.length;
        int i2 = 0;
        int length2 = this.f129mY[0].length;
        if (d2 <= dArr2[0]) {
            for (int i3 = 0; i3 < length2; i3++) {
                dArr[i3] = this.f129mY[0][i3];
            }
            return;
        }
        int i4 = length - 1;
        if (d2 >= dArr2[i4]) {
            while (i2 < length2) {
                dArr[i2] = this.f129mY[i4][i2];
                i2++;
            }
            return;
        }
        int i5 = 0;
        while (i5 < i4) {
            if (d2 == this.f128mT[i5]) {
                for (int i6 = 0; i6 < length2; i6++) {
                    dArr[i6] = this.f129mY[i5][i6];
                }
            }
            double[] dArr3 = this.f128mT;
            int i7 = i5 + 1;
            if (d2 < dArr3[i7]) {
                double d3 = dArr3[i7] - dArr3[i5];
                double d4 = (d2 - dArr3[i5]) / d3;
                while (i2 < length2) {
                    double[][] dArr4 = this.f129mY;
                    double d5 = dArr4[i5][i2];
                    double d6 = dArr4[i7][i2];
                    double[][] dArr5 = this.mTangent;
                    dArr[i2] = interpolate(d3, d4, d5, d6, dArr5[i5][i2], dArr5[i7][i2]);
                    i2++;
                }
                return;
            }
            i5 = i7;
        }
    }

    @Override // androidx.constraintlayout.motion.utils.CurveFit
    public void getSlope(double d2, double[] dArr) {
        double d3;
        double[] dArr2 = this.f128mT;
        int length = dArr2.length;
        int length2 = this.f129mY[0].length;
        if (d2 <= dArr2[0]) {
            d3 = dArr2[0];
        } else {
            int i2 = length - 1;
            d3 = d2 >= dArr2[i2] ? dArr2[i2] : d2;
        }
        int i3 = 0;
        while (i3 < length - 1) {
            double[] dArr3 = this.f128mT;
            int i4 = i3 + 1;
            if (d3 <= dArr3[i4]) {
                double d4 = dArr3[i4] - dArr3[i3];
                double d5 = (d3 - dArr3[i3]) / d4;
                for (int i5 = 0; i5 < length2; i5++) {
                    double[][] dArr4 = this.f129mY;
                    double d6 = dArr4[i3][i5];
                    double d7 = dArr4[i4][i5];
                    double[][] dArr5 = this.mTangent;
                    dArr[i5] = diff(d4, d5, d6, d7, dArr5[i3][i5], dArr5[i4][i5]) / d4;
                }
                return;
            }
            i3 = i4;
        }
    }

    @Override // androidx.constraintlayout.motion.utils.CurveFit
    public double[] getTimePoints() {
        return this.f128mT;
    }

    @Override // androidx.constraintlayout.motion.utils.CurveFit
    public double getSlope(double d2, int i2) {
        double d3;
        double[] dArr = this.f128mT;
        int length = dArr.length;
        int i3 = 0;
        if (d2 < dArr[0]) {
            d3 = dArr[0];
        } else {
            int i4 = length - 1;
            d3 = d2 >= dArr[i4] ? dArr[i4] : d2;
        }
        while (i3 < length - 1) {
            double[] dArr2 = this.f128mT;
            int i5 = i3 + 1;
            if (d3 <= dArr2[i5]) {
                double d4 = dArr2[i5] - dArr2[i3];
                double d5 = (d3 - dArr2[i3]) / d4;
                double[][] dArr3 = this.f129mY;
                double d6 = dArr3[i3][i2];
                double d7 = dArr3[i5][i2];
                double[][] dArr4 = this.mTangent;
                return diff(d4, d5, d6, d7, dArr4[i3][i2], dArr4[i5][i2]) / d4;
            }
            i3 = i5;
        }
        return ShadowDrawableWrapper.COS_45;
    }

    @Override // androidx.constraintlayout.motion.utils.CurveFit
    public void getPos(double d2, float[] fArr) {
        double[] dArr = this.f128mT;
        int length = dArr.length;
        int i2 = 0;
        int length2 = this.f129mY[0].length;
        if (d2 <= dArr[0]) {
            for (int i3 = 0; i3 < length2; i3++) {
                fArr[i3] = (float) this.f129mY[0][i3];
            }
            return;
        }
        int i4 = length - 1;
        if (d2 >= dArr[i4]) {
            while (i2 < length2) {
                fArr[i2] = (float) this.f129mY[i4][i2];
                i2++;
            }
            return;
        }
        int i5 = 0;
        while (i5 < i4) {
            if (d2 == this.f128mT[i5]) {
                for (int i6 = 0; i6 < length2; i6++) {
                    fArr[i6] = (float) this.f129mY[i5][i6];
                }
            }
            double[] dArr2 = this.f128mT;
            int i7 = i5 + 1;
            if (d2 < dArr2[i7]) {
                double d3 = dArr2[i7] - dArr2[i5];
                double d4 = (d2 - dArr2[i5]) / d3;
                while (i2 < length2) {
                    double[][] dArr3 = this.f129mY;
                    double d5 = dArr3[i5][i2];
                    double d6 = dArr3[i7][i2];
                    double[][] dArr4 = this.mTangent;
                    fArr[i2] = (float) interpolate(d3, d4, d5, d6, dArr4[i5][i2], dArr4[i7][i2]);
                    i2++;
                }
                return;
            }
            i5 = i7;
        }
    }

    @Override // androidx.constraintlayout.motion.utils.CurveFit
    public double getPos(double d2, int i2) {
        double[] dArr = this.f128mT;
        int length = dArr.length;
        int i3 = 0;
        if (d2 <= dArr[0]) {
            return this.f129mY[0][i2];
        }
        int i4 = length - 1;
        if (d2 >= dArr[i4]) {
            return this.f129mY[i4][i2];
        }
        while (i3 < i4) {
            double[] dArr2 = this.f128mT;
            if (d2 == dArr2[i3]) {
                return this.f129mY[i3][i2];
            }
            int i5 = i3 + 1;
            if (d2 < dArr2[i5]) {
                double d3 = dArr2[i5] - dArr2[i3];
                double d4 = (d2 - dArr2[i3]) / d3;
                double[][] dArr3 = this.f129mY;
                double d5 = dArr3[i3][i2];
                double d6 = dArr3[i5][i2];
                double[][] dArr4 = this.mTangent;
                return interpolate(d3, d4, d5, d6, dArr4[i3][i2], dArr4[i5][i2]);
            }
            i3 = i5;
        }
        return ShadowDrawableWrapper.COS_45;
    }
}
