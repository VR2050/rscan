package androidx.constraintlayout.motion.utils;

import com.google.android.material.shadow.ShadowDrawableWrapper;
import java.util.Arrays;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public class Oscillator {
    public static final int BOUNCE = 6;
    public static final int COS_WAVE = 5;
    public static final int REVERSE_SAW_WAVE = 4;
    public static final int SAW_WAVE = 3;
    public static final int SIN_WAVE = 0;
    public static final int SQUARE_WAVE = 1;
    public static String TAG = "Oscillator";
    public static final int TRIANGLE_WAVE = 2;
    public double[] mArea;
    public int mType;
    public float[] mPeriod = new float[0];
    public double[] mPosition = new double[0];
    public double PI2 = 6.283185307179586d;
    private boolean mNormalized = false;

    public void addPoint(double d2, float f2) {
        int length = this.mPeriod.length + 1;
        int binarySearch = Arrays.binarySearch(this.mPosition, d2);
        if (binarySearch < 0) {
            binarySearch = (-binarySearch) - 1;
        }
        this.mPosition = Arrays.copyOf(this.mPosition, length);
        this.mPeriod = Arrays.copyOf(this.mPeriod, length);
        this.mArea = new double[length];
        double[] dArr = this.mPosition;
        System.arraycopy(dArr, binarySearch, dArr, binarySearch + 1, (length - binarySearch) - 1);
        this.mPosition[binarySearch] = d2;
        this.mPeriod[binarySearch] = f2;
        this.mNormalized = false;
    }

    public double getDP(double d2) {
        if (d2 <= ShadowDrawableWrapper.COS_45) {
            d2 = 1.0E-5d;
        } else if (d2 >= 1.0d) {
            d2 = 0.999999d;
        }
        int binarySearch = Arrays.binarySearch(this.mPosition, d2);
        if (binarySearch > 0 || binarySearch == 0) {
            return ShadowDrawableWrapper.COS_45;
        }
        int i2 = (-binarySearch) - 1;
        float[] fArr = this.mPeriod;
        int i3 = i2 - 1;
        double d3 = fArr[i2] - fArr[i3];
        double[] dArr = this.mPosition;
        double d4 = d3 / (dArr[i2] - dArr[i3]);
        return (fArr[i3] - (d4 * dArr[i3])) + (d2 * d4);
    }

    public double getP(double d2) {
        if (d2 < ShadowDrawableWrapper.COS_45) {
            d2 = 0.0d;
        } else if (d2 > 1.0d) {
            d2 = 1.0d;
        }
        int binarySearch = Arrays.binarySearch(this.mPosition, d2);
        if (binarySearch > 0) {
            return 1.0d;
        }
        if (binarySearch == 0) {
            return ShadowDrawableWrapper.COS_45;
        }
        int i2 = (-binarySearch) - 1;
        float[] fArr = this.mPeriod;
        int i3 = i2 - 1;
        double d3 = fArr[i2] - fArr[i3];
        double[] dArr = this.mPosition;
        double d4 = d3 / (dArr[i2] - dArr[i3]);
        return ((((d2 * d2) - (dArr[i3] * dArr[i3])) * d4) / 2.0d) + ((d2 - dArr[i3]) * (fArr[i3] - (dArr[i3] * d4))) + this.mArea[i3];
    }

    public double getSlope(double d2) {
        switch (this.mType) {
            case 1:
                return ShadowDrawableWrapper.COS_45;
            case 2:
                return Math.signum((((getP(d2) * 4.0d) + 3.0d) % 4.0d) - 2.0d) * getDP(d2) * 4.0d;
            case 3:
                return getDP(d2) * 2.0d;
            case 4:
                return (-getDP(d2)) * 2.0d;
            case 5:
                return Math.sin(getP(d2) * this.PI2) * getDP(d2) * (-this.PI2);
            case 6:
                return ((((getP(d2) * 4.0d) + 2.0d) % 4.0d) - 2.0d) * getDP(d2) * 4.0d;
            default:
                return Math.cos(getP(d2) * this.PI2) * getDP(d2) * this.PI2;
        }
    }

    public double getValue(double d2) {
        double abs;
        switch (this.mType) {
            case 1:
                return Math.signum(0.5d - (getP(d2) % 1.0d));
            case 2:
                abs = Math.abs((((getP(d2) * 4.0d) + 1.0d) % 4.0d) - 2.0d);
                break;
            case 3:
                return (((getP(d2) * 2.0d) + 1.0d) % 2.0d) - 1.0d;
            case 4:
                abs = ((getP(d2) * 2.0d) + 1.0d) % 2.0d;
                break;
            case 5:
                return Math.cos(getP(d2) * this.PI2);
            case 6:
                double abs2 = 1.0d - Math.abs(((getP(d2) * 4.0d) % 4.0d) - 2.0d);
                abs = abs2 * abs2;
                break;
            default:
                return Math.sin(getP(d2) * this.PI2);
        }
        return 1.0d - abs;
    }

    public void normalize() {
        double d2 = 0.0d;
        int i2 = 0;
        while (true) {
            if (i2 >= this.mPeriod.length) {
                break;
            }
            d2 += r7[i2];
            i2++;
        }
        double d3 = 0.0d;
        int i3 = 1;
        while (true) {
            float[] fArr = this.mPeriod;
            if (i3 >= fArr.length) {
                break;
            }
            int i4 = i3 - 1;
            float f2 = (fArr[i4] + fArr[i3]) / 2.0f;
            double[] dArr = this.mPosition;
            d3 += (dArr[i3] - dArr[i4]) * f2;
            i3++;
        }
        int i5 = 0;
        while (true) {
            float[] fArr2 = this.mPeriod;
            if (i5 >= fArr2.length) {
                break;
            }
            fArr2[i5] = (float) (fArr2[i5] * (d2 / d3));
            i5++;
        }
        this.mArea[0] = 0.0d;
        int i6 = 1;
        while (true) {
            float[] fArr3 = this.mPeriod;
            if (i6 >= fArr3.length) {
                this.mNormalized = true;
                return;
            }
            int i7 = i6 - 1;
            float f3 = (fArr3[i7] + fArr3[i6]) / 2.0f;
            double[] dArr2 = this.mPosition;
            double d4 = dArr2[i6] - dArr2[i7];
            double[] dArr3 = this.mArea;
            dArr3[i6] = (d4 * f3) + dArr3[i7];
            i6++;
        }
    }

    public void setType(int i2) {
        this.mType = i2;
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("pos =");
        m586H.append(Arrays.toString(this.mPosition));
        m586H.append(" period=");
        m586H.append(Arrays.toString(this.mPeriod));
        return m586H.toString();
    }
}
