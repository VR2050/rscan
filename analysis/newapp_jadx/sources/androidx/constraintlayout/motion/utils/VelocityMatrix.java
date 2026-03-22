package androidx.constraintlayout.motion.utils;

import androidx.constraintlayout.motion.widget.KeyCycleOscillator;
import androidx.constraintlayout.motion.widget.SplineSet;

/* loaded from: classes.dex */
public class VelocityMatrix {
    private static String TAG = "VelocityMatrix";
    public float mDRotate;
    public float mDScaleX;
    public float mDScaleY;
    public float mDTranslateX;
    public float mDTranslateY;
    public float mRotate;

    public void applyTransform(float f2, float f3, int i2, int i3, float[] fArr) {
        float f4 = fArr[0];
        float f5 = fArr[1];
        float f6 = (f3 - 0.5f) * 2.0f;
        float f7 = f4 + this.mDTranslateX;
        float f8 = f5 + this.mDTranslateY;
        float f9 = (this.mDScaleX * (f2 - 0.5f) * 2.0f) + f7;
        float f10 = (this.mDScaleY * f6) + f8;
        float radians = (float) Math.toRadians(this.mRotate);
        float radians2 = (float) Math.toRadians(this.mDRotate);
        double d2 = radians;
        double d3 = i3 * f6;
        float sin = (((float) ((Math.sin(d2) * ((-i2) * r7)) - (Math.cos(d2) * d3))) * radians2) + f9;
        float cos = (radians2 * ((float) ((Math.cos(d2) * (i2 * r7)) - (Math.sin(d2) * d3)))) + f10;
        fArr[0] = sin;
        fArr[1] = cos;
    }

    public void clear() {
        this.mDRotate = 0.0f;
        this.mDTranslateY = 0.0f;
        this.mDTranslateX = 0.0f;
        this.mDScaleY = 0.0f;
        this.mDScaleX = 0.0f;
    }

    public void setRotationVelocity(SplineSet splineSet, float f2) {
        if (splineSet != null) {
            this.mDRotate = splineSet.getSlope(f2);
            this.mRotate = splineSet.get(f2);
        }
    }

    public void setScaleVelocity(SplineSet splineSet, SplineSet splineSet2, float f2) {
        if (splineSet != null) {
            this.mDScaleX = splineSet.getSlope(f2);
        }
        if (splineSet2 != null) {
            this.mDScaleY = splineSet2.getSlope(f2);
        }
    }

    public void setTranslationVelocity(SplineSet splineSet, SplineSet splineSet2, float f2) {
        if (splineSet != null) {
            this.mDTranslateX = splineSet.getSlope(f2);
        }
        if (splineSet2 != null) {
            this.mDTranslateY = splineSet2.getSlope(f2);
        }
    }

    public void setRotationVelocity(KeyCycleOscillator keyCycleOscillator, float f2) {
        if (keyCycleOscillator != null) {
            this.mDRotate = keyCycleOscillator.getSlope(f2);
        }
    }

    public void setScaleVelocity(KeyCycleOscillator keyCycleOscillator, KeyCycleOscillator keyCycleOscillator2, float f2) {
        if (keyCycleOscillator == null && keyCycleOscillator2 == null) {
            return;
        }
        if (keyCycleOscillator == null) {
            this.mDScaleX = keyCycleOscillator.getSlope(f2);
        }
        if (keyCycleOscillator2 == null) {
            this.mDScaleY = keyCycleOscillator2.getSlope(f2);
        }
    }

    public void setTranslationVelocity(KeyCycleOscillator keyCycleOscillator, KeyCycleOscillator keyCycleOscillator2, float f2) {
        if (keyCycleOscillator != null) {
            this.mDTranslateX = keyCycleOscillator.getSlope(f2);
        }
        if (keyCycleOscillator2 != null) {
            this.mDTranslateY = keyCycleOscillator2.getSlope(f2);
        }
    }
}
