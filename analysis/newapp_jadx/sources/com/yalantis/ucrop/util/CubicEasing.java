package com.yalantis.ucrop.util;

/* loaded from: classes2.dex */
public final class CubicEasing {
    public static float easeIn(float f2, float f3, float f4, float f5) {
        float f6 = f2 / f5;
        return (f4 * f6 * f6 * f6) + f3;
    }

    public static float easeInOut(float f2, float f3, float f4, float f5) {
        float f6 = f2 / (f5 / 2.0f);
        float f7 = f4 / 2.0f;
        if (f6 < 1.0f) {
            return (f7 * f6 * f6 * f6) + f3;
        }
        float f8 = f6 - 2.0f;
        return (((f8 * f8 * f8) + 2.0f) * f7) + f3;
    }

    public static float easeOut(float f2, float f3, float f4, float f5) {
        float f6 = (f2 / f5) - 1.0f;
        return (((f6 * f6 * f6) + 1.0f) * f4) + f3;
    }
}
