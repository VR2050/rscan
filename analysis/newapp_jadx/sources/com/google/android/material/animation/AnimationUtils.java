package com.google.android.material.animation;

import android.animation.TimeInterpolator;
import android.view.animation.DecelerateInterpolator;
import android.view.animation.LinearInterpolator;
import androidx.annotation.FloatRange;
import androidx.annotation.RestrictTo;
import androidx.interpolator.view.animation.FastOutLinearInInterpolator;
import androidx.interpolator.view.animation.FastOutSlowInInterpolator;
import androidx.interpolator.view.animation.LinearOutSlowInInterpolator;
import p005b.p131d.p132a.p133a.C1499a;

@RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
/* loaded from: classes2.dex */
public class AnimationUtils {
    public static final TimeInterpolator LINEAR_INTERPOLATOR = new LinearInterpolator();
    public static final TimeInterpolator FAST_OUT_SLOW_IN_INTERPOLATOR = new FastOutSlowInInterpolator();
    public static final TimeInterpolator FAST_OUT_LINEAR_IN_INTERPOLATOR = new FastOutLinearInInterpolator();
    public static final TimeInterpolator LINEAR_OUT_SLOW_IN_INTERPOLATOR = new LinearOutSlowInInterpolator();
    public static final TimeInterpolator DECELERATE_INTERPOLATOR = new DecelerateInterpolator();

    public static float lerp(float f2, float f3, float f4) {
        return C1499a.m627m(f3, f2, f4, f2);
    }

    public static int lerp(int i2, int i3, float f2) {
        return Math.round(f2 * (i3 - i2)) + i2;
    }

    public static float lerp(float f2, float f3, @FloatRange(from = 0.0d, m110to = 1.0d) float f4, @FloatRange(from = 0.0d, m110to = 1.0d) float f5, @FloatRange(from = 0.0d, m110to = 1.0d) float f6) {
        return f6 < f4 ? f2 : f6 > f5 ? f3 : lerp(f2, f3, (f6 - f4) / (f5 - f4));
    }
}
