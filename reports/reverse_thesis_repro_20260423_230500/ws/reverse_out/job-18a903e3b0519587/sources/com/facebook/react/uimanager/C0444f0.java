package com.facebook.react.uimanager;

import android.util.DisplayMetrics;
import android.util.TypedValue;

/* JADX INFO: renamed from: com.facebook.react.uimanager.f0, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0444f0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final C0444f0 f7603a = new C0444f0();

    private C0444f0() {
    }

    public static final float c() {
        return C0478x.d().density;
    }

    public static final float f(float f3) {
        if (Float.isNaN(f3)) {
            return Float.NaN;
        }
        return f3 / C0478x.d().density;
    }

    public static final float g(double d3) {
        return h((float) d3);
    }

    public static final float h(float f3) {
        if (Float.isNaN(f3)) {
            return Float.NaN;
        }
        return TypedValue.applyDimension(1, f3, C0478x.d());
    }

    public static final float i(double d3) {
        return l((float) d3, 0.0f, 2, null);
    }

    public static final float j(float f3) {
        return l(f3, 0.0f, 2, null);
    }

    public static final float k(float f3, float f4) {
        if (Float.isNaN(f3)) {
            return Float.NaN;
        }
        DisplayMetrics displayMetricsD = C0478x.d();
        float fApplyDimension = TypedValue.applyDimension(2, f3, displayMetricsD);
        return f4 >= 1.0f ? Math.min(fApplyDimension, f3 * displayMetricsD.density * f4) : fApplyDimension;
    }

    public static /* synthetic */ float l(float f3, float f4, int i3, Object obj) {
        if ((i3 & 2) != 0) {
            f4 = Float.NaN;
        }
        return k(f3, f4);
    }

    public final float a(double d3) {
        return h((float) d3);
    }

    public final float b(float f3) {
        return h(f3);
    }

    public final float d(float f3) {
        return f(f3);
    }

    public final float e(int i3) {
        return f(i3);
    }
}
