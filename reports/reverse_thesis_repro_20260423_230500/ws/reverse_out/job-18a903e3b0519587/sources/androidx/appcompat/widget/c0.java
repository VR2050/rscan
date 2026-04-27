package androidx.appcompat.widget;

import android.R;
import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.graphics.Color;
import android.util.Log;
import android.util.TypedValue;
import android.view.View;

/* JADX INFO: loaded from: classes.dex */
public abstract class c0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private static final ThreadLocal f4036a = new ThreadLocal();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    static final int[] f4037b = {-16842910};

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    static final int[] f4038c = {R.attr.state_focused};

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    static final int[] f4039d = {R.attr.state_activated};

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    static final int[] f4040e = {R.attr.state_pressed};

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    static final int[] f4041f = {R.attr.state_checked};

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    static final int[] f4042g = {R.attr.state_selected};

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    static final int[] f4043h = {-16842919, -16842908};

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    static final int[] f4044i = new int[0];

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private static final int[] f4045j = new int[1];

    public static void a(View view, Context context) {
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(d.j.f9139y0);
        try {
            if (!typedArrayObtainStyledAttributes.hasValue(d.j.f8958D0)) {
                Log.e("ThemeUtils", "View " + view.getClass() + " is an AppCompat widget that can only be used with a Theme.AppCompat theme (or descendant).");
            }
        } finally {
            typedArrayObtainStyledAttributes.recycle();
        }
    }

    public static int b(Context context, int i3) {
        ColorStateList colorStateListE = e(context, i3);
        if (colorStateListE != null && colorStateListE.isStateful()) {
            return colorStateListE.getColorForState(f4037b, colorStateListE.getDefaultColor());
        }
        TypedValue typedValueF = f();
        context.getTheme().resolveAttribute(R.attr.disabledAlpha, typedValueF, true);
        return d(context, i3, typedValueF.getFloat());
    }

    public static int c(Context context, int i3) {
        int[] iArr = f4045j;
        iArr[0] = i3;
        g0 g0VarT = g0.t(context, null, iArr);
        try {
            return g0VarT.b(0, 0);
        } finally {
            g0VarT.w();
        }
    }

    static int d(Context context, int i3, float f3) {
        return androidx.core.graphics.a.g(c(context, i3), Math.round(Color.alpha(r0) * f3));
    }

    public static ColorStateList e(Context context, int i3) {
        int[] iArr = f4045j;
        iArr[0] = i3;
        g0 g0VarT = g0.t(context, null, iArr);
        try {
            return g0VarT.c(0);
        } finally {
            g0VarT.w();
        }
    }

    private static TypedValue f() {
        ThreadLocal threadLocal = f4036a;
        TypedValue typedValue = (TypedValue) threadLocal.get();
        if (typedValue != null) {
            return typedValue;
        }
        TypedValue typedValue2 = new TypedValue();
        threadLocal.set(typedValue2);
        return typedValue2;
    }
}
