package com.facebook.react.views.text;

import android.R;
import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;

/* JADX INFO: loaded from: classes.dex */
public final class a {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final a f8044a = new a();

    private a() {
    }

    private final ColorStateList a(Context context, int i3) {
        TypedArray typedArrayObtainStyledAttributes = context.getTheme().obtainStyledAttributes(new int[]{i3});
        t2.j.e(typedArrayObtainStyledAttributes, "obtainStyledAttributes(...)");
        return typedArrayObtainStyledAttributes.getColorStateList(0);
    }

    public static final ColorStateList b(Context context) {
        t2.j.f(context, "context");
        return f8044a.a(context, R.attr.textColor);
    }

    public static final int c(Context context) {
        t2.j.f(context, "context");
        ColorStateList colorStateListA = f8044a.a(context, R.attr.textColorHighlight);
        if (colorStateListA != null) {
            return colorStateListA.getDefaultColor();
        }
        return 0;
    }

    public static final ColorStateList d(Context context) {
        t2.j.f(context, "context");
        return f8044a.a(context, R.attr.textColorHint);
    }
}
