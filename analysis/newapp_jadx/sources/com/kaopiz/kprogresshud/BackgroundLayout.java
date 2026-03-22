package com.kaopiz.kprogresshud;

import android.content.Context;
import android.graphics.drawable.GradientDrawable;
import android.util.AttributeSet;
import android.widget.LinearLayout;

/* loaded from: classes2.dex */
public class BackgroundLayout extends LinearLayout {

    /* renamed from: c */
    public float f10149c;

    /* renamed from: e */
    public int f10150e;

    public BackgroundLayout(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        m4519a(getContext().getResources().getColor(R$color.kprogresshud_default_color), this.f10149c);
    }

    /* renamed from: a */
    public final void m4519a(int i2, float f2) {
        GradientDrawable gradientDrawable = new GradientDrawable();
        gradientDrawable.setShape(0);
        gradientDrawable.setColor(i2);
        gradientDrawable.setCornerRadius(f2);
        setBackground(gradientDrawable);
    }
}
