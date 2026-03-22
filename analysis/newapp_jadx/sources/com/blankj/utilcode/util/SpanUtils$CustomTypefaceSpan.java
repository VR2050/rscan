package com.blankj.utilcode.util;

import android.annotation.SuppressLint;
import android.graphics.Paint;
import android.graphics.Typeface;
import android.text.TextPaint;
import android.text.style.TypefaceSpan;

@SuppressLint({"ParcelCreator"})
/* loaded from: classes.dex */
public class SpanUtils$CustomTypefaceSpan extends TypefaceSpan {
    /* renamed from: b */
    public final void m3883b(Paint paint, Typeface typeface) {
        Typeface typeface2 = paint.getTypeface();
        if (typeface2 != null) {
            typeface2.getStyle();
        }
        throw null;
    }

    @Override // android.text.style.TypefaceSpan, android.text.style.CharacterStyle
    public void updateDrawState(TextPaint textPaint) {
        m3883b(textPaint, null);
    }

    @Override // android.text.style.TypefaceSpan, android.text.style.MetricAffectingSpan
    public void updateMeasureState(TextPaint textPaint) {
        m3883b(textPaint, null);
    }
}
