package com.jbzd.media.movecartoons.view.text;

import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.drawable.Drawable;
import android.text.style.DynamicDrawableSpan;
import androidx.annotation.NonNull;

/* loaded from: classes2.dex */
public class TextDrawableCenterSpan extends DynamicDrawableSpan {
    private Drawable drawable;

    public TextDrawableCenterSpan(@NonNull Drawable drawable) {
        this.drawable = drawable;
    }

    @Override // android.text.style.DynamicDrawableSpan, android.text.style.ReplacementSpan
    public void draw(@NonNull Canvas canvas, CharSequence charSequence, int i2, int i3, float f2, int i4, int i5, int i6, @NonNull Paint paint) {
        Drawable drawable = getDrawable();
        canvas.save();
        canvas.translate(f2, (i6 - drawable.getBounds().bottom) * 0.5f);
        drawable.draw(canvas);
        canvas.restore();
    }

    @Override // android.text.style.DynamicDrawableSpan
    public Drawable getDrawable() {
        return this.drawable;
    }
}
