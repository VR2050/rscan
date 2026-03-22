package com.jbzd.media.movecartoons.view.text;

import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.text.TextPaint;
import androidx.annotation.ColorInt;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import com.jbzd.media.movecartoons.MyApp;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

/* loaded from: classes2.dex */
public class TextDrawable extends Drawable {
    private Paint mBgPaint;
    private RectF mRect = new RectF();
    private String mText;
    private TextPaint mTextPaint;

    public TextDrawable(@ColorInt int i2, String str, @ColorInt int i3, float f2) {
        this.mText = str;
        if (i2 != 0) {
            Paint paint = new Paint(1);
            this.mBgPaint = paint;
            paint.setColor(i2);
            this.mBgPaint.setStyle(Paint.Style.FILL);
        }
        TextPaint textPaint = new TextPaint(1);
        this.mTextPaint = textPaint;
        textPaint.setColor(i3);
        this.mTextPaint.setTextSize(f2);
        this.mTextPaint.setStyle(Paint.Style.FILL);
        this.mTextPaint.setTypeface(Typeface.DEFAULT);
        getBounds().set(0, 0, (int) (this.mTextPaint.measureText(str) + (C2354n.m2425R(MyApp.f9894i, 4.0f) * 2)), this.mTextPaint.getFontMetricsInt().bottom - this.mTextPaint.getFontMetricsInt().top);
    }

    private void drawBg(Canvas canvas) {
        if (this.mBgPaint == null) {
            return;
        }
        this.mRect.set(getBounds());
        float m2425R = C2354n.m2425R(MyApp.f9894i, 4.0f);
        canvas.drawRoundRect(this.mRect, m2425R, m2425R, this.mBgPaint);
    }

    private void drawText(Canvas canvas) {
        Rect bounds = getBounds();
        Paint.FontMetrics fontMetrics = new Paint.FontMetrics();
        this.mTextPaint.getFontMetrics(fontMetrics);
        float measureText = ((bounds.right - bounds.left) - this.mTextPaint.measureText(this.mText)) / 2.0f;
        float f2 = fontMetrics.bottom;
        float f3 = fontMetrics.top;
        canvas.drawText(this.mText, measureText, (((bounds.bottom - bounds.top) - (f2 - f3)) / 2.0f) - f3, this.mTextPaint);
    }

    @Override // android.graphics.drawable.Drawable
    public void draw(@NonNull Canvas canvas) {
        drawBg(canvas);
        drawText(canvas);
    }

    @Override // android.graphics.drawable.Drawable
    public int getOpacity() {
        return -3;
    }

    @Override // android.graphics.drawable.Drawable
    public void setAlpha(int i2) {
        Paint paint = this.mBgPaint;
        if (paint != null) {
            paint.setAlpha(i2);
        }
        this.mTextPaint.setAlpha(i2);
    }

    @Override // android.graphics.drawable.Drawable
    public void setColorFilter(@Nullable ColorFilter colorFilter) {
        Paint paint = this.mBgPaint;
        if (paint != null) {
            paint.setColorFilter(colorFilter);
        }
        this.mTextPaint.setColorFilter(colorFilter);
    }
}
