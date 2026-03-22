package com.youth.banner.indicator;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.RectF;
import android.util.AttributeSet;

/* loaded from: classes2.dex */
public class RectangleIndicator extends BaseIndicator {
    public RectF rectF;

    public RectangleIndicator(Context context) {
        this(context, null);
    }

    @Override // android.view.View
    public void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        int indicatorSize = this.config.getIndicatorSize();
        if (indicatorSize <= 1) {
            return;
        }
        int i2 = 0;
        float f2 = 0.0f;
        while (i2 < indicatorSize) {
            this.mPaint.setColor(this.config.getCurrentPosition() == i2 ? this.config.getSelectedColor() : this.config.getNormalColor());
            this.rectF.set(f2, 0.0f, (this.config.getCurrentPosition() == i2 ? this.config.getSelectedWidth() : this.config.getNormalWidth()) + f2, this.config.getHeight());
            f2 += this.config.getIndicatorSpace() + r4;
            canvas.drawRoundRect(this.rectF, this.config.getRadius(), this.config.getRadius(), this.mPaint);
            i2++;
        }
    }

    @Override // android.view.View
    public void onMeasure(int i2, int i3) {
        super.onMeasure(i2, i3);
        int indicatorSize = this.config.getIndicatorSize();
        if (indicatorSize <= 1) {
            return;
        }
        int i4 = indicatorSize - 1;
        setMeasuredDimension(this.config.getSelectedWidth() + (this.config.getNormalWidth() * i4) + (this.config.getIndicatorSpace() * i4), this.config.getHeight());
    }

    public RectangleIndicator(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 0);
    }

    public RectangleIndicator(Context context, AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        this.rectF = new RectF();
    }
}
