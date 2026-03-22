package com.youth.banner.indicator;

import android.content.Context;
import android.graphics.Canvas;
import android.util.AttributeSet;

/* loaded from: classes2.dex */
public class CircleIndicator extends BaseIndicator {
    private int mNormalRadius;
    private int mSelectedRadius;
    private int maxRadius;

    public CircleIndicator(Context context) {
        this(context, null);
    }

    @Override // android.view.View
    public void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        int indicatorSize = this.config.getIndicatorSize();
        if (indicatorSize <= 1) {
            return;
        }
        float f2 = 0.0f;
        int i2 = 0;
        while (i2 < indicatorSize) {
            this.mPaint.setColor(this.config.getCurrentPosition() == i2 ? this.config.getSelectedColor() : this.config.getNormalColor());
            int selectedWidth = this.config.getCurrentPosition() == i2 ? this.config.getSelectedWidth() : this.config.getNormalWidth();
            float f3 = this.config.getCurrentPosition() == i2 ? this.mSelectedRadius : this.mNormalRadius;
            canvas.drawCircle(f2 + f3, this.maxRadius, f3, this.mPaint);
            f2 += this.config.getIndicatorSpace() + selectedWidth;
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
        this.mNormalRadius = this.config.getNormalWidth() / 2;
        int selectedWidth = this.config.getSelectedWidth() / 2;
        this.mSelectedRadius = selectedWidth;
        this.maxRadius = Math.max(selectedWidth, this.mNormalRadius);
        int i4 = indicatorSize - 1;
        setMeasuredDimension((this.config.getNormalWidth() * i4) + this.config.getSelectedWidth() + (this.config.getIndicatorSpace() * i4), Math.max(this.config.getNormalWidth(), this.config.getSelectedWidth()));
    }

    public CircleIndicator(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 0);
    }

    public CircleIndicator(Context context, AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        this.mNormalRadius = this.config.getNormalWidth() / 2;
        this.mSelectedRadius = this.config.getSelectedWidth() / 2;
    }
}
