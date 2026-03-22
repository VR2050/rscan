package com.jbzd.media.movecartoons.view.image;

import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.view.View;
import android.widget.ImageView;
import androidx.appcompat.widget.AppCompatImageView;
import com.jbzd.media.movecartoons.R$styleable;

/* loaded from: classes2.dex */
public class ScaleImageView extends AppCompatImageView {
    private int scaleX;
    private int scaleY;

    public ScaleImageView(Context context) {
        super(context);
        this.scaleX = 0;
        this.scaleY = 0;
    }

    private void init(Context context, AttributeSet attributeSet) {
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.ScaleView);
        int i2 = (int) ((context.getResources().getDisplayMetrics().density * 2.0f) + 0.5f);
        this.scaleX = obtainStyledAttributes.getDimensionPixelOffset(1, i2);
        this.scaleY = obtainStyledAttributes.getDimensionPixelOffset(0, i2);
        obtainStyledAttributes.recycle();
    }

    @Override // android.widget.ImageView, android.view.View
    public void onMeasure(int i2, int i3) {
        setMeasuredDimension(ImageView.getDefaultSize(0, i2), ImageView.getDefaultSize(0, i3));
        int measuredWidth = getMeasuredWidth();
        super.onMeasure(View.MeasureSpec.makeMeasureSpec(measuredWidth, 1073741824), View.MeasureSpec.makeMeasureSpec((measuredWidth * this.scaleY) / this.scaleX, 1073741824));
    }

    public void setAspectRatio(int i2, int i3) {
        this.scaleX = i2;
        this.scaleY = i3;
        requestLayout();
    }

    public ScaleImageView(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.scaleX = 0;
        this.scaleY = 0;
        init(context, attributeSet);
    }

    public ScaleImageView(Context context, AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
        this.scaleX = 0;
        this.scaleY = 0;
        init(context, attributeSet);
    }
}
