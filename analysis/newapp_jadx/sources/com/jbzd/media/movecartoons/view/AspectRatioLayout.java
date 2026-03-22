package com.jbzd.media.movecartoons.view;

import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.view.View;
import android.widget.RelativeLayout;
import androidx.annotation.AttrRes;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import androidx.annotation.StyleRes;
import com.jbzd.media.movecartoons.R$styleable;

/* loaded from: classes2.dex */
public class AspectRatioLayout extends RelativeLayout {
    private static final String TAG = "AspectRatioLayout";
    private float heightRatio;
    private float widthRatio;

    public AspectRatioLayout(@NonNull Context context) {
        super(context);
        init(context, null, 0, 0);
    }

    private void init(@NonNull Context context, @Nullable AttributeSet attributeSet, @AttrRes int i2, @StyleRes int i3) {
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.AspectRatioLayout, i2, i3);
        this.widthRatio = obtainStyledAttributes.getFloat(1, 1.0f);
        this.heightRatio = obtainStyledAttributes.getFloat(0, 1.0f);
        obtainStyledAttributes.recycle();
    }

    public float getAspectRatio() {
        return this.widthRatio / this.heightRatio;
    }

    public float getHeightRatio() {
        return this.heightRatio;
    }

    public float getWidthRatio() {
        return this.widthRatio;
    }

    @Override // android.widget.RelativeLayout, android.view.View
    public void onMeasure(int i2, int i3) {
        int size = View.MeasureSpec.getSize(i2);
        int size2 = View.MeasureSpec.getSize(i3);
        int mode = View.MeasureSpec.getMode(i2);
        int mode2 = View.MeasureSpec.getMode(i3);
        if (mode == 1073741824) {
            size2 = Math.round((this.heightRatio / this.widthRatio) * size);
            mode2 = 1073741824;
        } else if (mode2 == 1073741824) {
            size = Math.round((this.widthRatio / this.heightRatio) * size2);
            mode = 1073741824;
        }
        super.onMeasure(View.MeasureSpec.makeMeasureSpec(size, mode), View.MeasureSpec.makeMeasureSpec(size2, mode2));
    }

    public void setAspectRatio(float f2, float f3) {
        this.widthRatio = f2;
        this.heightRatio = f3;
        requestLayout();
    }

    public AspectRatioLayout(@NonNull Context context, @Nullable AttributeSet attributeSet) {
        super(context, attributeSet);
        init(context, attributeSet, 0, 0);
    }

    public AspectRatioLayout(@NonNull Context context, @Nullable AttributeSet attributeSet, @AttrRes int i2) {
        super(context, attributeSet, i2);
        init(context, attributeSet, i2, 0);
    }

    @RequiresApi(api = 21)
    public AspectRatioLayout(@NonNull Context context, @Nullable AttributeSet attributeSet, @AttrRes int i2, @StyleRes int i3) {
        super(context, attributeSet, i2, i3);
        init(context, attributeSet, i2, i3);
    }
}
