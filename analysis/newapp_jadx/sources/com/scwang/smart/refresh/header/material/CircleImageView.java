package com.scwang.smart.refresh.header.material;

import android.annotation.SuppressLint;
import android.content.Context;
import android.graphics.drawable.ShapeDrawable;
import android.graphics.drawable.shapes.OvalShape;
import android.widget.ImageView;
import androidx.annotation.ColorInt;

@SuppressLint({"ViewConstructor", "AppCompatCustomView"})
/* loaded from: classes2.dex */
public class CircleImageView extends ImageView {

    /* renamed from: c */
    public int f10501c;

    public CircleImageView(Context context, int i2) {
        super(context);
        float f2 = getResources().getDisplayMetrics().density;
        this.f10501c = (int) (3.5f * f2);
        ShapeDrawable shapeDrawable = new ShapeDrawable(new OvalShape());
        setElevation(f2 * 4.0f);
        shapeDrawable.getPaint().setColor(i2);
        setBackground(shapeDrawable);
    }

    @Override // android.widget.ImageView, android.view.View
    public void onMeasure(int i2, int i3) {
        super.onMeasure(i2, i3);
    }

    @Override // android.view.View
    public void setBackgroundColor(@ColorInt int i2) {
        if (getBackground() instanceof ShapeDrawable) {
            ((ShapeDrawable) getBackground()).getPaint().setColor(i2);
        }
    }
}
