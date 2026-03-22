package com.youth.banner.transformer;

import android.view.View;
import androidx.annotation.NonNull;

/* loaded from: classes2.dex */
public class RotateUpPageTransformer extends BasePageTransformer {
    private static final float DEFAULT_MAX_ROTATE = 15.0f;
    private float mMaxRotate;

    public RotateUpPageTransformer() {
        this.mMaxRotate = DEFAULT_MAX_ROTATE;
    }

    @Override // androidx.viewpager2.widget.ViewPager2.PageTransformer
    public void transformPage(@NonNull View view, float f2) {
        if (f2 < -1.0f) {
            view.setRotation(this.mMaxRotate);
            view.setPivotX(view.getWidth());
            view.setPivotY(0.0f);
            return;
        }
        if (f2 > 1.0f) {
            view.setRotation(-this.mMaxRotate);
            view.setPivotX(0.0f);
            view.setPivotY(0.0f);
        } else {
            if (f2 < 0.0f) {
                view.setPivotX((((-f2) * 0.5f) + 0.5f) * view.getWidth());
                view.setPivotY(0.0f);
                view.setRotation((-this.mMaxRotate) * f2);
                return;
            }
            view.setPivotX((1.0f - f2) * view.getWidth() * 0.5f);
            view.setPivotY(0.0f);
            view.setRotation((-this.mMaxRotate) * f2);
        }
    }

    public RotateUpPageTransformer(float f2) {
        this.mMaxRotate = DEFAULT_MAX_ROTATE;
        this.mMaxRotate = f2;
    }
}
