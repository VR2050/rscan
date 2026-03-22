package com.youth.banner.transformer;

import android.view.View;
import androidx.annotation.NonNull;

/* loaded from: classes2.dex */
public class AlphaPageTransformer extends BasePageTransformer {
    private static final float DEFAULT_MIN_ALPHA = 0.5f;
    private float mMinAlpha;

    public AlphaPageTransformer() {
        this.mMinAlpha = 0.5f;
    }

    @Override // androidx.viewpager2.widget.ViewPager2.PageTransformer
    public void transformPage(@NonNull View view, float f2) {
        view.setScaleX(0.999f);
        if (f2 < -1.0f) {
            view.setAlpha(this.mMinAlpha);
            return;
        }
        if (f2 > 1.0f) {
            view.setAlpha(this.mMinAlpha);
            return;
        }
        if (f2 < 0.0f) {
            float f3 = this.mMinAlpha;
            view.setAlpha(((f2 + 1.0f) * (1.0f - f3)) + f3);
        } else {
            float f4 = this.mMinAlpha;
            view.setAlpha(((1.0f - f2) * (1.0f - f4)) + f4);
        }
    }

    public AlphaPageTransformer(float f2) {
        this.mMinAlpha = 0.5f;
        this.mMinAlpha = f2;
    }
}
