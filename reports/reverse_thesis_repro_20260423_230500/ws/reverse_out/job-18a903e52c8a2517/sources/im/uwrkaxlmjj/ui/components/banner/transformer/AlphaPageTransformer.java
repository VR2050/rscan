package im.uwrkaxlmjj.ui.components.banner.transformer;

import android.view.View;

/* JADX INFO: loaded from: classes5.dex */
public class AlphaPageTransformer extends BasePageTransformer {
    private static final float DEFAULT_MIN_ALPHA = 0.5f;
    private float mMinAlpha;

    public AlphaPageTransformer() {
        this.mMinAlpha = 0.5f;
    }

    public AlphaPageTransformer(float minAlpha) {
        this.mMinAlpha = 0.5f;
        this.mMinAlpha = minAlpha;
    }

    @Override // androidx.viewpager2.widget.ViewPager2.PageTransformer
    public void transformPage(View view, float position) {
        view.setScaleX(0.999f);
        if (position < -1.0f) {
            view.setAlpha(this.mMinAlpha);
            return;
        }
        if (position > 1.0f) {
            view.setAlpha(this.mMinAlpha);
            return;
        }
        if (position < 0.0f) {
            float f = this.mMinAlpha;
            float factor = f + ((1.0f - f) * (1.0f + position));
            view.setAlpha(factor);
        } else {
            float f2 = this.mMinAlpha;
            float factor2 = f2 + ((1.0f - f2) * (1.0f - position));
            view.setAlpha(factor2);
        }
    }
}
