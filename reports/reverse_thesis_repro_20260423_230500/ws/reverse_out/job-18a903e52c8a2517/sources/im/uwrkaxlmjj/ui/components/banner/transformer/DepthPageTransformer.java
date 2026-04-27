package im.uwrkaxlmjj.ui.components.banner.transformer;

import android.view.View;

/* JADX INFO: loaded from: classes5.dex */
public class DepthPageTransformer extends BasePageTransformer {
    private static final float DEFAULT_MIN_SCALE = 0.75f;
    private float mMinScale;

    public DepthPageTransformer() {
        this.mMinScale = 0.75f;
    }

    public DepthPageTransformer(float minScale) {
        this.mMinScale = 0.75f;
        this.mMinScale = minScale;
    }

    @Override // androidx.viewpager2.widget.ViewPager2.PageTransformer
    public void transformPage(View view, float position) {
        int pageWidth = view.getWidth();
        if (position < -1.0f) {
            view.setAlpha(0.0f);
            return;
        }
        if (position <= 0.0f) {
            view.setAlpha(1.0f);
            view.setTranslationX(0.0f);
            view.setScaleX(1.0f);
            view.setScaleY(1.0f);
            return;
        }
        if (position <= 1.0f) {
            view.setVisibility(0);
            view.setAlpha(1.0f - position);
            view.setTranslationX(pageWidth * (-position));
            float f = this.mMinScale;
            float scaleFactor = f + ((1.0f - f) * (1.0f - Math.abs(position)));
            view.setScaleX(scaleFactor);
            view.setScaleY(scaleFactor);
            if (position == 1.0f) {
                view.setVisibility(4);
                return;
            }
            return;
        }
        view.setAlpha(0.0f);
    }
}
