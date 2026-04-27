package im.uwrkaxlmjj.ui.components.banner.transformer;

import android.view.View;

/* JADX INFO: loaded from: classes5.dex */
public class ZoomOutPageTransformer extends BasePageTransformer {
    private static final float DEFAULT_MIN_ALPHA = 0.5f;
    private static final float DEFAULT_MIN_SCALE = 0.85f;
    private float mMinAlpha;
    private float mMinScale;

    public ZoomOutPageTransformer() {
        this.mMinScale = DEFAULT_MIN_SCALE;
        this.mMinAlpha = 0.5f;
    }

    public ZoomOutPageTransformer(float minScale, float minAlpha) {
        this.mMinScale = DEFAULT_MIN_SCALE;
        this.mMinAlpha = 0.5f;
        this.mMinScale = minScale;
        this.mMinAlpha = minAlpha;
    }

    @Override // androidx.viewpager2.widget.ViewPager2.PageTransformer
    public void transformPage(View view, float position) {
        int pageWidth = view.getWidth();
        int pageHeight = view.getHeight();
        if (position < -1.0f) {
            view.setAlpha(0.0f);
            return;
        }
        if (position <= 1.0f) {
            float scaleFactor = Math.max(this.mMinScale, 1.0f - Math.abs(position));
            float vertMargin = (pageHeight * (1.0f - scaleFactor)) / 2.0f;
            float horzMargin = (pageWidth * (1.0f - scaleFactor)) / 2.0f;
            if (position < 0.0f) {
                view.setTranslationX(horzMargin - (vertMargin / 2.0f));
            } else {
                view.setTranslationX((-horzMargin) + (vertMargin / 2.0f));
            }
            view.setScaleX(scaleFactor);
            view.setScaleY(scaleFactor);
            float f = this.mMinAlpha;
            float f2 = this.mMinScale;
            view.setAlpha(f + (((scaleFactor - f2) / (1.0f - f2)) * (1.0f - f)));
            return;
        }
        view.setAlpha(0.0f);
    }
}
