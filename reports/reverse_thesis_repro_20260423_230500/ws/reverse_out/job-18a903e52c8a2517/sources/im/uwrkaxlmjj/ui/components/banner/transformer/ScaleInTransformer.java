package im.uwrkaxlmjj.ui.components.banner.transformer;

import android.view.View;

/* JADX INFO: loaded from: classes5.dex */
public class ScaleInTransformer extends BasePageTransformer {
    private static final float DEFAULT_MIN_SCALE = 0.85f;
    private float mMinScale;

    public ScaleInTransformer() {
        this.mMinScale = DEFAULT_MIN_SCALE;
    }

    public ScaleInTransformer(float minScale) {
        this.mMinScale = DEFAULT_MIN_SCALE;
        this.mMinScale = minScale;
    }

    @Override // androidx.viewpager2.widget.ViewPager2.PageTransformer
    public void transformPage(View view, float position) {
        int pageWidth = view.getWidth();
        int pageHeight = view.getHeight();
        view.setPivotY(pageHeight / 2);
        view.setPivotX(pageWidth / 2);
        if (position < -1.0f) {
            view.setScaleX(this.mMinScale);
            view.setScaleY(this.mMinScale);
            view.setPivotX(pageWidth);
            return;
        }
        if (position > 1.0f) {
            view.setPivotX(0.0f);
            view.setScaleX(this.mMinScale);
            view.setScaleY(this.mMinScale);
        } else {
            if (position < 0.0f) {
                float f = this.mMinScale;
                float scaleFactor = ((position + 1.0f) * (1.0f - f)) + f;
                view.setScaleX(scaleFactor);
                view.setScaleY(scaleFactor);
                view.setPivotX(pageWidth * (((-position) * 0.5f) + 0.5f));
                return;
            }
            float f2 = this.mMinScale;
            float scaleFactor2 = ((1.0f - position) * (1.0f - f2)) + f2;
            view.setScaleX(scaleFactor2);
            view.setScaleY(scaleFactor2);
            view.setPivotX(pageWidth * (1.0f - position) * 0.5f);
        }
    }
}
