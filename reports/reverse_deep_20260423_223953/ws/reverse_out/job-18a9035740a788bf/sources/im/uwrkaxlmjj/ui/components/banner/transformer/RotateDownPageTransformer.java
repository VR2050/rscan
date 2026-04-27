package im.uwrkaxlmjj.ui.components.banner.transformer;

import android.view.View;

/* JADX INFO: loaded from: classes5.dex */
public class RotateDownPageTransformer extends BasePageTransformer {
    private static final float DEFAULT_MAX_ROTATE = 15.0f;
    private float mMaxRotate;

    public RotateDownPageTransformer() {
        this.mMaxRotate = DEFAULT_MAX_ROTATE;
    }

    public RotateDownPageTransformer(float maxRotate) {
        this.mMaxRotate = DEFAULT_MAX_ROTATE;
        this.mMaxRotate = maxRotate;
    }

    @Override // androidx.viewpager2.widget.ViewPager2.PageTransformer
    public void transformPage(View view, float position) {
        if (position < -1.0f) {
            view.setRotation(this.mMaxRotate * (-1.0f));
            view.setPivotX(view.getWidth());
            view.setPivotY(view.getHeight());
        } else if (position > 1.0f) {
            view.setRotation(this.mMaxRotate);
            view.setPivotX(view.getWidth() * 0);
            view.setPivotY(view.getHeight());
        } else if (position >= 0.0f) {
            view.setPivotX(view.getWidth() * 0.5f * (1.0f - position));
            view.setPivotY(view.getHeight());
            view.setRotation(this.mMaxRotate * position);
        } else {
            view.setPivotX(view.getWidth() * (((-position) * 0.5f) + 0.5f));
            view.setPivotY(view.getHeight());
            view.setRotation(this.mMaxRotate * position);
        }
    }
}
