package im.uwrkaxlmjj.ui.components.banner.transformer;

import android.view.View;

/* JADX INFO: loaded from: classes5.dex */
public class RotateYTransformer extends BasePageTransformer {
    private static final float DEFAULT_MAX_ROTATE = 35.0f;
    private float mMaxRotate;

    public RotateYTransformer() {
        this.mMaxRotate = DEFAULT_MAX_ROTATE;
    }

    public RotateYTransformer(float maxRotate) {
        this.mMaxRotate = DEFAULT_MAX_ROTATE;
        this.mMaxRotate = maxRotate;
    }

    @Override // androidx.viewpager2.widget.ViewPager2.PageTransformer
    public void transformPage(View view, float position) {
        view.setPivotY(view.getHeight() / 2);
        if (position < -1.0f) {
            view.setRotationY(this.mMaxRotate * (-1.0f));
            view.setPivotX(view.getWidth());
            return;
        }
        if (position <= 1.0f) {
            view.setRotationY(this.mMaxRotate * position);
            if (position < 0.0f) {
                view.setPivotX(view.getWidth() * (((-position) * 0.5f) + 0.5f));
                view.setPivotX(view.getWidth());
                return;
            } else {
                view.setPivotX(view.getWidth() * 0.5f * (1.0f - position));
                view.setPivotX(0.0f);
                return;
            }
        }
        view.setRotationY(this.mMaxRotate * 1.0f);
        view.setPivotX(0.0f);
    }
}
