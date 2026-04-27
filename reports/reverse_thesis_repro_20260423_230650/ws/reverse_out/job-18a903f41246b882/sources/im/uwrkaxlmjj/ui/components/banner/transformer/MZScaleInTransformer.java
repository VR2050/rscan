package im.uwrkaxlmjj.ui.components.banner.transformer;

import android.view.View;
import android.view.ViewParent;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewpager2.widget.ViewPager2;

/* JADX INFO: loaded from: classes5.dex */
public class MZScaleInTransformer extends BasePageTransformer {
    private static final float DEFAULT_MIN_SCALE = 0.85f;
    private float mMinScale;

    public MZScaleInTransformer() {
        this.mMinScale = DEFAULT_MIN_SCALE;
    }

    public MZScaleInTransformer(float minScale) {
        this.mMinScale = DEFAULT_MIN_SCALE;
        this.mMinScale = minScale;
    }

    @Override // androidx.viewpager2.widget.ViewPager2.PageTransformer
    public void transformPage(View view, float position) {
        ViewPager2 viewPager = requireViewPager(view);
        float paddingLeft = viewPager.getPaddingLeft();
        float paddingRight = viewPager.getPaddingRight();
        float width = viewPager.getMeasuredWidth();
        float offsetPosition = paddingLeft / ((width - paddingLeft) - paddingRight);
        float currentPos = position - offsetPosition;
        float itemWidth = view.getWidth();
        float f = this.mMinScale;
        float reduceX = ((1.0f - f) * itemWidth) / 2.0f;
        if (currentPos <= -1.0f) {
            view.setTranslationX(reduceX);
            view.setScaleX(this.mMinScale);
            view.setScaleY(this.mMinScale);
            return;
        }
        if (currentPos <= 1.0d) {
            float scale = (1.0f - f) * Math.abs(1.0f - Math.abs(currentPos));
            float translationX = (-reduceX) * currentPos;
            if (currentPos <= -0.5d) {
                view.setTranslationX((Math.abs(Math.abs(currentPos) - 0.5f) / 0.5f) + translationX);
            } else if (currentPos > 0.0f && currentPos >= 0.5d) {
                view.setTranslationX(translationX - (Math.abs(Math.abs(currentPos) - 0.5f) / 0.5f));
            } else {
                view.setTranslationX(translationX);
            }
            view.setScaleX(this.mMinScale + scale);
            view.setScaleY(this.mMinScale + scale);
            return;
        }
        view.setScaleX(f);
        view.setScaleY(this.mMinScale);
        view.setTranslationX(-reduceX);
    }

    private ViewPager2 requireViewPager(View page) {
        ViewParent parent = page.getParent();
        ViewParent parentParent = parent.getParent();
        if ((parent instanceof RecyclerView) && (parentParent instanceof ViewPager2)) {
            return (ViewPager2) parentParent;
        }
        throw new IllegalStateException("Expected the page view to be managed by a ViewPager2 instance.");
    }
}
