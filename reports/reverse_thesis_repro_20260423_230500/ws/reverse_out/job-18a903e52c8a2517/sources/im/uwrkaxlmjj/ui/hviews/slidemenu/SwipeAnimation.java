package im.uwrkaxlmjj.ui.hviews.slidemenu;

import android.view.View;
import android.view.animation.Animation;
import android.view.animation.DecelerateInterpolator;
import android.view.animation.Transformation;
import androidx.core.view.ViewCompat;

/* JADX INFO: loaded from: classes5.dex */
class SwipeAnimation extends Animation {
    private View changeXView;
    private boolean left;
    private View resizeView;
    private int startWidth = -1;
    private int width;

    SwipeAnimation(View resizeView, int width, View changeXView, boolean left) {
        this.resizeView = resizeView;
        this.width = width;
        this.changeXView = changeXView;
        this.left = left;
        setDuration(300L);
        setInterpolator(new DecelerateInterpolator());
    }

    @Override // android.view.animation.Animation
    protected void applyTransformation(float interpolatedTime, Transformation t) {
        if (this.startWidth < 0) {
            this.startWidth = this.resizeView.getWidth();
        }
        View view = this.resizeView;
        int i = this.startWidth;
        Utils.setViewWidth(view, i + ((int) ((this.width - i) * interpolatedTime)));
        if (this.left) {
            ViewCompat.setTranslationX(this.changeXView, this.resizeView.getWidth());
        } else {
            ViewCompat.setTranslationX(this.changeXView, -this.resizeView.getWidth());
        }
    }

    @Override // android.view.animation.Animation
    public boolean willChangeBounds() {
        return true;
    }
}
