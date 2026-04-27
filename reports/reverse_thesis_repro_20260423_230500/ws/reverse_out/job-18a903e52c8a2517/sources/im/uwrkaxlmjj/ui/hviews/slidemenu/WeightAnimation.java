package im.uwrkaxlmjj.ui.hviews.slidemenu;

import android.view.View;
import android.view.animation.Animation;
import android.view.animation.Transformation;

/* JADX INFO: loaded from: classes5.dex */
class WeightAnimation extends Animation {
    private final float endWeight;
    private View view;
    private float startWeight = -1.0f;
    private float deltaWeight = -1.0f;

    WeightAnimation(float endWeight, View view) {
        this.endWeight = endWeight;
        this.view = view;
        setDuration(200L);
    }

    public View getView() {
        return this.view;
    }

    @Override // android.view.animation.Animation
    protected void applyTransformation(float interpolatedTime, Transformation t) {
        if (this.startWeight < 0.0f) {
            float viewWeight = Utils.getViewWeight(this.view);
            this.startWeight = viewWeight;
            this.deltaWeight = this.endWeight - viewWeight;
        }
        Utils.setViewWeight(this.view, this.startWeight + (this.deltaWeight * interpolatedTime));
    }

    @Override // android.view.animation.Animation
    public boolean willChangeBounds() {
        return true;
    }
}
