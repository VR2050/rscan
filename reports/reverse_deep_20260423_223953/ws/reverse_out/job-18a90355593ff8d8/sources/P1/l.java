package P1;

import android.view.View;
import android.view.animation.Animation;
import android.view.animation.Transformation;

/* JADX INFO: loaded from: classes.dex */
class l extends Animation {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final View f2197b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final float f2198c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final float f2199d;

    public l(View view, float f3, float f4) {
        this.f2197b = view;
        this.f2198c = f3;
        this.f2199d = f4 - f3;
        setAnimationListener(new a(view));
    }

    @Override // android.view.animation.Animation
    protected void applyTransformation(float f3, Transformation transformation) {
        this.f2197b.setAlpha(this.f2198c + (this.f2199d * f3));
    }

    @Override // android.view.animation.Animation
    public boolean willChangeBounds() {
        return false;
    }

    static class a implements Animation.AnimationListener {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final View f2200a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private boolean f2201b = false;

        public a(View view) {
            this.f2200a = view;
        }

        @Override // android.view.animation.Animation.AnimationListener
        public void onAnimationEnd(Animation animation) {
            if (this.f2201b) {
                this.f2200a.setLayerType(0, null);
            }
        }

        @Override // android.view.animation.Animation.AnimationListener
        public void onAnimationStart(Animation animation) {
            if (this.f2200a.hasOverlappingRendering() && this.f2200a.getLayerType() == 0) {
                this.f2201b = true;
                this.f2200a.setLayerType(2, null);
            }
        }

        @Override // android.view.animation.Animation.AnimationListener
        public void onAnimationRepeat(Animation animation) {
        }
    }
}
