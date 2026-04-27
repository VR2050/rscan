package im.uwrkaxlmjj.utils;

import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.view.View;
import android.view.animation.DecelerateInterpolator;

/* JADX INFO: loaded from: classes5.dex */
public class AnimationUtils {
    public static void executeAlphaScaleDisplayAnimation(View view) {
        AnimatorSet animatorSet = new AnimatorSet();
        animatorSet.setInterpolator(new DecelerateInterpolator(1.5f));
        animatorSet.setDuration(280L);
        animatorSet.playTogether(ObjectAnimator.ofFloat(view, "alpha", 0.2f, 1.0f), ObjectAnimator.ofFloat(view, "scaleX", 0.95f, 1.0f), ObjectAnimator.ofFloat(view, "scaleY", 0.95f, 1.0f));
        animatorSet.start();
    }
}
