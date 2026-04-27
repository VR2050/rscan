package im.uwrkaxlmjj.ui.wallet.utils;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
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

    public static void animationShow(View view) {
        view.setVisibility(0);
        AnimatorSet animatorSet = new AnimatorSet();
        animatorSet.setInterpolator(new DecelerateInterpolator(1.5f));
        animatorSet.setDuration(280L);
        animatorSet.playTogether(ObjectAnimator.ofFloat(view, "alpha", 0.2f, 1.0f), ObjectAnimator.ofFloat(view, "scaleX", 0.95f, 1.0f), ObjectAnimator.ofFloat(view, "scaleY", 0.95f, 1.0f));
        animatorSet.start();
    }

    public static void animationHide(final View view) {
        AnimatorSet animatorSet = new AnimatorSet();
        animatorSet.setInterpolator(new DecelerateInterpolator(1.5f));
        animatorSet.setDuration(280L);
        animatorSet.playTogether(ObjectAnimator.ofFloat(view, "alpha", 1.0f, 0.2f), ObjectAnimator.ofFloat(view, "scaleX", 1.0f, 0.95f), ObjectAnimator.ofFloat(view, "scaleY", 1.0f, 0.95f));
        animatorSet.start();
        animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.wallet.utils.AnimationUtils.1
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                super.onAnimationEnd(animation);
                view.setVisibility(8);
            }
        });
    }
}
