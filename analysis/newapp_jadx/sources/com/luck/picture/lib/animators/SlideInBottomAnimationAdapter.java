package com.luck.picture.lib.animators;

import android.animation.Animator;
import android.animation.ObjectAnimator;
import android.view.View;
import androidx.constraintlayout.motion.widget.Key;
import androidx.recyclerview.widget.RecyclerView;

/* loaded from: classes2.dex */
public class SlideInBottomAnimationAdapter extends BaseAnimationAdapter {
    public SlideInBottomAnimationAdapter(RecyclerView.Adapter adapter) {
        super(adapter);
    }

    @Override // com.luck.picture.lib.animators.BaseAnimationAdapter
    public Animator[] getAnimators(View view) {
        return new Animator[]{ObjectAnimator.ofFloat(view, Key.TRANSLATION_Y, view.getMeasuredHeight(), 0.0f)};
    }
}
