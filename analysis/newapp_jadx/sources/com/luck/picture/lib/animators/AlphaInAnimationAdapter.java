package com.luck.picture.lib.animators;

import android.animation.Animator;
import android.animation.ObjectAnimator;
import android.view.View;
import androidx.constraintlayout.motion.widget.Key;
import androidx.recyclerview.widget.RecyclerView;

/* loaded from: classes2.dex */
public class AlphaInAnimationAdapter extends BaseAnimationAdapter {
    private static final float DEFAULT_ALPHA_FROM = 0.0f;
    private final float mFrom;

    public AlphaInAnimationAdapter(RecyclerView.Adapter adapter) {
        this(adapter, 0.0f);
    }

    @Override // com.luck.picture.lib.animators.BaseAnimationAdapter
    public Animator[] getAnimators(View view) {
        return new Animator[]{ObjectAnimator.ofFloat(view, Key.ALPHA, this.mFrom, 1.0f)};
    }

    public AlphaInAnimationAdapter(RecyclerView.Adapter adapter, float f2) {
        super(adapter);
        this.mFrom = f2;
    }
}
