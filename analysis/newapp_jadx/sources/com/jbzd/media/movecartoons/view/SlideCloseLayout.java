package com.jbzd.media.movecartoons.view;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.ObjectAnimator;
import android.animation.ValueAnimator;
import android.content.Context;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.widget.FrameLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.motion.widget.Key;
import com.jbzd.media.movecartoons.view.SlideCloseLayout;
import p005b.p325v.p326a.C2818e;

/* loaded from: classes2.dex */
public class SlideCloseLayout extends FrameLayout {
    private boolean isScrollingUp;
    private Drawable mBackground;
    private LayoutScrollListener mScrollListener;
    private int previousX;
    private int previousY;

    public interface LayoutScrollListener {
        void onLayoutClosed();

        void onLayoutScrollRevocer();

        void onLayoutScrolling(float f2);
    }

    public SlideCloseLayout(@NonNull Context context) {
        super(context);
    }

    private void layoutRecoverAnim() {
        ObjectAnimator ofFloat = ObjectAnimator.ofFloat(this, Key.TRANSLATION_Y, getTranslationY(), 0.0f);
        ofFloat.setDuration(100L);
        ofFloat.start();
        Drawable drawable = this.mBackground;
        if (drawable != null) {
            drawable.setAlpha(255);
            this.mScrollListener.onLayoutScrollRevocer();
        }
    }

    /* renamed from: a */
    public /* synthetic */ void m4513a(ValueAnimator valueAnimator) {
        if (this.mBackground != null) {
            this.mBackground.setAlpha(255 - (((int) (Math.abs(getTranslationY() * 1.0f) * 255.0f)) / getHeight()));
        }
    }

    public void layoutExitAnim() {
        float[] fArr = new float[2];
        fArr[0] = getTranslationY();
        fArr[1] = this.isScrollingUp ? -getHeight() : getHeight();
        ObjectAnimator ofFloat = ObjectAnimator.ofFloat(this, Key.TRANSLATION_Y, fArr);
        ofFloat.addListener(new AnimatorListenerAdapter() { // from class: com.jbzd.media.movecartoons.view.SlideCloseLayout.1
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animator) {
                if (SlideCloseLayout.this.mBackground != null) {
                    SlideCloseLayout.this.mBackground.setAlpha(0);
                }
                if (SlideCloseLayout.this.mScrollListener != null) {
                    SlideCloseLayout.this.mScrollListener.onLayoutClosed();
                }
            }
        });
        ofFloat.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() { // from class: b.a.a.a.u.p
            @Override // android.animation.ValueAnimator.AnimatorUpdateListener
            public final void onAnimationUpdate(ValueAnimator valueAnimator) {
                SlideCloseLayout.this.m4513a(valueAnimator);
            }
        });
        ofFloat.setDuration(200L);
        ofFloat.start();
    }

    @Override // android.view.ViewGroup
    public boolean onInterceptTouchEvent(MotionEvent motionEvent) {
        if (motionEvent.getPointerCount() > 1) {
            return false;
        }
        int rawY = (int) motionEvent.getRawY();
        int rawX = (int) motionEvent.getRawX();
        int action = motionEvent.getAction();
        if (action == 0) {
            this.previousX = rawX;
            this.previousY = rawY;
        } else if (action == 2) {
            if (Math.abs(rawX - this.previousX) + 50 < Math.abs(rawY - this.previousY)) {
                return true;
            }
        }
        return false;
    }

    @Override // android.view.View
    public boolean onTouchEvent(@NonNull MotionEvent motionEvent) {
        int rawY = (int) motionEvent.getRawY();
        int rawX = (int) motionEvent.getRawX();
        int action = motionEvent.getAction();
        if (action == 0) {
            this.previousX = rawX;
            this.previousY = rawY;
        } else if (action == 1) {
            if (Math.abs(getTranslationY()) > getHeight() / 4) {
                layoutExitAnim();
            } else {
                layoutRecoverAnim();
            }
        } else if (action == 2) {
            int i2 = rawY - this.previousY;
            this.isScrollingUp = i2 <= 0;
            float f2 = i2;
            setTranslationY(f2);
            if (this.mBackground != null) {
                int abs = ((int) (Math.abs(f2 * 1.0f) * 255.0f)) / getHeight();
                this.mBackground.setAlpha(255 - abs);
                this.mScrollListener.onLayoutScrolling(abs / 255.0f);
                C2818e.m3273b("alpha is " + abs, new Object[0]);
            }
        }
        return true;
    }

    @Override // android.view.View
    public void setBackground(Drawable drawable) {
        this.mBackground = drawable;
    }

    public void setScrollListener(LayoutScrollListener layoutScrollListener) {
        this.mScrollListener = layoutScrollListener;
    }

    public SlideCloseLayout(@NonNull Context context, @Nullable AttributeSet attributeSet) {
        super(context, attributeSet);
    }

    public SlideCloseLayout(@NonNull Context context, @Nullable AttributeSet attributeSet, int i2) {
        super(context, attributeSet, i2);
    }
}
