package com.just.agentweb;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.animation.ValueAnimator;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.util.AttributeSet;
import android.view.View;
import android.view.animation.DecelerateInterpolator;
import android.view.animation.LinearInterpolator;
import android.widget.FrameLayout;

/* JADX INFO: loaded from: classes3.dex */
public class WebIndicator extends BaseIndicatorView implements BaseIndicatorSpec {
    public static final int DO_END_ANIMATION_DURATION = 600;
    public static final int FINISH = 2;
    public static final int MAX_DECELERATE_SPEED_DURATION = 450;
    public static final int MAX_UNIFORM_SPEED_DURATION = 8000;
    public static final int STARTED = 1;
    public static final int UN_START = 0;
    private int indicatorStatus;
    private Animator mAnimator;
    private AnimatorListenerAdapter mAnimatorListenerAdapter;
    private ValueAnimator.AnimatorUpdateListener mAnimatorUpdateListener;
    private int mColor;
    private int mCurrentDoEndAnimationDuration;
    private int mCurrentMaxDecelerateSpeedDuration;
    private int mCurrentMaxUniformSpeedDuration;
    private float mCurrentProgress;
    private Paint mPaint;
    private int mTargetWidth;
    public int mWebIndicatorDefaultHeight;

    public WebIndicator(Context context) {
        this(context, null);
    }

    public WebIndicator(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public WebIndicator(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        this.mTargetWidth = 0;
        this.mCurrentMaxUniformSpeedDuration = 8000;
        this.mCurrentMaxDecelerateSpeedDuration = 450;
        this.mCurrentDoEndAnimationDuration = 600;
        this.indicatorStatus = 0;
        this.mCurrentProgress = 0.0f;
        this.mWebIndicatorDefaultHeight = 3;
        this.mAnimatorUpdateListener = new ValueAnimator.AnimatorUpdateListener() { // from class: com.just.agentweb.WebIndicator.1
            @Override // android.animation.ValueAnimator.AnimatorUpdateListener
            public void onAnimationUpdate(ValueAnimator animation) {
                float t = ((Float) animation.getAnimatedValue()).floatValue();
                WebIndicator.this.mCurrentProgress = t;
                WebIndicator.this.invalidate();
            }
        };
        this.mAnimatorListenerAdapter = new AnimatorListenerAdapter() { // from class: com.just.agentweb.WebIndicator.2
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                WebIndicator.this.doEnd();
            }
        };
        init(context, attrs, defStyleAttr);
    }

    private void init(Context context, AttributeSet attrs, int defStyleAttr) {
        this.mPaint = new Paint();
        this.mColor = Color.parseColor("#1aad19");
        this.mPaint.setAntiAlias(true);
        this.mPaint.setColor(this.mColor);
        this.mPaint.setDither(true);
        this.mPaint.setStrokeCap(Paint.Cap.SQUARE);
        this.mTargetWidth = context.getResources().getDisplayMetrics().widthPixels;
        this.mWebIndicatorDefaultHeight = AgentWebUtils.dp2px(context, 3.0f);
    }

    public void setColor(int color) {
        this.mColor = color;
        this.mPaint.setColor(color);
    }

    public void setColor(String color) {
        setColor(Color.parseColor(color));
    }

    @Override // android.widget.FrameLayout, android.view.View
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int wMode = View.MeasureSpec.getMode(widthMeasureSpec);
        int w = View.MeasureSpec.getSize(widthMeasureSpec);
        int hMode = View.MeasureSpec.getMode(heightMeasureSpec);
        int h = View.MeasureSpec.getSize(heightMeasureSpec);
        if (wMode == Integer.MIN_VALUE) {
            w = w <= getContext().getResources().getDisplayMetrics().widthPixels ? w : getContext().getResources().getDisplayMetrics().widthPixels;
        }
        if (hMode == Integer.MIN_VALUE) {
            h = this.mWebIndicatorDefaultHeight;
        }
        setMeasuredDimension(w, h);
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void dispatchDraw(Canvas canvas) {
        canvas.drawRect(0.0f, 0.0f, (this.mCurrentProgress / 100.0f) * Float.valueOf(getWidth()).floatValue(), getHeight(), this.mPaint);
    }

    @Override // com.just.agentweb.BaseIndicatorView, com.just.agentweb.BaseIndicatorSpec
    public void show() {
        if (getVisibility() == 8) {
            setVisibility(0);
            this.mCurrentProgress = 0.0f;
            startAnim(false);
        }
    }

    @Override // android.view.View
    protected void onSizeChanged(int w, int h, int oldw, int oldh) {
        super.onSizeChanged(w, h, oldw, oldh);
        this.mTargetWidth = getMeasuredWidth();
        int screenWidth = getContext().getResources().getDisplayMetrics().widthPixels;
        int i = this.mTargetWidth;
        if (i >= screenWidth) {
            this.mCurrentMaxDecelerateSpeedDuration = 450;
            this.mCurrentMaxUniformSpeedDuration = 8000;
            this.mCurrentDoEndAnimationDuration = 450;
        } else {
            float rate = i / Float.valueOf(screenWidth).floatValue();
            this.mCurrentMaxUniformSpeedDuration = (int) (8000.0f * rate);
            this.mCurrentMaxDecelerateSpeedDuration = (int) (450.0f * rate);
            this.mCurrentDoEndAnimationDuration = (int) (600.0f * rate);
        }
        LogUtils.i("WebProgress", "CURRENT_MAX_UNIFORM_SPEED_DURATION" + this.mCurrentMaxUniformSpeedDuration);
    }

    public void setProgress(float progress) {
        if (getVisibility() == 8) {
            setVisibility(0);
        }
        if (progress >= 95.0f && this.indicatorStatus != 2) {
            startAnim(true);
        }
    }

    @Override // com.just.agentweb.BaseIndicatorView, com.just.agentweb.BaseIndicatorSpec
    public void hide() {
        this.indicatorStatus = 2;
    }

    private void startAnim(boolean isFinished) {
        float v = isFinished ? 100.0f : 95.0f;
        Animator animator = this.mAnimator;
        if (animator != null && animator.isStarted()) {
            this.mAnimator.cancel();
        }
        float f = this.mCurrentProgress;
        if (f == 0.0f) {
            f = 1.0E-8f;
        }
        this.mCurrentProgress = f;
        if (!isFinished) {
            AnimatorSet animatorSet = new AnimatorSet();
            float p1 = v * 0.6f;
            float p2 = v;
            ValueAnimator animator2 = ValueAnimator.ofFloat(this.mCurrentProgress, p1);
            ValueAnimator animator0 = ValueAnimator.ofFloat(p1, p2);
            float residue = (1.0f - (this.mCurrentProgress / 100.0f)) - 0.05f;
            long duration = (long) (this.mCurrentMaxUniformSpeedDuration * residue);
            long duration6 = (long) (duration * 0.6f);
            long duration4 = (long) (duration * 0.4f);
            animator2.setInterpolator(new LinearInterpolator());
            animator2.setDuration(duration4);
            animator2.addUpdateListener(this.mAnimatorUpdateListener);
            animator0.setInterpolator(new LinearInterpolator());
            animator0.setDuration(duration6);
            animator0.addUpdateListener(this.mAnimatorUpdateListener);
            animatorSet.play(animator0).after(animator2);
            animatorSet.start();
            this.mAnimator = animatorSet;
        } else {
            ValueAnimator segment95Animator = null;
            if (f < 95.0f) {
                segment95Animator = ValueAnimator.ofFloat(f, 95.0f);
                float residue2 = (1.0f - (this.mCurrentProgress / 100.0f)) - 0.05f;
                segment95Animator.setDuration((long) (this.mCurrentMaxDecelerateSpeedDuration * residue2));
                segment95Animator.setInterpolator(new DecelerateInterpolator());
                segment95Animator.addUpdateListener(this.mAnimatorUpdateListener);
            }
            ObjectAnimator mObjectAnimator = ObjectAnimator.ofFloat(this, "alpha", 1.0f, 0.0f);
            mObjectAnimator.setDuration(this.mCurrentDoEndAnimationDuration);
            ValueAnimator mValueAnimatorEnd = ValueAnimator.ofFloat(95.0f, 100.0f);
            mValueAnimatorEnd.setDuration(this.mCurrentDoEndAnimationDuration);
            mValueAnimatorEnd.addUpdateListener(this.mAnimatorUpdateListener);
            AnimatorSet animatorSet2 = new AnimatorSet();
            animatorSet2.playTogether(mObjectAnimator, mValueAnimatorEnd);
            if (segment95Animator != null) {
                AnimatorSet animatorSet0 = new AnimatorSet();
                animatorSet0.play(animatorSet2).after(segment95Animator);
                animatorSet2 = animatorSet0;
            }
            animatorSet2.addListener(this.mAnimatorListenerAdapter);
            animatorSet2.start();
            this.mAnimator = animatorSet2;
        }
        this.indicatorStatus = 1;
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        Animator animator = this.mAnimator;
        if (animator != null && animator.isStarted()) {
            this.mAnimator.cancel();
            this.mAnimator = null;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void doEnd() {
        if (this.indicatorStatus == 2 && this.mCurrentProgress == 100.0f) {
            setVisibility(8);
            this.mCurrentProgress = 0.0f;
            setAlpha(1.0f);
        }
        this.indicatorStatus = 0;
    }

    @Override // com.just.agentweb.BaseIndicatorView, com.just.agentweb.BaseIndicatorSpec
    public void reset() {
        this.mCurrentProgress = 0.0f;
        Animator animator = this.mAnimator;
        if (animator != null && animator.isStarted()) {
            this.mAnimator.cancel();
        }
    }

    @Override // com.just.agentweb.BaseIndicatorView, com.just.agentweb.BaseIndicatorSpec
    public void setProgress(int newProgress) {
        setProgress(Float.valueOf(newProgress).floatValue());
    }

    @Override // com.just.agentweb.LayoutParamsOffer
    public FrameLayout.LayoutParams offerLayoutParams() {
        return new FrameLayout.LayoutParams(-1, this.mWebIndicatorDefaultHeight);
    }
}
