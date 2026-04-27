package com.scwang.smartrefresh.layout.internal;

import android.animation.Animator;
import android.animation.ValueAnimator;
import android.graphics.Canvas;
import android.graphics.Path;
import android.graphics.Rect;
import android.graphics.drawable.Animatable;
import com.zhy.http.okhttp.OkHttpUtils;

/* JADX INFO: loaded from: classes3.dex */
public class ProgressDrawable extends PaintDrawable implements Animatable, ValueAnimator.AnimatorUpdateListener {
    protected ValueAnimator mValueAnimator;
    protected int mWidth = 0;
    protected int mHeight = 0;
    protected int mProgressDegree = 0;
    protected Path mPath = new Path();

    public ProgressDrawable() {
        ValueAnimator valueAnimatorOfInt = ValueAnimator.ofInt(30, 3600);
        this.mValueAnimator = valueAnimatorOfInt;
        valueAnimatorOfInt.setDuration(OkHttpUtils.DEFAULT_MILLISECONDS);
        this.mValueAnimator.setInterpolator(null);
        this.mValueAnimator.setRepeatCount(-1);
        this.mValueAnimator.setRepeatMode(1);
    }

    @Override // android.animation.ValueAnimator.AnimatorUpdateListener
    public void onAnimationUpdate(ValueAnimator animation) {
        int value = ((Integer) animation.getAnimatedValue()).intValue();
        this.mProgressDegree = (value / 30) * 30;
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public void draw(Canvas canvas) {
        Rect bounds = getBounds();
        int width = bounds.width();
        int height = bounds.height();
        float r = Math.max(1.0f, width / 22.0f);
        if (this.mWidth != width || this.mHeight != height) {
            this.mPath.reset();
            this.mPath.addCircle(width - r, height / 2.0f, r, Path.Direction.CW);
            this.mPath.addRect(width - (r * 5.0f), (height / 2.0f) - r, width - r, (height / 2.0f) + r, Path.Direction.CW);
            this.mPath.addCircle(width - (5.0f * r), height / 2.0f, r, Path.Direction.CW);
            this.mWidth = width;
            this.mHeight = height;
        }
        canvas.save();
        canvas.rotate(this.mProgressDegree, width / 2.0f, height / 2.0f);
        for (int i = 0; i < 12; i++) {
            this.mPaint.setAlpha((i + 5) * 17);
            canvas.rotate(30.0f, width / 2.0f, height / 2.0f);
            canvas.drawPath(this.mPath, this.mPaint);
        }
        canvas.restore();
    }

    @Override // android.graphics.drawable.Animatable
    public void start() {
        if (!this.mValueAnimator.isRunning()) {
            this.mValueAnimator.addUpdateListener(this);
            this.mValueAnimator.start();
        }
    }

    @Override // android.graphics.drawable.Animatable
    public void stop() {
        if (this.mValueAnimator.isRunning()) {
            Animator animator = this.mValueAnimator;
            animator.removeAllListeners();
            this.mValueAnimator.removeAllUpdateListeners();
            this.mValueAnimator.cancel();
        }
    }

    @Override // android.graphics.drawable.Animatable
    public boolean isRunning() {
        return this.mValueAnimator.isRunning();
    }
}
