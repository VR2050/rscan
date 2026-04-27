package com.scwang.smartrefresh.layout.header;

import android.animation.Animator;
import android.animation.AnimatorSet;
import android.animation.ValueAnimator;
import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.RectF;
import android.util.AttributeSet;
import android.view.View;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.view.animation.Interpolator;
import androidx.core.content.ContextCompat;
import androidx.core.view.ViewCompat;
import com.scwang.smartrefresh.layout.R;
import com.scwang.smartrefresh.layout.api.RefreshHeader;
import com.scwang.smartrefresh.layout.api.RefreshLayout;
import com.scwang.smartrefresh.layout.constant.RefreshState;
import com.scwang.smartrefresh.layout.constant.SpinnerStyle;
import com.scwang.smartrefresh.layout.internal.InternalAbstract;
import com.scwang.smartrefresh.layout.util.SmartUtil;
import org.webrtc.mozi.JavaScreenCapturer;

/* JADX INFO: loaded from: classes3.dex */
public class BezierRadarHeader extends InternalAbstract implements RefreshHeader {
    protected static final byte PROPERTY_DOT_ALPHA = 2;
    protected static final byte PROPERTY_RADAR_ANGLE = 4;
    protected static final byte PROPERTY_RADAR_SCALE = 0;
    protected static final byte PROPERTY_RIPPLE_RADIUS = 3;
    protected static final byte PROPERTY_WAVE_HEIGHT = 1;
    protected int mAccentColor;
    protected Animator mAnimatorSet;
    protected float mDotAlpha;
    protected float mDotFraction;
    protected float mDotRadius;
    protected boolean mEnableHorizontalDrag;
    protected boolean mManualAccentColor;
    protected boolean mManualPrimaryColor;
    protected Paint mPaint;
    protected Path mPath;
    protected int mPrimaryColor;
    protected int mRadarAngle;
    protected float mRadarCircle;
    protected float mRadarRadius;
    protected RectF mRadarRect;
    protected float mRadarScale;
    protected float mRippleRadius;
    protected int mWaveHeight;
    protected int mWaveOffsetX;
    protected int mWaveOffsetY;
    protected boolean mWavePulling;
    protected int mWaveTop;

    public BezierRadarHeader(Context context) {
        this(context, null);
    }

    public BezierRadarHeader(Context context, AttributeSet attrs) {
        super(context, attrs, 0);
        this.mEnableHorizontalDrag = false;
        this.mWaveOffsetX = -1;
        this.mWaveOffsetY = 0;
        this.mRadarAngle = 0;
        this.mRadarRadius = 0.0f;
        this.mRadarCircle = 0.0f;
        this.mRadarScale = 0.0f;
        this.mRadarRect = new RectF(0.0f, 0.0f, 0.0f, 0.0f);
        this.mSpinnerStyle = SpinnerStyle.FixedBehind;
        this.mPath = new Path();
        Paint paint = new Paint();
        this.mPaint = paint;
        paint.setAntiAlias(true);
        this.mDotRadius = SmartUtil.dp2px(7.0f);
        this.mRadarRadius = SmartUtil.dp2px(20.0f);
        this.mRadarCircle = SmartUtil.dp2px(7.0f);
        this.mPaint.setStrokeWidth(SmartUtil.dp2px(3.0f));
        setMinimumHeight(SmartUtil.dp2px(100.0f));
        if (isInEditMode()) {
            this.mWaveTop = 1000;
            this.mRadarScale = 1.0f;
            this.mRadarAngle = JavaScreenCapturer.DEGREE_270;
        } else {
            this.mRadarScale = 0.0f;
        }
        TypedArray ta = context.obtainStyledAttributes(attrs, R.styleable.BezierRadarHeader);
        this.mEnableHorizontalDrag = ta.getBoolean(R.styleable.BezierRadarHeader_srlEnableHorizontalDrag, this.mEnableHorizontalDrag);
        setAccentColor(ta.getColor(R.styleable.BezierRadarHeader_srlAccentColor, -1));
        setPrimaryColor(ta.getColor(R.styleable.BezierRadarHeader_srlPrimaryColor, -14540254));
        this.mManualAccentColor = ta.hasValue(R.styleable.BezierRadarHeader_srlAccentColor);
        this.mManualPrimaryColor = ta.hasValue(R.styleable.BezierRadarHeader_srlPrimaryColor);
        ta.recycle();
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        Animator animator = this.mAnimatorSet;
        if (animator != null) {
            animator.removeAllListeners();
            this.mAnimatorSet.end();
            this.mAnimatorSet = null;
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    protected void dispatchDraw(Canvas canvas) {
        int width = getWidth();
        int height = isInEditMode() ? getHeight() : this.mWaveOffsetY;
        drawWave(canvas, width);
        drawDot(canvas, width, height);
        drawRadar(canvas, width, height);
        drawRipple(canvas, width, height);
        super.dispatchDraw(canvas);
    }

    protected void drawWave(Canvas canvas, int width) {
        this.mPath.reset();
        this.mPath.lineTo(0.0f, this.mWaveTop);
        Path path = this.mPath;
        int i = this.mWaveOffsetX;
        float f = i >= 0 ? i : width / 2.0f;
        path.quadTo(f, this.mWaveHeight + r3, width, this.mWaveTop);
        this.mPath.lineTo(width, 0.0f);
        this.mPaint.setColor(this.mPrimaryColor);
        canvas.drawPath(this.mPath, this.mPaint);
    }

    protected void drawDot(Canvas canvas, int width, int height) {
        if (this.mDotAlpha > 0.0f) {
            this.mPaint.setColor(this.mAccentColor);
            float x = SmartUtil.px2dp(height);
            float f = 7.0f;
            float f2 = this.mDotFraction;
            float wide = (((width * 1.0f) / 7.0f) * f2) - (f2 > 1.0f ? ((f2 - 1.0f) * ((width * 1.0f) / 7.0f)) / f2 : 0.0f);
            float f3 = height;
            float f4 = this.mDotFraction;
            float f5 = 2.0f;
            float high = f3 - (f4 > 1.0f ? (((f4 - 1.0f) * height) / 2.0f) / f4 : 0.0f);
            int i = 0;
            while (i < 7) {
                float index = (i + 1.0f) - 4.0f;
                float alpha = (1.0f - ((Math.abs(index) / f) * f5)) * 255.0f;
                float high2 = high;
                this.mPaint.setAlpha((int) (((double) (this.mDotAlpha * alpha)) * (1.0d - (1.0d / Math.pow((((double) x) / 800.0d) + 1.0d, 15.0d)))));
                float radius = this.mDotRadius * (1.0f - (1.0f / ((x / 10.0f) + 1.0f)));
                f5 = 2.0f;
                canvas.drawCircle(((width / 2.0f) - (radius / 2.0f)) + (wide * index), high2 / 2.0f, radius, this.mPaint);
                i++;
                high = high2;
                f = 7.0f;
            }
            this.mPaint.setAlpha(255);
        }
    }

    protected void drawRadar(Canvas canvas, int width, int height) {
        if (this.mAnimatorSet != null || isInEditMode()) {
            float f = this.mRadarRadius;
            float f2 = this.mRadarScale;
            float radius = f * f2;
            float circle = this.mRadarCircle * f2;
            this.mPaint.setColor(this.mAccentColor);
            this.mPaint.setStyle(Paint.Style.FILL);
            canvas.drawCircle(width / 2.0f, height / 2.0f, radius, this.mPaint);
            this.mPaint.setStyle(Paint.Style.STROKE);
            canvas.drawCircle(width / 2.0f, height / 2.0f, radius + circle, this.mPaint);
            this.mPaint.setColor((this.mPrimaryColor & ViewCompat.MEASURED_SIZE_MASK) | 1426063360);
            this.mPaint.setStyle(Paint.Style.FILL);
            this.mRadarRect.set((width / 2.0f) - radius, (height / 2.0f) - radius, (width / 2.0f) + radius, (height / 2.0f) + radius);
            canvas.drawArc(this.mRadarRect, 270.0f, this.mRadarAngle, true, this.mPaint);
            float radius2 = radius + circle;
            this.mPaint.setStyle(Paint.Style.STROKE);
            this.mRadarRect.set((width / 2.0f) - radius2, (height / 2.0f) - radius2, (width / 2.0f) + radius2, (height / 2.0f) + radius2);
            canvas.drawArc(this.mRadarRect, 270.0f, this.mRadarAngle, false, this.mPaint);
            this.mPaint.setStyle(Paint.Style.FILL);
        }
    }

    protected void drawRipple(Canvas canvas, int width, int height) {
        if (this.mRippleRadius > 0.0f) {
            this.mPaint.setColor(this.mAccentColor);
            canvas.drawCircle(width / 2.0f, height / 2.0f, this.mRippleRadius, this.mPaint);
        }
    }

    @Override // com.scwang.smartrefresh.layout.internal.InternalAbstract, com.scwang.smartrefresh.layout.api.RefreshInternal
    public void onMoving(boolean isDragging, float percent, int offset, int height, int maxDragHeight) {
        this.mWaveOffsetY = offset;
        if (isDragging || this.mWavePulling) {
            this.mWavePulling = true;
            this.mWaveTop = Math.min(height, offset);
            this.mWaveHeight = (int) (Math.max(0, offset - height) * 1.9f);
            this.mDotFraction = percent;
            invalidate();
        }
    }

    @Override // com.scwang.smartrefresh.layout.internal.InternalAbstract, com.scwang.smartrefresh.layout.api.RefreshInternal
    public void onReleased(RefreshLayout refreshLayout, int height, int maxDragHeight) {
        this.mWaveTop = height - 1;
        this.mWavePulling = false;
        Interpolator interpolatorDecelerate = new SmartUtil(SmartUtil.INTERPOLATOR_DECELERATE);
        ValueAnimator animatorDotAlpha = ValueAnimator.ofFloat(1.0f, 0.0f);
        animatorDotAlpha.setInterpolator(interpolatorDecelerate);
        animatorDotAlpha.addUpdateListener(new AnimatorUpdater(PROPERTY_DOT_ALPHA));
        ValueAnimator animatorRadarScale = ValueAnimator.ofFloat(0.0f, 1.0f);
        animatorDotAlpha.setInterpolator(interpolatorDecelerate);
        animatorRadarScale.addUpdateListener(new AnimatorUpdater((byte) 0));
        ValueAnimator mRadarAnimator = ValueAnimator.ofInt(0, 360);
        mRadarAnimator.setDuration(720L);
        mRadarAnimator.setRepeatCount(-1);
        mRadarAnimator.setInterpolator(new AccelerateDecelerateInterpolator());
        mRadarAnimator.addUpdateListener(new AnimatorUpdater(PROPERTY_RADAR_ANGLE));
        AnimatorSet animatorSet = new AnimatorSet();
        animatorSet.playSequentially(animatorDotAlpha, animatorRadarScale, mRadarAnimator);
        animatorSet.start();
        int i = this.mWaveHeight;
        ValueAnimator animatorWave = ValueAnimator.ofInt(i, 0, -((int) (i * 0.8f)), 0, -((int) (i * 0.4f)), 0);
        animatorWave.addUpdateListener(new AnimatorUpdater(PROPERTY_WAVE_HEIGHT));
        animatorWave.setInterpolator(new SmartUtil(SmartUtil.INTERPOLATOR_DECELERATE));
        animatorWave.setDuration(800L);
        animatorWave.start();
        this.mAnimatorSet = animatorSet;
    }

    @Override // com.scwang.smartrefresh.layout.internal.InternalAbstract, com.scwang.smartrefresh.layout.api.RefreshInternal
    public int onFinish(RefreshLayout layout, boolean success) {
        Animator animator = this.mAnimatorSet;
        if (animator != null) {
            animator.removeAllListeners();
            this.mAnimatorSet.end();
            this.mAnimatorSet = null;
        }
        int width = getWidth();
        int height = this.mWaveOffsetY;
        float bigRadius = (float) Math.sqrt((width * width) + (height * height));
        ValueAnimator animator2 = ValueAnimator.ofFloat(this.mRadarRadius, bigRadius);
        animator2.setDuration(400L);
        animator2.addUpdateListener(new AnimatorUpdater(PROPERTY_RIPPLE_RADIUS));
        animator2.start();
        return 400;
    }

    /* JADX INFO: renamed from: com.scwang.smartrefresh.layout.header.BezierRadarHeader$1, reason: invalid class name */
    static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$com$scwang$smartrefresh$layout$constant$RefreshState;

        static {
            int[] iArr = new int[RefreshState.values().length];
            $SwitchMap$com$scwang$smartrefresh$layout$constant$RefreshState = iArr;
            try {
                iArr[RefreshState.None.ordinal()] = 1;
            } catch (NoSuchFieldError e) {
            }
            try {
                $SwitchMap$com$scwang$smartrefresh$layout$constant$RefreshState[RefreshState.PullDownToRefresh.ordinal()] = 2;
            } catch (NoSuchFieldError e2) {
            }
        }
    }

    @Override // com.scwang.smartrefresh.layout.internal.InternalAbstract, com.scwang.smartrefresh.layout.listener.OnStateChangedListener
    public void onStateChanged(RefreshLayout refreshLayout, RefreshState oldState, RefreshState newState) {
        int i = AnonymousClass1.$SwitchMap$com$scwang$smartrefresh$layout$constant$RefreshState[newState.ordinal()];
        if (i == 1 || i == 2) {
            this.mDotAlpha = 1.0f;
            this.mRadarScale = 0.0f;
            this.mRippleRadius = 0.0f;
        }
    }

    @Override // com.scwang.smartrefresh.layout.internal.InternalAbstract, com.scwang.smartrefresh.layout.api.RefreshInternal
    @Deprecated
    public void setPrimaryColors(int... colors) {
        if (colors.length > 0 && !this.mManualPrimaryColor) {
            setPrimaryColor(colors[0]);
            this.mManualPrimaryColor = false;
        }
        if (colors.length > 1 && !this.mManualAccentColor) {
            setAccentColor(colors[1]);
            this.mManualAccentColor = false;
        }
    }

    @Override // com.scwang.smartrefresh.layout.internal.InternalAbstract, com.scwang.smartrefresh.layout.api.RefreshInternal
    public boolean isSupportHorizontalDrag() {
        return this.mEnableHorizontalDrag;
    }

    @Override // com.scwang.smartrefresh.layout.internal.InternalAbstract, com.scwang.smartrefresh.layout.api.RefreshInternal
    public void onHorizontalDrag(float percentX, int offsetX, int offsetMax) {
        this.mWaveOffsetX = offsetX;
        invalidate();
    }

    public BezierRadarHeader setPrimaryColor(int color) {
        this.mPrimaryColor = color;
        this.mManualPrimaryColor = true;
        return this;
    }

    public BezierRadarHeader setAccentColor(int color) {
        this.mAccentColor = color;
        this.mManualAccentColor = true;
        return this;
    }

    public BezierRadarHeader setPrimaryColorId(int colorId) {
        setPrimaryColor(ContextCompat.getColor(getContext(), colorId));
        return this;
    }

    public BezierRadarHeader setAccentColorId(int colorId) {
        setAccentColor(ContextCompat.getColor(getContext(), colorId));
        return this;
    }

    public BezierRadarHeader setEnableHorizontalDrag(boolean enable) {
        this.mEnableHorizontalDrag = enable;
        if (!enable) {
            this.mWaveOffsetX = -1;
        }
        return this;
    }

    protected class AnimatorUpdater implements ValueAnimator.AnimatorUpdateListener {
        byte propertyName;

        AnimatorUpdater(byte name) {
            this.propertyName = name;
        }

        @Override // android.animation.ValueAnimator.AnimatorUpdateListener
        public void onAnimationUpdate(ValueAnimator animation) {
            byte b = this.propertyName;
            if (b == 0) {
                BezierRadarHeader.this.mRadarScale = ((Float) animation.getAnimatedValue()).floatValue();
            } else if (1 == b) {
                if (BezierRadarHeader.this.mWavePulling) {
                    animation.cancel();
                    return;
                } else {
                    BezierRadarHeader.this.mWaveHeight = ((Integer) animation.getAnimatedValue()).intValue() / 2;
                }
            } else if (2 == b) {
                BezierRadarHeader.this.mDotAlpha = ((Float) animation.getAnimatedValue()).floatValue();
            } else if (3 == b) {
                BezierRadarHeader.this.mRippleRadius = ((Float) animation.getAnimatedValue()).floatValue();
            } else if (4 == b) {
                BezierRadarHeader.this.mRadarAngle = ((Integer) animation.getAnimatedValue()).intValue();
            }
            View thisView = BezierRadarHeader.this;
            thisView.invalidate();
        }
    }
}
