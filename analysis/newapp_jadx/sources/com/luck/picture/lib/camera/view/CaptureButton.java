package com.luck.picture.lib.camera.view;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ValueAnimator;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.os.CountDownTimer;
import android.view.MotionEvent;
import android.view.View;
import com.luck.picture.lib.camera.CheckPermission;
import com.luck.picture.lib.camera.CustomCameraView;
import com.luck.picture.lib.camera.listener.CaptureListener;
import com.luck.picture.lib.camera.view.CaptureButton;
import com.luck.picture.lib.tools.DoubleUtils;

/* loaded from: classes2.dex */
public class CaptureButton extends View {
    public static final int STATE_BAN = 5;
    public static final int STATE_IDLE = 1;
    public static final int STATE_LONG_PRESS = 3;
    public static final int STATE_PRESS = 2;
    public static final int STATE_RECORDERING = 4;
    private float button_inside_radius;
    private float button_outside_radius;
    private float button_radius;
    private int button_size;
    private int button_state;
    private CaptureListener captureLisenter;
    private float center_X;
    private float center_Y;
    private int duration;
    private float event_Y;
    private int inside_color;
    private int inside_reduce_size;
    private LongPressRunnable longPressRunnable;
    private Paint mPaint;
    private int min_duration;
    private int outside_add_size;
    private int outside_color;
    private float progress;
    private int progress_color;
    private int recorded_time;
    private RectF rectF;
    private int state;
    private float strokeWidth;
    private RecordCountDownTimer timer;

    public class LongPressRunnable implements Runnable {
        private LongPressRunnable() {
        }

        @Override // java.lang.Runnable
        public void run() {
            CaptureButton.this.state = 3;
            if (CheckPermission.getRecordState() != 1) {
                CaptureButton.this.state = 1;
                if (CaptureButton.this.captureLisenter != null) {
                    CaptureButton.this.captureLisenter.recordError();
                    return;
                }
            }
            CaptureButton captureButton = CaptureButton.this;
            captureButton.startRecordAnimation(captureButton.button_outside_radius, CaptureButton.this.button_outside_radius + CaptureButton.this.outside_add_size, CaptureButton.this.button_inside_radius, CaptureButton.this.button_inside_radius - CaptureButton.this.inside_reduce_size);
        }
    }

    public class RecordCountDownTimer extends CountDownTimer {
        public RecordCountDownTimer(long j2, long j3) {
            super(j2, j3);
        }

        @Override // android.os.CountDownTimer
        public void onFinish() {
            CaptureButton.this.recordEnd();
        }

        @Override // android.os.CountDownTimer
        public void onTick(long j2) {
            CaptureButton.this.updateProgress(j2);
        }
    }

    public CaptureButton(Context context) {
        super(context);
        this.progress_color = -300503530;
        this.outside_color = -287515428;
        this.inside_color = -1;
    }

    private void handlerPressByState() {
        int i2;
        removeCallbacks(this.longPressRunnable);
        int i3 = this.state;
        if (i3 != 2) {
            if (i3 == 3 || i3 == 4) {
                this.timer.cancel();
                recordEnd();
            }
        } else if (this.captureLisenter == null || !((i2 = this.button_state) == 257 || i2 == 259)) {
            this.state = 1;
        } else {
            startCaptureAnimation(this.button_inside_radius);
        }
        this.state = 1;
    }

    private void resetRecordAnim() {
        this.state = 5;
        this.progress = 0.0f;
        invalidate();
        float f2 = this.button_outside_radius;
        float f3 = this.button_radius;
        startRecordAnimation(f2, f3, this.button_inside_radius, 0.75f * f3);
    }

    private void startCaptureAnimation(float f2) {
        ValueAnimator ofFloat = ValueAnimator.ofFloat(f2, 0.75f * f2, f2);
        ofFloat.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() { // from class: b.t.a.a.i0.f.b
            @Override // android.animation.ValueAnimator.AnimatorUpdateListener
            public final void onAnimationUpdate(ValueAnimator valueAnimator) {
                CaptureButton.this.m4545a(valueAnimator);
            }
        });
        ofFloat.addListener(new AnimatorListenerAdapter() { // from class: com.luck.picture.lib.camera.view.CaptureButton.1
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animator) {
                super.onAnimationEnd(animator);
            }

            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationStart(Animator animator) {
                super.onAnimationStart(animator);
                if (CaptureButton.this.captureLisenter != null) {
                    CaptureButton.this.captureLisenter.takePictures();
                }
                CaptureButton.this.state = 5;
            }
        });
        ofFloat.setDuration(50L);
        ofFloat.start();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void startRecordAnimation(float f2, float f3, float f4, float f5) {
        ValueAnimator ofFloat = ValueAnimator.ofFloat(f2, f3);
        ValueAnimator ofFloat2 = ValueAnimator.ofFloat(f4, f5);
        ofFloat.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() { // from class: b.t.a.a.i0.f.c
            @Override // android.animation.ValueAnimator.AnimatorUpdateListener
            public final void onAnimationUpdate(ValueAnimator valueAnimator) {
                CaptureButton.this.m4546b(valueAnimator);
            }
        });
        ofFloat2.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() { // from class: b.t.a.a.i0.f.a
            @Override // android.animation.ValueAnimator.AnimatorUpdateListener
            public final void onAnimationUpdate(ValueAnimator valueAnimator) {
                CaptureButton.this.m4547c(valueAnimator);
            }
        });
        AnimatorSet animatorSet = new AnimatorSet();
        animatorSet.addListener(new AnimatorListenerAdapter() { // from class: com.luck.picture.lib.camera.view.CaptureButton.2
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animator) {
                super.onAnimationEnd(animator);
                if (DoubleUtils.isFastDoubleClick()) {
                    return;
                }
                if (CaptureButton.this.state != 3) {
                    CaptureButton.this.state = 1;
                    return;
                }
                if (CaptureButton.this.captureLisenter != null) {
                    CaptureButton.this.captureLisenter.recordStart();
                }
                CaptureButton.this.state = 4;
                CaptureButton.this.timer.start();
            }
        });
        animatorSet.playTogether(ofFloat, ofFloat2);
        animatorSet.setDuration(100L);
        animatorSet.start();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateProgress(long j2) {
        int i2 = this.duration;
        this.recorded_time = (int) (i2 - j2);
        this.progress = 360.0f - ((j2 / i2) * 360.0f);
        invalidate();
    }

    /* renamed from: a */
    public /* synthetic */ void m4545a(ValueAnimator valueAnimator) {
        this.button_inside_radius = ((Float) valueAnimator.getAnimatedValue()).floatValue();
        invalidate();
    }

    /* renamed from: b */
    public /* synthetic */ void m4546b(ValueAnimator valueAnimator) {
        this.button_outside_radius = ((Float) valueAnimator.getAnimatedValue()).floatValue();
        invalidate();
    }

    /* renamed from: c */
    public /* synthetic */ void m4547c(ValueAnimator valueAnimator) {
        this.button_inside_radius = ((Float) valueAnimator.getAnimatedValue()).floatValue();
        invalidate();
    }

    public int getButtonFeatures() {
        return this.button_state;
    }

    public boolean isIdle() {
        return this.state == 1;
    }

    @Override // android.view.View
    public void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        this.mPaint.setStyle(Paint.Style.FILL);
        this.mPaint.setColor(this.outside_color);
        canvas.drawCircle(this.center_X, this.center_Y, this.button_outside_radius, this.mPaint);
        this.mPaint.setColor(this.inside_color);
        canvas.drawCircle(this.center_X, this.center_Y, this.button_inside_radius, this.mPaint);
        if (this.state == 4) {
            this.mPaint.setColor(this.progress_color);
            this.mPaint.setStyle(Paint.Style.STROKE);
            this.mPaint.setStrokeWidth(this.strokeWidth);
            canvas.drawArc(this.rectF, -90.0f, this.progress, false, this.mPaint);
        }
    }

    @Override // android.view.View
    public void onMeasure(int i2, int i3) {
        super.onMeasure(i2, i3);
        int i4 = this.button_size;
        int i5 = this.outside_add_size;
        setMeasuredDimension((i5 * 2) + i4, (i5 * 2) + i4);
    }

    @Override // android.view.View
    public boolean onTouchEvent(MotionEvent motionEvent) {
        CaptureListener captureListener;
        int i2;
        int action = motionEvent.getAction();
        if (action != 0) {
            if (action == 1) {
                handlerPressByState();
            } else if (action == 2 && (captureListener = this.captureLisenter) != null && this.state == 4 && ((i2 = this.button_state) == 258 || i2 == 259)) {
                captureListener.recordZoom(this.event_Y - motionEvent.getY());
            }
        } else if (motionEvent.getPointerCount() <= 1 && this.state == 1) {
            this.event_Y = motionEvent.getY();
            this.state = 2;
            int i3 = this.button_state;
            if (i3 == 258 || i3 == 259) {
                postDelayed(this.longPressRunnable, 500L);
            }
        }
        return true;
    }

    public void recordEnd() {
        CaptureListener captureListener = this.captureLisenter;
        if (captureListener != null) {
            int i2 = this.recorded_time;
            if (i2 < this.min_duration) {
                captureListener.recordShort(i2);
            } else {
                captureListener.recordEnd(i2);
            }
        }
        resetRecordAnim();
    }

    public void resetState() {
        this.state = 1;
    }

    public void setButtonFeatures(int i2) {
        this.button_state = i2;
    }

    public void setCaptureListener(CaptureListener captureListener) {
        this.captureLisenter = captureListener;
    }

    public void setDuration(int i2) {
        this.duration = i2;
        this.timer = new RecordCountDownTimer(i2, i2 / 360);
    }

    public void setMinDuration(int i2) {
        this.min_duration = i2;
    }

    public CaptureButton(Context context, int i2) {
        super(context);
        this.progress_color = -300503530;
        this.outside_color = -287515428;
        this.inside_color = -1;
        this.button_size = i2;
        float f2 = i2 / 2.0f;
        this.button_radius = f2;
        this.button_outside_radius = f2;
        this.button_inside_radius = f2 * 0.75f;
        this.strokeWidth = i2 / 15;
        int i3 = i2 / 8;
        this.outside_add_size = i3;
        this.inside_reduce_size = i3;
        Paint paint = new Paint();
        this.mPaint = paint;
        paint.setAntiAlias(true);
        this.progress = 0.0f;
        this.longPressRunnable = new LongPressRunnable();
        this.state = 1;
        this.button_state = CustomCameraView.BUTTON_STATE_BOTH;
        this.duration = 10000;
        this.min_duration = 1500;
        int i4 = this.button_size;
        int i5 = this.outside_add_size;
        this.center_X = ((i5 * 2) + i4) / 2;
        this.center_Y = ((i5 * 2) + i4) / 2;
        float f3 = this.center_X;
        float f4 = this.button_radius;
        int i6 = this.outside_add_size;
        float f5 = this.strokeWidth;
        float f6 = this.center_Y;
        this.rectF = new RectF(f3 - ((i6 + f4) - (f5 / 2.0f)), f6 - ((i6 + f4) - (f5 / 2.0f)), ((i6 + f4) - (f5 / 2.0f)) + f3, ((f4 + i6) - (f5 / 2.0f)) + f6);
        this.timer = new RecordCountDownTimer(this.duration, r0 / 360);
    }
}
