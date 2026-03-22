package p005b.p340x.p354b.p355a.p359e;

import android.animation.ValueAnimator;
import android.graphics.Canvas;
import android.graphics.Path;
import android.graphics.Rect;
import android.graphics.drawable.Animatable;
import androidx.annotation.NonNull;
import androidx.work.WorkRequest;

/* renamed from: b.x.b.a.e.c */
/* loaded from: classes2.dex */
public class C2909c extends AbstractC2908b implements Animatable, ValueAnimator.AnimatorUpdateListener {

    /* renamed from: h */
    public ValueAnimator f7981h;

    /* renamed from: e */
    public int f7978e = 0;

    /* renamed from: f */
    public int f7979f = 0;

    /* renamed from: g */
    public int f7980g = 0;

    /* renamed from: i */
    public Path f7982i = new Path();

    public C2909c() {
        ValueAnimator ofInt = ValueAnimator.ofInt(30, 3600);
        this.f7981h = ofInt;
        ofInt.setDuration(WorkRequest.MIN_BACKOFF_MILLIS);
        this.f7981h.setInterpolator(null);
        this.f7981h.setRepeatCount(-1);
        this.f7981h.setRepeatMode(1);
    }

    @Override // android.graphics.drawable.Drawable
    public void draw(@NonNull Canvas canvas) {
        Rect bounds = getBounds();
        int width = bounds.width();
        int height = bounds.height();
        float f2 = width;
        float max = Math.max(1.0f, f2 / 22.0f);
        if (this.f7978e != width || this.f7979f != height) {
            this.f7982i.reset();
            float f3 = f2 - max;
            float f4 = height / 2.0f;
            this.f7982i.addCircle(f3, f4, max, Path.Direction.CW);
            float f5 = f2 - (5.0f * max);
            this.f7982i.addRect(f5, f4 - max, f3, f4 + max, Path.Direction.CW);
            this.f7982i.addCircle(f5, f4, max, Path.Direction.CW);
            this.f7978e = width;
            this.f7979f = height;
        }
        canvas.save();
        float f6 = f2 / 2.0f;
        float f7 = height / 2.0f;
        canvas.rotate(this.f7980g, f6, f7);
        for (int i2 = 0; i2 < 12; i2++) {
            this.f7977c.setAlpha((i2 + 5) * 17);
            canvas.rotate(30.0f, f6, f7);
            canvas.drawPath(this.f7982i, this.f7977c);
        }
        canvas.restore();
    }

    @Override // android.graphics.drawable.Animatable
    public boolean isRunning() {
        return this.f7981h.isRunning();
    }

    @Override // android.animation.ValueAnimator.AnimatorUpdateListener
    public void onAnimationUpdate(ValueAnimator valueAnimator) {
        this.f7980g = (((Integer) valueAnimator.getAnimatedValue()).intValue() / 30) * 30;
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Animatable
    public void start() {
        if (this.f7981h.isRunning()) {
            return;
        }
        this.f7981h.addUpdateListener(this);
        this.f7981h.start();
    }

    @Override // android.graphics.drawable.Animatable
    public void stop() {
        if (this.f7981h.isRunning()) {
            this.f7981h.removeAllListeners();
            this.f7981h.removeAllUpdateListeners();
            this.f7981h.cancel();
        }
    }
}
