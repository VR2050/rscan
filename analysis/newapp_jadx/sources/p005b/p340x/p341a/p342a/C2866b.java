package p005b.p340x.p341a.p342a;

import android.animation.ValueAnimator;
import android.graphics.Canvas;
import android.graphics.Path;
import android.graphics.Rect;
import android.graphics.drawable.Animatable;
import androidx.annotation.NonNull;
import androidx.work.WorkRequest;

/* renamed from: b.x.a.a.b */
/* loaded from: classes2.dex */
public class C2866b extends AbstractC2865a implements Animatable, ValueAnimator.AnimatorUpdateListener {

    /* renamed from: h */
    public ValueAnimator f7806h;

    /* renamed from: e */
    public int f7803e = 0;

    /* renamed from: f */
    public int f7804f = 0;

    /* renamed from: g */
    public int f7805g = 0;

    /* renamed from: i */
    public Path f7807i = new Path();

    public C2866b() {
        ValueAnimator ofInt = ValueAnimator.ofInt(30, 3600);
        this.f7806h = ofInt;
        ofInt.setDuration(WorkRequest.MIN_BACKOFF_MILLIS);
        this.f7806h.setInterpolator(null);
        this.f7806h.setRepeatCount(-1);
        this.f7806h.setRepeatMode(1);
    }

    @Override // android.graphics.drawable.Drawable
    public void draw(@NonNull Canvas canvas) {
        Rect bounds = getBounds();
        int width = bounds.width();
        int height = bounds.height();
        float f2 = width;
        float max = Math.max(1.0f, f2 / 22.0f);
        if (this.f7803e != width || this.f7804f != height) {
            this.f7807i.reset();
            float f3 = f2 - max;
            float f4 = height / 2.0f;
            this.f7807i.addCircle(f3, f4, max, Path.Direction.CW);
            float f5 = f2 - (5.0f * max);
            this.f7807i.addRect(f5, f4 - max, f3, f4 + max, Path.Direction.CW);
            this.f7807i.addCircle(f5, f4, max, Path.Direction.CW);
            this.f7803e = width;
            this.f7804f = height;
        }
        canvas.save();
        float f6 = f2 / 2.0f;
        float f7 = height / 2.0f;
        canvas.rotate(this.f7805g, f6, f7);
        for (int i2 = 0; i2 < 12; i2++) {
            this.f7802c.setAlpha((i2 + 5) * 17);
            canvas.rotate(30.0f, f6, f7);
            canvas.drawPath(this.f7807i, this.f7802c);
        }
        canvas.restore();
    }

    @Override // android.graphics.drawable.Animatable
    public boolean isRunning() {
        return this.f7806h.isRunning();
    }

    @Override // android.animation.ValueAnimator.AnimatorUpdateListener
    public void onAnimationUpdate(ValueAnimator valueAnimator) {
        this.f7805g = (((Integer) valueAnimator.getAnimatedValue()).intValue() / 30) * 30;
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Animatable
    public void start() {
        if (this.f7806h.isRunning()) {
            return;
        }
        this.f7806h.addUpdateListener(this);
        this.f7806h.start();
    }

    @Override // android.graphics.drawable.Animatable
    public void stop() {
        if (this.f7806h.isRunning()) {
            this.f7806h.removeAllListeners();
            this.f7806h.removeAllUpdateListeners();
            this.f7806h.cancel();
        }
    }
}
