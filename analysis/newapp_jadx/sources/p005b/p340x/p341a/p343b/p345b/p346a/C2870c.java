package p005b.p340x.p341a.p343b.p345b.p346a;

import android.content.res.Resources;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.drawable.Animatable;
import android.graphics.drawable.Drawable;
import android.view.View;
import android.view.animation.Animation;
import android.view.animation.Interpolator;
import android.view.animation.LinearInterpolator;
import androidx.annotation.NonNull;
import androidx.core.view.ViewCompat;
import androidx.interpolator.view.animation.FastOutSlowInInterpolator;
import com.google.android.material.shadow.ShadowDrawableWrapper;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/* renamed from: b.x.a.b.b.a.c */
/* loaded from: classes2.dex */
public class C2870c extends Drawable implements Animatable {

    /* renamed from: c */
    public static final Interpolator f7815c = new LinearInterpolator();

    /* renamed from: e */
    public static final Interpolator f7816e = new FastOutSlowInInterpolator();

    /* renamed from: f */
    public static final int[] f7817f = {ViewCompat.MEASURED_STATE_MASK};

    /* renamed from: g */
    public final List<Animation> f7818g = new ArrayList();

    /* renamed from: h */
    public final a f7819h;

    /* renamed from: i */
    public float f7820i;

    /* renamed from: j */
    public View f7821j;

    /* renamed from: k */
    public Animation f7822k;

    /* renamed from: l */
    public float f7823l;

    /* renamed from: m */
    public float f7824m;

    /* renamed from: n */
    public float f7825n;

    /* renamed from: o */
    public boolean f7826o;

    /* renamed from: b.x.a.b.b.a.c$a */
    public class a {

        /* renamed from: a */
        public final RectF f7827a = new RectF();

        /* renamed from: b */
        public final Paint f7828b;

        /* renamed from: c */
        public final Paint f7829c;

        /* renamed from: d */
        public float f7830d;

        /* renamed from: e */
        public float f7831e;

        /* renamed from: f */
        public float f7832f;

        /* renamed from: g */
        public float f7833g;

        /* renamed from: h */
        public float f7834h;

        /* renamed from: i */
        public int[] f7835i;

        /* renamed from: j */
        public int f7836j;

        /* renamed from: k */
        public float f7837k;

        /* renamed from: l */
        public float f7838l;

        /* renamed from: m */
        public float f7839m;

        /* renamed from: n */
        public boolean f7840n;

        /* renamed from: o */
        public Path f7841o;

        /* renamed from: p */
        public float f7842p;

        /* renamed from: q */
        public double f7843q;

        /* renamed from: r */
        public int f7844r;

        /* renamed from: s */
        public int f7845s;

        /* renamed from: t */
        public int f7846t;

        public a(C2870c c2870c) {
            Paint paint = new Paint();
            this.f7828b = paint;
            Paint paint2 = new Paint();
            this.f7829c = paint2;
            this.f7830d = 0.0f;
            this.f7831e = 0.0f;
            this.f7832f = 0.0f;
            this.f7833g = 5.0f;
            this.f7834h = 2.5f;
            paint.setStrokeCap(Paint.Cap.SQUARE);
            paint.setAntiAlias(true);
            paint.setStyle(Paint.Style.STROKE);
            paint2.setStyle(Paint.Style.FILL);
            paint2.setAntiAlias(true);
        }

        /* renamed from: a */
        public void m3313a(int i2) {
            this.f7836j = i2;
            this.f7846t = this.f7835i[i2];
        }
    }

    public C2870c(View view) {
        a aVar = new a(this);
        this.f7819h = aVar;
        this.f7821j = view;
        aVar.f7835i = f7817f;
        aVar.m3313a(0);
        m3309b(40, 40, 8.75f, 2.5f, 10.0f, 5.0f);
        C2868a c2868a = new C2868a(this, aVar);
        c2868a.setRepeatCount(-1);
        c2868a.setRepeatMode(1);
        c2868a.setInterpolator(f7815c);
        c2868a.setAnimationListener(new AnimationAnimationListenerC2869b(this, aVar));
        this.f7822k = c2868a;
    }

    /* renamed from: a */
    public void m3308a(float f2) {
        this.f7819h.f7832f = f2;
        invalidateSelf();
    }

    /* renamed from: b */
    public final void m3309b(int i2, int i3, float f2, float f3, float f4, float f5) {
        float f6 = Resources.getSystem().getDisplayMetrics().density;
        this.f7824m = i2 * f6;
        this.f7825n = i3 * f6;
        this.f7819h.m3313a(0);
        float f7 = f3 * f6;
        this.f7819h.f7828b.setStrokeWidth(f7);
        a aVar = this.f7819h;
        aVar.f7833g = f7;
        aVar.f7843q = f2 * f6;
        aVar.f7844r = (int) (f4 * f6);
        aVar.f7845s = (int) (f5 * f6);
        int i4 = (int) this.f7824m;
        int i5 = (int) this.f7825n;
        Objects.requireNonNull(aVar);
        float min = Math.min(i4, i5);
        double d2 = aVar.f7843q;
        aVar.f7834h = (float) ((d2 <= ShadowDrawableWrapper.COS_45 || min < 0.0f) ? Math.ceil(aVar.f7833g / 2.0f) : (min / 2.0f) - d2);
        invalidateSelf();
    }

    /* renamed from: c */
    public void m3310c(float f2, float f3) {
        a aVar = this.f7819h;
        aVar.f7830d = f2;
        aVar.f7831e = f3;
        invalidateSelf();
    }

    /* renamed from: d */
    public void m3311d(boolean z) {
        a aVar = this.f7819h;
        if (aVar.f7840n != z) {
            aVar.f7840n = z;
            invalidateSelf();
        }
    }

    @Override // android.graphics.drawable.Drawable
    public void draw(@NonNull Canvas canvas) {
        Rect bounds = getBounds();
        int save = canvas.save();
        canvas.rotate(this.f7820i, bounds.exactCenterX(), bounds.exactCenterY());
        a aVar = this.f7819h;
        RectF rectF = aVar.f7827a;
        rectF.set(bounds);
        float f2 = aVar.f7834h;
        rectF.inset(f2, f2);
        float f3 = aVar.f7830d;
        float f4 = aVar.f7832f;
        float f5 = (f3 + f4) * 360.0f;
        float f6 = ((aVar.f7831e + f4) * 360.0f) - f5;
        if (f6 != 0.0f) {
            aVar.f7828b.setColor(aVar.f7846t);
            canvas.drawArc(rectF, f5, f6, false, aVar.f7828b);
        }
        if (aVar.f7840n) {
            Path path = aVar.f7841o;
            if (path == null) {
                Path path2 = new Path();
                aVar.f7841o = path2;
                path2.setFillType(Path.FillType.EVEN_ODD);
            } else {
                path.reset();
            }
            float f7 = (((int) aVar.f7834h) / 2) * aVar.f7842p;
            float cos = (float) ((Math.cos(ShadowDrawableWrapper.COS_45) * aVar.f7843q) + bounds.exactCenterX());
            float sin = (float) ((Math.sin(ShadowDrawableWrapper.COS_45) * aVar.f7843q) + bounds.exactCenterY());
            aVar.f7841o.moveTo(0.0f, 0.0f);
            aVar.f7841o.lineTo(aVar.f7844r * aVar.f7842p, 0.0f);
            Path path3 = aVar.f7841o;
            float f8 = aVar.f7844r;
            float f9 = aVar.f7842p;
            path3.lineTo((f8 * f9) / 2.0f, aVar.f7845s * f9);
            aVar.f7841o.offset(cos - f7, sin);
            aVar.f7841o.close();
            aVar.f7829c.setColor(aVar.f7846t);
            canvas.rotate((f5 + f6) - 5.0f, bounds.exactCenterX(), bounds.exactCenterY());
            canvas.drawPath(aVar.f7841o, aVar.f7829c);
        }
        canvas.restoreToCount(save);
    }

    /* renamed from: e */
    public void m3312e(float f2, a aVar) {
        if (f2 > 0.75f) {
            float f3 = (f2 - 0.75f) / 0.25f;
            int[] iArr = aVar.f7835i;
            int i2 = aVar.f7836j;
            int i3 = iArr[i2];
            int i4 = iArr[(i2 + 1) % iArr.length];
            aVar.f7846t = ((((i3 >> 24) & 255) + ((int) ((((i4 >> 24) & 255) - r1) * f3))) << 24) | ((((i3 >> 16) & 255) + ((int) ((((i4 >> 16) & 255) - r3) * f3))) << 16) | ((((i3 >> 8) & 255) + ((int) ((((i4 >> 8) & 255) - r4) * f3))) << 8) | ((i3 & 255) + ((int) (f3 * ((i4 & 255) - r2))));
        }
    }

    @Override // android.graphics.drawable.Drawable
    public int getIntrinsicHeight() {
        return (int) this.f7825n;
    }

    @Override // android.graphics.drawable.Drawable
    public int getIntrinsicWidth() {
        return (int) this.f7824m;
    }

    @Override // android.graphics.drawable.Drawable
    public int getOpacity() {
        return -3;
    }

    @Override // android.graphics.drawable.Animatable
    public boolean isRunning() {
        List<Animation> list = this.f7818g;
        int size = list.size();
        for (int i2 = 0; i2 < size; i2++) {
            Animation animation = list.get(i2);
            if (animation.hasStarted() && !animation.hasEnded()) {
                return true;
            }
        }
        return false;
    }

    @Override // android.graphics.drawable.Drawable
    public void setAlpha(int i2) {
    }

    @Override // android.graphics.drawable.Drawable
    public void setColorFilter(ColorFilter colorFilter) {
        this.f7819h.f7828b.setColorFilter(colorFilter);
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Animatable
    public void start() {
        this.f7822k.reset();
        a aVar = this.f7819h;
        float f2 = aVar.f7830d;
        aVar.f7837k = f2;
        float f3 = aVar.f7831e;
        aVar.f7838l = f3;
        aVar.f7839m = aVar.f7832f;
        if (f3 != f2) {
            this.f7826o = true;
            this.f7822k.setDuration(666L);
            this.f7821j.startAnimation(this.f7822k);
            return;
        }
        aVar.m3313a(0);
        a aVar2 = this.f7819h;
        aVar2.f7837k = 0.0f;
        aVar2.f7838l = 0.0f;
        aVar2.f7839m = 0.0f;
        aVar2.f7830d = 0.0f;
        aVar2.f7831e = 0.0f;
        aVar2.f7832f = 0.0f;
        this.f7822k.setDuration(1332L);
        this.f7821j.startAnimation(this.f7822k);
    }

    @Override // android.graphics.drawable.Animatable
    public void stop() {
        this.f7821j.clearAnimation();
        this.f7819h.m3313a(0);
        a aVar = this.f7819h;
        aVar.f7837k = 0.0f;
        aVar.f7838l = 0.0f;
        aVar.f7839m = 0.0f;
        aVar.f7830d = 0.0f;
        aVar.f7831e = 0.0f;
        aVar.f7832f = 0.0f;
        m3311d(false);
        this.f7820i = 0.0f;
        invalidateSelf();
    }
}
