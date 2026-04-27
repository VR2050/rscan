package androidx.swiperefreshlayout.widget;

import android.animation.Animator;
import android.animation.ValueAnimator;
import android.content.Context;
import android.content.res.Resources;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.drawable.Animatable;
import android.graphics.drawable.Drawable;
import android.view.animation.Interpolator;
import android.view.animation.LinearInterpolator;
import q.g;

/* JADX INFO: loaded from: classes.dex */
public class b extends Drawable implements Animatable {

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private static final Interpolator f5287h = new LinearInterpolator();

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private static final Interpolator f5288i = new C.a();

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private static final int[] f5289j = {-16777216};

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final c f5290b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private float f5291c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private Resources f5292d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private Animator f5293e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    float f5294f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    boolean f5295g;

    class a implements ValueAnimator.AnimatorUpdateListener {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ c f5296a;

        a(c cVar) {
            this.f5296a = cVar;
        }

        @Override // android.animation.ValueAnimator.AnimatorUpdateListener
        public void onAnimationUpdate(ValueAnimator valueAnimator) {
            float fFloatValue = ((Float) valueAnimator.getAnimatedValue()).floatValue();
            b.this.n(fFloatValue, this.f5296a);
            b.this.b(fFloatValue, this.f5296a, false);
            b.this.invalidateSelf();
        }
    }

    /* JADX INFO: renamed from: androidx.swiperefreshlayout.widget.b$b, reason: collision with other inner class name */
    class C0083b implements Animator.AnimatorListener {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ c f5298a;

        C0083b(c cVar) {
            this.f5298a = cVar;
        }

        @Override // android.animation.Animator.AnimatorListener
        public void onAnimationCancel(Animator animator) {
        }

        @Override // android.animation.Animator.AnimatorListener
        public void onAnimationEnd(Animator animator) {
        }

        @Override // android.animation.Animator.AnimatorListener
        public void onAnimationRepeat(Animator animator) {
            b.this.b(1.0f, this.f5298a, true);
            this.f5298a.A();
            this.f5298a.l();
            b bVar = b.this;
            if (!bVar.f5295g) {
                bVar.f5294f += 1.0f;
                return;
            }
            bVar.f5295g = false;
            animator.cancel();
            animator.setDuration(1332L);
            animator.start();
            this.f5298a.x(false);
        }

        @Override // android.animation.Animator.AnimatorListener
        public void onAnimationStart(Animator animator) {
            b.this.f5294f = 0.0f;
        }
    }

    private static class c {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final RectF f5300a = new RectF();

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final Paint f5301b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final Paint f5302c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final Paint f5303d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        float f5304e;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        float f5305f;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        float f5306g;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        float f5307h;

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        int[] f5308i;

        /* JADX INFO: renamed from: j, reason: collision with root package name */
        int f5309j;

        /* JADX INFO: renamed from: k, reason: collision with root package name */
        float f5310k;

        /* JADX INFO: renamed from: l, reason: collision with root package name */
        float f5311l;

        /* JADX INFO: renamed from: m, reason: collision with root package name */
        float f5312m;

        /* JADX INFO: renamed from: n, reason: collision with root package name */
        boolean f5313n;

        /* JADX INFO: renamed from: o, reason: collision with root package name */
        Path f5314o;

        /* JADX INFO: renamed from: p, reason: collision with root package name */
        float f5315p;

        /* JADX INFO: renamed from: q, reason: collision with root package name */
        float f5316q;

        /* JADX INFO: renamed from: r, reason: collision with root package name */
        int f5317r;

        /* JADX INFO: renamed from: s, reason: collision with root package name */
        int f5318s;

        /* JADX INFO: renamed from: t, reason: collision with root package name */
        int f5319t;

        /* JADX INFO: renamed from: u, reason: collision with root package name */
        int f5320u;

        c() {
            Paint paint = new Paint();
            this.f5301b = paint;
            Paint paint2 = new Paint();
            this.f5302c = paint2;
            Paint paint3 = new Paint();
            this.f5303d = paint3;
            this.f5304e = 0.0f;
            this.f5305f = 0.0f;
            this.f5306g = 0.0f;
            this.f5307h = 5.0f;
            this.f5315p = 1.0f;
            this.f5319t = 255;
            paint.setStrokeCap(Paint.Cap.SQUARE);
            paint.setAntiAlias(true);
            paint.setStyle(Paint.Style.STROKE);
            paint2.setStyle(Paint.Style.FILL);
            paint2.setAntiAlias(true);
            paint3.setColor(0);
        }

        void A() {
            this.f5310k = this.f5304e;
            this.f5311l = this.f5305f;
            this.f5312m = this.f5306g;
        }

        void a(Canvas canvas, Rect rect) {
            RectF rectF = this.f5300a;
            float f3 = this.f5316q;
            float fMin = (this.f5307h / 2.0f) + f3;
            if (f3 <= 0.0f) {
                fMin = (Math.min(rect.width(), rect.height()) / 2.0f) - Math.max((this.f5317r * this.f5315p) / 2.0f, this.f5307h / 2.0f);
            }
            rectF.set(rect.centerX() - fMin, rect.centerY() - fMin, rect.centerX() + fMin, rect.centerY() + fMin);
            float f4 = this.f5304e;
            float f5 = this.f5306g;
            float f6 = (f4 + f5) * 360.0f;
            float f7 = ((this.f5305f + f5) * 360.0f) - f6;
            this.f5301b.setColor(this.f5320u);
            this.f5301b.setAlpha(this.f5319t);
            float f8 = this.f5307h / 2.0f;
            rectF.inset(f8, f8);
            canvas.drawCircle(rectF.centerX(), rectF.centerY(), rectF.width() / 2.0f, this.f5303d);
            float f9 = -f8;
            rectF.inset(f9, f9);
            canvas.drawArc(rectF, f6, f7, false, this.f5301b);
            b(canvas, f6, f7, rectF);
        }

        void b(Canvas canvas, float f3, float f4, RectF rectF) {
            if (this.f5313n) {
                Path path = this.f5314o;
                if (path == null) {
                    Path path2 = new Path();
                    this.f5314o = path2;
                    path2.setFillType(Path.FillType.EVEN_ODD);
                } else {
                    path.reset();
                }
                float fMin = Math.min(rectF.width(), rectF.height()) / 2.0f;
                float f5 = (this.f5317r * this.f5315p) / 2.0f;
                this.f5314o.moveTo(0.0f, 0.0f);
                this.f5314o.lineTo(this.f5317r * this.f5315p, 0.0f);
                Path path3 = this.f5314o;
                float f6 = this.f5317r;
                float f7 = this.f5315p;
                path3.lineTo((f6 * f7) / 2.0f, this.f5318s * f7);
                this.f5314o.offset((fMin + rectF.centerX()) - f5, rectF.centerY() + (this.f5307h / 2.0f));
                this.f5314o.close();
                this.f5302c.setColor(this.f5320u);
                this.f5302c.setAlpha(this.f5319t);
                canvas.save();
                canvas.rotate(f3 + f4, rectF.centerX(), rectF.centerY());
                canvas.drawPath(this.f5314o, this.f5302c);
                canvas.restore();
            }
        }

        int c() {
            return this.f5319t;
        }

        float d() {
            return this.f5305f;
        }

        int e() {
            return this.f5308i[f()];
        }

        int f() {
            return (this.f5309j + 1) % this.f5308i.length;
        }

        float g() {
            return this.f5304e;
        }

        int h() {
            return this.f5308i[this.f5309j];
        }

        float i() {
            return this.f5311l;
        }

        float j() {
            return this.f5312m;
        }

        float k() {
            return this.f5310k;
        }

        void l() {
            t(f());
        }

        void m() {
            this.f5310k = 0.0f;
            this.f5311l = 0.0f;
            this.f5312m = 0.0f;
            y(0.0f);
            v(0.0f);
            w(0.0f);
        }

        void n(int i3) {
            this.f5319t = i3;
        }

        void o(float f3, float f4) {
            this.f5317r = (int) f3;
            this.f5318s = (int) f4;
        }

        void p(float f3) {
            if (f3 != this.f5315p) {
                this.f5315p = f3;
            }
        }

        void q(float f3) {
            this.f5316q = f3;
        }

        void r(int i3) {
            this.f5320u = i3;
        }

        void s(ColorFilter colorFilter) {
            this.f5301b.setColorFilter(colorFilter);
        }

        void t(int i3) {
            this.f5309j = i3;
            this.f5320u = this.f5308i[i3];
        }

        void u(int[] iArr) {
            this.f5308i = iArr;
            t(0);
        }

        void v(float f3) {
            this.f5305f = f3;
        }

        void w(float f3) {
            this.f5306g = f3;
        }

        void x(boolean z3) {
            if (this.f5313n != z3) {
                this.f5313n = z3;
            }
        }

        void y(float f3) {
            this.f5304e = f3;
        }

        void z(float f3) {
            this.f5307h = f3;
            this.f5301b.setStrokeWidth(f3);
        }
    }

    public b(Context context) {
        this.f5292d = ((Context) g.f(context)).getResources();
        c cVar = new c();
        this.f5290b = cVar;
        cVar.u(f5289j);
        k(2.5f);
        m();
    }

    private void a(float f3, c cVar) {
        n(f3, cVar);
        float fFloor = (float) (Math.floor(cVar.j() / 0.8f) + 1.0d);
        cVar.y(cVar.k() + (((cVar.i() - 0.01f) - cVar.k()) * f3));
        cVar.v(cVar.i());
        cVar.w(cVar.j() + ((fFloor - cVar.j()) * f3));
    }

    private int c(float f3, int i3, int i4) {
        return ((((i3 >> 24) & 255) + ((int) ((((i4 >> 24) & 255) - r0) * f3))) << 24) | ((((i3 >> 16) & 255) + ((int) ((((i4 >> 16) & 255) - r1) * f3))) << 16) | ((((i3 >> 8) & 255) + ((int) ((((i4 >> 8) & 255) - r2) * f3))) << 8) | ((i3 & 255) + ((int) (f3 * ((i4 & 255) - r8))));
    }

    private void h(float f3) {
        this.f5291c = f3;
    }

    private void i(float f3, float f4, float f5, float f6) {
        c cVar = this.f5290b;
        float f7 = this.f5292d.getDisplayMetrics().density;
        cVar.z(f4 * f7);
        cVar.q(f3 * f7);
        cVar.t(0);
        cVar.o(f5 * f7, f6 * f7);
    }

    private void m() {
        c cVar = this.f5290b;
        ValueAnimator valueAnimatorOfFloat = ValueAnimator.ofFloat(0.0f, 1.0f);
        valueAnimatorOfFloat.addUpdateListener(new a(cVar));
        valueAnimatorOfFloat.setRepeatCount(-1);
        valueAnimatorOfFloat.setRepeatMode(1);
        valueAnimatorOfFloat.setInterpolator(f5287h);
        valueAnimatorOfFloat.addListener(new C0083b(cVar));
        this.f5293e = valueAnimatorOfFloat;
    }

    void b(float f3, c cVar, boolean z3) {
        float interpolation;
        float interpolation2;
        if (this.f5295g) {
            a(f3, cVar);
            return;
        }
        if (f3 != 1.0f || z3) {
            float fJ = cVar.j();
            if (f3 < 0.5f) {
                interpolation = cVar.k();
                interpolation2 = (f5288i.getInterpolation(f3 / 0.5f) * 0.79f) + 0.01f + interpolation;
            } else {
                float fK = cVar.k() + 0.79f;
                interpolation = fK - (((1.0f - f5288i.getInterpolation((f3 - 0.5f) / 0.5f)) * 0.79f) + 0.01f);
                interpolation2 = fK;
            }
            float f4 = fJ + (0.20999998f * f3);
            float f5 = (f3 + this.f5294f) * 216.0f;
            cVar.y(interpolation);
            cVar.v(interpolation2);
            cVar.w(f4);
            h(f5);
        }
    }

    public void d(boolean z3) {
        this.f5290b.x(z3);
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public void draw(Canvas canvas) {
        Rect bounds = getBounds();
        canvas.save();
        canvas.rotate(this.f5291c, bounds.exactCenterX(), bounds.exactCenterY());
        this.f5290b.a(canvas, bounds);
        canvas.restore();
    }

    public void e(float f3) {
        this.f5290b.p(f3);
        invalidateSelf();
    }

    public void f(int... iArr) {
        this.f5290b.u(iArr);
        this.f5290b.t(0);
        invalidateSelf();
    }

    public void g(float f3) {
        this.f5290b.w(f3);
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public int getAlpha() {
        return this.f5290b.c();
    }

    @Override // android.graphics.drawable.Drawable
    public int getOpacity() {
        return -3;
    }

    @Override // android.graphics.drawable.Animatable
    public boolean isRunning() {
        return this.f5293e.isRunning();
    }

    public void j(float f3, float f4) {
        this.f5290b.y(f3);
        this.f5290b.v(f4);
        invalidateSelf();
    }

    public void k(float f3) {
        this.f5290b.z(f3);
        invalidateSelf();
    }

    public void l(int i3) {
        if (i3 == 0) {
            i(11.0f, 3.0f, 12.0f, 6.0f);
        } else {
            i(7.5f, 2.5f, 10.0f, 5.0f);
        }
        invalidateSelf();
    }

    void n(float f3, c cVar) {
        if (f3 > 0.75f) {
            cVar.r(c((f3 - 0.75f) / 0.25f, cVar.h(), cVar.e()));
        } else {
            cVar.r(cVar.h());
        }
    }

    @Override // android.graphics.drawable.Drawable
    public void setAlpha(int i3) {
        this.f5290b.n(i3);
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public void setColorFilter(ColorFilter colorFilter) {
        this.f5290b.s(colorFilter);
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Animatable
    public void start() {
        this.f5293e.cancel();
        this.f5290b.A();
        if (this.f5290b.d() != this.f5290b.g()) {
            this.f5295g = true;
            this.f5293e.setDuration(666L);
            this.f5293e.start();
        } else {
            this.f5290b.t(0);
            this.f5290b.m();
            this.f5293e.setDuration(1332L);
            this.f5293e.start();
        }
    }

    @Override // android.graphics.drawable.Animatable
    public void stop() {
        this.f5293e.cancel();
        h(0.0f);
        this.f5290b.x(false);
        this.f5290b.t(0);
        this.f5290b.m();
        invalidateSelf();
    }
}
