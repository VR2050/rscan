package androidx.core.widget;

import android.content.res.Resources;
import android.os.SystemClock;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewConfiguration;
import android.view.animation.AccelerateInterpolator;
import android.view.animation.AnimationUtils;
import android.view.animation.Interpolator;
import androidx.core.view.V;

/* JADX INFO: loaded from: classes.dex */
public abstract class a implements View.OnTouchListener {

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private static final int f4555s = ViewConfiguration.getTapTimeout();

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    final View f4558d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private Runnable f4559e;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private int f4562h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private int f4563i;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private boolean f4567m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    boolean f4568n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    boolean f4569o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    boolean f4570p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private boolean f4571q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private boolean f4572r;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    final C0067a f4556b = new C0067a();

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final Interpolator f4557c = new AccelerateInterpolator();

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private float[] f4560f = {0.0f, 0.0f};

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private float[] f4561g = {Float.MAX_VALUE, Float.MAX_VALUE};

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private float[] f4564j = {0.0f, 0.0f};

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private float[] f4565k = {0.0f, 0.0f};

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private float[] f4566l = {Float.MAX_VALUE, Float.MAX_VALUE};

    /* JADX INFO: renamed from: androidx.core.widget.a$a, reason: collision with other inner class name */
    private static class C0067a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private int f4573a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private int f4574b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private float f4575c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private float f4576d;

        /* JADX INFO: renamed from: j, reason: collision with root package name */
        private float f4582j;

        /* JADX INFO: renamed from: k, reason: collision with root package name */
        private int f4583k;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private long f4577e = Long.MIN_VALUE;

        /* JADX INFO: renamed from: i, reason: collision with root package name */
        private long f4581i = -1;

        /* JADX INFO: renamed from: f, reason: collision with root package name */
        private long f4578f = 0;

        /* JADX INFO: renamed from: g, reason: collision with root package name */
        private int f4579g = 0;

        /* JADX INFO: renamed from: h, reason: collision with root package name */
        private int f4580h = 0;

        C0067a() {
        }

        private float e(long j3) {
            if (j3 < this.f4577e) {
                return 0.0f;
            }
            long j4 = this.f4581i;
            if (j4 < 0 || j3 < j4) {
                return a.e((j3 - r0) / this.f4573a, 0.0f, 1.0f) * 0.5f;
            }
            float f3 = this.f4582j;
            return (1.0f - f3) + (f3 * a.e((j3 - j4) / this.f4583k, 0.0f, 1.0f));
        }

        private float g(float f3) {
            return ((-4.0f) * f3 * f3) + (f3 * 4.0f);
        }

        public void a() {
            if (this.f4578f == 0) {
                throw new RuntimeException("Cannot compute scroll delta before calling start()");
            }
            long jCurrentAnimationTimeMillis = AnimationUtils.currentAnimationTimeMillis();
            float fG = g(e(jCurrentAnimationTimeMillis));
            long j3 = jCurrentAnimationTimeMillis - this.f4578f;
            this.f4578f = jCurrentAnimationTimeMillis;
            float f3 = j3 * fG;
            this.f4579g = (int) (this.f4575c * f3);
            this.f4580h = (int) (f3 * this.f4576d);
        }

        public int b() {
            return this.f4579g;
        }

        public int c() {
            return this.f4580h;
        }

        public int d() {
            float f3 = this.f4575c;
            return (int) (f3 / Math.abs(f3));
        }

        public int f() {
            float f3 = this.f4576d;
            return (int) (f3 / Math.abs(f3));
        }

        public boolean h() {
            return this.f4581i > 0 && AnimationUtils.currentAnimationTimeMillis() > this.f4581i + ((long) this.f4583k);
        }

        public void i() {
            long jCurrentAnimationTimeMillis = AnimationUtils.currentAnimationTimeMillis();
            this.f4583k = a.f((int) (jCurrentAnimationTimeMillis - this.f4577e), 0, this.f4574b);
            this.f4582j = e(jCurrentAnimationTimeMillis);
            this.f4581i = jCurrentAnimationTimeMillis;
        }

        public void j(int i3) {
            this.f4574b = i3;
        }

        public void k(int i3) {
            this.f4573a = i3;
        }

        public void l(float f3, float f4) {
            this.f4575c = f3;
            this.f4576d = f4;
        }

        public void m() {
            long jCurrentAnimationTimeMillis = AnimationUtils.currentAnimationTimeMillis();
            this.f4577e = jCurrentAnimationTimeMillis;
            this.f4581i = -1L;
            this.f4578f = jCurrentAnimationTimeMillis;
            this.f4582j = 0.5f;
            this.f4579g = 0;
            this.f4580h = 0;
        }
    }

    private class b implements Runnable {
        b() {
        }

        @Override // java.lang.Runnable
        public void run() {
            a aVar = a.this;
            if (aVar.f4570p) {
                if (aVar.f4568n) {
                    aVar.f4568n = false;
                    aVar.f4556b.m();
                }
                C0067a c0067a = a.this.f4556b;
                if (c0067a.h() || !a.this.u()) {
                    a.this.f4570p = false;
                    return;
                }
                a aVar2 = a.this;
                if (aVar2.f4569o) {
                    aVar2.f4569o = false;
                    aVar2.c();
                }
                c0067a.a();
                a.this.j(c0067a.b(), c0067a.c());
                V.S(a.this.f4558d, this);
            }
        }
    }

    public a(View view) {
        this.f4558d = view;
        float f3 = Resources.getSystem().getDisplayMetrics().density;
        float f4 = (int) ((1575.0f * f3) + 0.5f);
        o(f4, f4);
        float f5 = (int) ((f3 * 315.0f) + 0.5f);
        p(f5, f5);
        l(1);
        n(Float.MAX_VALUE, Float.MAX_VALUE);
        s(0.2f, 0.2f);
        t(1.0f, 1.0f);
        k(f4555s);
        r(500);
        q(500);
    }

    private float d(int i3, float f3, float f4, float f5) {
        float fH = h(this.f4560f[i3], f4, this.f4561g[i3], f3);
        if (fH == 0.0f) {
            return 0.0f;
        }
        float f6 = this.f4564j[i3];
        float f7 = this.f4565k[i3];
        float f8 = this.f4566l[i3];
        float f9 = f6 * f5;
        return fH > 0.0f ? e(fH * f9, f7, f8) : -e((-fH) * f9, f7, f8);
    }

    static float e(float f3, float f4, float f5) {
        return f3 > f5 ? f5 : f3 < f4 ? f4 : f3;
    }

    static int f(int i3, int i4, int i5) {
        return i3 > i5 ? i5 : i3 < i4 ? i4 : i3;
    }

    private float g(float f3, float f4) {
        if (f4 == 0.0f) {
            return 0.0f;
        }
        int i3 = this.f4562h;
        if (i3 == 0 || i3 == 1) {
            if (f3 < f4) {
                if (f3 >= 0.0f) {
                    return 1.0f - (f3 / f4);
                }
                if (this.f4570p && i3 == 1) {
                    return 1.0f;
                }
            }
        } else if (i3 == 2 && f3 < 0.0f) {
            return f3 / (-f4);
        }
        return 0.0f;
    }

    private float h(float f3, float f4, float f5, float f6) {
        float interpolation;
        float fE = e(f3 * f4, 0.0f, f5);
        float fG = g(f4 - f6, fE) - g(f6, fE);
        if (fG < 0.0f) {
            interpolation = -this.f4557c.getInterpolation(-fG);
        } else {
            if (fG <= 0.0f) {
                return 0.0f;
            }
            interpolation = this.f4557c.getInterpolation(fG);
        }
        return e(interpolation, -1.0f, 1.0f);
    }

    private void i() {
        if (this.f4568n) {
            this.f4570p = false;
        } else {
            this.f4556b.i();
        }
    }

    private void v() {
        int i3;
        if (this.f4559e == null) {
            this.f4559e = new b();
        }
        this.f4570p = true;
        this.f4568n = true;
        if (this.f4567m || (i3 = this.f4563i) <= 0) {
            this.f4559e.run();
        } else {
            V.T(this.f4558d, this.f4559e, i3);
        }
        this.f4567m = true;
    }

    public abstract boolean a(int i3);

    public abstract boolean b(int i3);

    void c() {
        long jUptimeMillis = SystemClock.uptimeMillis();
        MotionEvent motionEventObtain = MotionEvent.obtain(jUptimeMillis, jUptimeMillis, 3, 0.0f, 0.0f, 0);
        this.f4558d.onTouchEvent(motionEventObtain);
        motionEventObtain.recycle();
    }

    public abstract void j(int i3, int i4);

    public a k(int i3) {
        this.f4563i = i3;
        return this;
    }

    public a l(int i3) {
        this.f4562h = i3;
        return this;
    }

    public a m(boolean z3) {
        if (this.f4571q && !z3) {
            i();
        }
        this.f4571q = z3;
        return this;
    }

    public a n(float f3, float f4) {
        float[] fArr = this.f4561g;
        fArr[0] = f3;
        fArr[1] = f4;
        return this;
    }

    public a o(float f3, float f4) {
        float[] fArr = this.f4566l;
        fArr[0] = f3 / 1000.0f;
        fArr[1] = f4 / 1000.0f;
        return this;
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x0016  */
    @Override // android.view.View.OnTouchListener
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean onTouch(android.view.View r6, android.view.MotionEvent r7) {
        /*
            r5 = this;
            boolean r0 = r5.f4571q
            r1 = 0
            if (r0 != 0) goto L6
            return r1
        L6:
            int r0 = r7.getActionMasked()
            r2 = 1
            if (r0 == 0) goto L1a
            if (r0 == r2) goto L16
            r3 = 2
            if (r0 == r3) goto L1e
            r6 = 3
            if (r0 == r6) goto L16
            goto L58
        L16:
            r5.i()
            goto L58
        L1a:
            r5.f4569o = r2
            r5.f4567m = r1
        L1e:
            float r0 = r7.getX()
            int r3 = r6.getWidth()
            float r3 = (float) r3
            android.view.View r4 = r5.f4558d
            int r4 = r4.getWidth()
            float r4 = (float) r4
            float r0 = r5.d(r1, r0, r3, r4)
            float r7 = r7.getY()
            int r6 = r6.getHeight()
            float r6 = (float) r6
            android.view.View r3 = r5.f4558d
            int r3 = r3.getHeight()
            float r3 = (float) r3
            float r6 = r5.d(r2, r7, r6, r3)
            androidx.core.widget.a$a r7 = r5.f4556b
            r7.l(r0, r6)
            boolean r6 = r5.f4570p
            if (r6 != 0) goto L58
            boolean r6 = r5.u()
            if (r6 == 0) goto L58
            r5.v()
        L58:
            boolean r6 = r5.f4572r
            if (r6 == 0) goto L61
            boolean r6 = r5.f4570p
            if (r6 == 0) goto L61
            r1 = r2
        L61:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.core.widget.a.onTouch(android.view.View, android.view.MotionEvent):boolean");
    }

    public a p(float f3, float f4) {
        float[] fArr = this.f4565k;
        fArr[0] = f3 / 1000.0f;
        fArr[1] = f4 / 1000.0f;
        return this;
    }

    public a q(int i3) {
        this.f4556b.j(i3);
        return this;
    }

    public a r(int i3) {
        this.f4556b.k(i3);
        return this;
    }

    public a s(float f3, float f4) {
        float[] fArr = this.f4560f;
        fArr[0] = f3;
        fArr[1] = f4;
        return this;
    }

    public a t(float f3, float f4) {
        float[] fArr = this.f4564j;
        fArr[0] = f3 / 1000.0f;
        fArr[1] = f4 / 1000.0f;
        return this;
    }

    boolean u() {
        C0067a c0067a = this.f4556b;
        int iF = c0067a.f();
        int iD = c0067a.d();
        return (iF != 0 && b(iF)) || (iD != 0 && a(iD));
    }
}
