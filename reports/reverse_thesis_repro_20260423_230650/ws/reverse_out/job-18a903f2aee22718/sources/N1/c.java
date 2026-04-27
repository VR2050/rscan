package N1;

import Q1.n;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.ColorFilter;
import android.graphics.DashPathEffect;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.PathEffect;
import android.graphics.PointF;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.Region;
import android.graphics.drawable.Drawable;
import android.os.Build;
import com.facebook.react.uimanager.C0444f0;
import com.facebook.react.uimanager.C0483z0;
import com.facebook.react.uimanager.L;
import h2.C0562h;
import h2.r;
import k2.AbstractC0605a;
import t2.u;

/* JADX INFO: loaded from: classes.dex */
public final class c extends Drawable {

    /* JADX INFO: renamed from: z, reason: collision with root package name */
    static final /* synthetic */ x2.g[] f1918z = {u.d(new t2.m(c.class, "borderStyle", "getBorderStyle()Lcom/facebook/react/uimanager/style/BorderStyle;", 0))};

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Context f1919a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final C0483z0 f1920b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private Q1.e f1921c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private Q1.c f1922d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final v2.b f1923e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private Integer[] f1924f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private Q1.h f1925g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private Q1.j f1926h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private int f1927i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final float f1928j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private Path f1929k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private final Paint f1930l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private boolean f1931m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private Path f1932n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private Path f1933o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private Path f1934p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private Path f1935q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private Path f1936r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private PointF f1937s;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private PointF f1938t;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    private PointF f1939u;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    private PointF f1940v;

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    private RectF f1941w;

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    private RectF f1942x;

    /* JADX INFO: renamed from: y, reason: collision with root package name */
    private RectF f1943y;

    public /* synthetic */ class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        public static final /* synthetic */ int[] f1944a;

        static {
            int[] iArr = new int[Q1.f.values().length];
            try {
                iArr[Q1.f.f2432c.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                iArr[Q1.f.f2433d.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                iArr[Q1.f.f2434e.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            f1944a = iArr;
        }
    }

    public static final class b extends v2.a {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ c f1945b;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        b(Object obj, c cVar) {
            super(obj);
            this.f1945b = cVar;
        }

        @Override // v2.a
        protected void c(x2.g gVar, Object obj, Object obj2) {
            t2.j.f(gVar, "property");
            if (t2.j.b(obj, obj2)) {
                return;
            }
            this.f1945b.f1931m = true;
            this.f1945b.invalidateSelf();
        }
    }

    public c(Context context, C0483z0 c0483z0, Q1.e eVar, Q1.c cVar, Q1.f fVar) {
        t2.j.f(context, "context");
        this.f1919a = context;
        this.f1920b = c0483z0;
        this.f1921c = eVar;
        this.f1922d = cVar;
        this.f1923e = m(fVar);
        this.f1925g = new Q1.h(0, 0, 0, 0, 15, null);
        this.f1927i = 255;
        this.f1928j = 0.8f;
        this.f1930l = new Paint(1);
        this.f1931m = true;
    }

    private final RectF b() {
        RectF rectFA;
        Q1.c cVar = this.f1922d;
        if (cVar == null || (rectFA = cVar.a(getLayoutDirection(), this.f1919a)) == null) {
            return new RectF(0.0f, 0.0f, 0.0f, 0.0f);
        }
        return new RectF(Float.isNaN(rectFA.left) ? 0.0f : C0444f0.f7603a.b(rectFA.left), Float.isNaN(rectFA.top) ? 0.0f : C0444f0.f7603a.b(rectFA.top), Float.isNaN(rectFA.right) ? 0.0f : C0444f0.f7603a.b(rectFA.right), Float.isNaN(rectFA.bottom) ? 0.0f : C0444f0.f7603a.b(rectFA.bottom));
    }

    private final void c(Canvas canvas, int i3, float f3, float f4, float f5, float f6, float f7, float f8, float f9, float f10) {
        if (i3 == 0) {
            return;
        }
        if (this.f1929k == null) {
            this.f1929k = new Path();
        }
        this.f1930l.setColor(n(i3, this.f1927i));
        Path path = this.f1929k;
        if (path != null) {
            path.reset();
        }
        Path path2 = this.f1929k;
        if (path2 != null) {
            path2.moveTo(f3, f4);
        }
        Path path3 = this.f1929k;
        if (path3 != null) {
            path3.lineTo(f5, f6);
        }
        Path path4 = this.f1929k;
        if (path4 != null) {
            path4.lineTo(f7, f8);
        }
        Path path5 = this.f1929k;
        if (path5 != null) {
            path5.lineTo(f9, f10);
        }
        Path path6 = this.f1929k;
        if (path6 != null) {
            path6.lineTo(f3, f4);
        }
        Path path7 = this.f1929k;
        if (path7 != null) {
            canvas.drawPath(path7, this.f1930l);
        }
    }

    private final void d(Canvas canvas) {
        RectF rectFB = b();
        int iC = u2.a.c(rectFB.left);
        int iC2 = u2.a.c(rectFB.top);
        int iC3 = u2.a.c(rectFB.right);
        int iC4 = u2.a.c(rectFB.bottom);
        if (iC > 0 || iC3 > 0 || iC2 > 0 || iC4 > 0) {
            Rect bounds = getBounds();
            t2.j.e(bounds, "getBounds(...)");
            int i3 = bounds.left;
            int i4 = bounds.top;
            int iF = f(iC, iC2, iC3, iC4, this.f1925g.b(), this.f1925g.d(), this.f1925g.c(), this.f1925g.a());
            if (iF == 0) {
                this.f1930l.setAntiAlias(false);
                int iWidth = bounds.width();
                int iHeight = bounds.height();
                if (iC > 0) {
                    float f3 = i3;
                    float f4 = i4;
                    float f5 = i3 + iC;
                    c(canvas, this.f1925g.b(), f3, f4, f5, i4 + iC2, f5, r0 - iC4, f3, i4 + iHeight);
                }
                if (iC2 > 0) {
                    float f6 = i3;
                    float f7 = i4;
                    float f8 = i3 + iC;
                    float f9 = i4 + iC2;
                    c(canvas, this.f1925g.d(), f6, f7, f8, f9, r0 - iC3, f9, i3 + iWidth, f7);
                }
                if (iC3 > 0) {
                    int i5 = i3 + iWidth;
                    float f10 = i5;
                    float f11 = i5 - iC3;
                    c(canvas, this.f1925g.c(), f10, i4, f10, i4 + iHeight, f11, r7 - iC4, f11, i4 + iC2);
                }
                if (iC4 > 0) {
                    int i6 = i4 + iHeight;
                    float f12 = i6;
                    float f13 = i6 - iC4;
                    int iA = this.f1925g.a();
                    c(canvas, iA, i3, f12, i3 + iWidth, f12, r8 - iC3, f13, i3 + iC, f13);
                }
                this.f1930l.setAntiAlias(true);
                return;
            }
            if (Color.alpha(iF) != 0) {
                int i7 = bounds.right;
                int i8 = bounds.bottom;
                this.f1930l.setColor(n(iF, this.f1927i));
                this.f1930l.setStyle(Paint.Style.STROKE);
                Path path = new Path();
                this.f1932n = path;
                if (iC > 0) {
                    path.reset();
                    int iC5 = u2.a.c(rectFB.left);
                    v(iC5);
                    this.f1930l.setStrokeWidth(iC5);
                    Path path2 = this.f1932n;
                    if (path2 != null) {
                        path2.moveTo(i3 + (iC5 / 2), i4);
                    }
                    Path path3 = this.f1932n;
                    if (path3 != null) {
                        path3.lineTo(i3 + (iC5 / 2), i8);
                    }
                    Path path4 = this.f1932n;
                    if (path4 != null) {
                        canvas.drawPath(path4, this.f1930l);
                    }
                }
                if (iC2 > 0) {
                    Path path5 = this.f1932n;
                    if (path5 != null) {
                        path5.reset();
                    }
                    int iC6 = u2.a.c(rectFB.top);
                    v(iC6);
                    this.f1930l.setStrokeWidth(iC6);
                    Path path6 = this.f1932n;
                    if (path6 != null) {
                        path6.moveTo(i3, i4 + (iC6 / 2));
                    }
                    Path path7 = this.f1932n;
                    if (path7 != null) {
                        path7.lineTo(i7, i4 + (iC6 / 2));
                    }
                    Path path8 = this.f1932n;
                    if (path8 != null) {
                        canvas.drawPath(path8, this.f1930l);
                    }
                }
                if (iC3 > 0) {
                    Path path9 = this.f1932n;
                    if (path9 != null) {
                        path9.reset();
                    }
                    int iC7 = u2.a.c(rectFB.right);
                    v(iC7);
                    this.f1930l.setStrokeWidth(iC7);
                    Path path10 = this.f1932n;
                    if (path10 != null) {
                        path10.moveTo(i7 - (iC7 / 2), i4);
                    }
                    Path path11 = this.f1932n;
                    if (path11 != null) {
                        path11.lineTo(i7 - (iC7 / 2), i8);
                    }
                    Path path12 = this.f1932n;
                    if (path12 != null) {
                        canvas.drawPath(path12, this.f1930l);
                    }
                }
                if (iC4 > 0) {
                    Path path13 = this.f1932n;
                    if (path13 != null) {
                        path13.reset();
                    }
                    int iC8 = u2.a.c(rectFB.bottom);
                    v(iC8);
                    this.f1930l.setStrokeWidth(iC8);
                    Path path14 = this.f1932n;
                    if (path14 != null) {
                        path14.moveTo(i3, i8 - (iC8 / 2));
                    }
                    Path path15 = this.f1932n;
                    if (path15 != null) {
                        path15.lineTo(i7, i8 - (iC8 / 2));
                    }
                    Path path16 = this.f1932n;
                    if (path16 != null) {
                        canvas.drawPath(path16, this.f1930l);
                    }
                }
            }
        }
    }

    private final void e(Canvas canvas) {
        PointF pointF;
        PointF pointF2;
        PointF pointF3;
        PointF pointF4;
        float f3;
        float f4;
        float f5;
        PointF pointF5;
        PointF pointF6;
        Q1.k kVarC;
        Q1.k kVarC2;
        Q1.k kVarC3;
        Q1.k kVarC4;
        t();
        canvas.save();
        Path path = this.f1935q;
        if (path == null) {
            throw new IllegalStateException("Required value was null.");
        }
        canvas.clipPath(path);
        RectF rectFB = b();
        float fB = 0.0f;
        if (rectFB.top > 0.0f || rectFB.bottom > 0.0f || rectFB.left > 0.0f || rectFB.right > 0.0f) {
            float fJ = j();
            int iG = g(n.f2478c);
            if (rectFB.top != fJ || rectFB.bottom != fJ || rectFB.left != fJ || rectFB.right != fJ || this.f1925g.b() != iG || this.f1925g.d() != iG || this.f1925g.c() != iG || this.f1925g.a() != iG) {
                this.f1930l.setStyle(Paint.Style.FILL);
                if (Build.VERSION.SDK_INT >= 26) {
                    Path path2 = this.f1936r;
                    if (path2 == null) {
                        throw new IllegalStateException("Required value was null.");
                    }
                    canvas.clipOutPath(path2);
                } else {
                    Path path3 = this.f1936r;
                    if (path3 == null) {
                        throw new IllegalStateException("Required value was null.");
                    }
                    canvas.clipPath(path3, Region.Op.DIFFERENCE);
                }
                RectF rectF = this.f1942x;
                if (rectF == null) {
                    throw new IllegalStateException("Required value was null.");
                }
                float f6 = rectF.left;
                float f7 = rectF.right;
                float f8 = rectF.top;
                float f9 = rectF.bottom;
                PointF pointF7 = this.f1939u;
                if (pointF7 == null) {
                    throw new IllegalStateException("Required value was null.");
                }
                PointF pointF8 = this.f1940v;
                if (pointF8 == null) {
                    throw new IllegalStateException("Required value was null.");
                }
                PointF pointF9 = this.f1937s;
                if (pointF9 == null) {
                    throw new IllegalStateException("Required value was null.");
                }
                PointF pointF10 = this.f1938t;
                if (pointF10 == null) {
                    throw new IllegalStateException("Required value was null.");
                }
                if (rectFB.left > 0.0f) {
                    float f10 = this.f1928j;
                    pointF = pointF10;
                    pointF2 = pointF9;
                    pointF3 = pointF8;
                    pointF4 = pointF7;
                    f3 = f9;
                    f4 = f8;
                    f5 = f7;
                    c(canvas, this.f1925g.b(), f6, f8 - f10, pointF7.x, pointF7.y - f10, pointF9.x, pointF9.y + f10, f6, f9 + f10);
                } else {
                    pointF = pointF10;
                    pointF2 = pointF9;
                    pointF3 = pointF8;
                    pointF4 = pointF7;
                    f3 = f9;
                    f4 = f8;
                    f5 = f7;
                }
                if (rectFB.top > 0.0f) {
                    float f11 = this.f1928j;
                    PointF pointF11 = pointF4;
                    PointF pointF12 = pointF3;
                    pointF5 = pointF12;
                    c(canvas, this.f1925g.d(), f6 - f11, f4, pointF11.x - f11, pointF11.y, pointF12.x + f11, pointF12.y, f5 + f11, f4);
                } else {
                    pointF5 = pointF3;
                }
                if (rectFB.right > 0.0f) {
                    float f12 = this.f1928j;
                    PointF pointF13 = pointF5;
                    PointF pointF14 = pointF;
                    pointF6 = pointF14;
                    c(canvas, this.f1925g.c(), f5, f4 - f12, pointF13.x, pointF13.y - f12, pointF14.x, pointF14.y + f12, f5, f3 + f12);
                } else {
                    pointF6 = pointF;
                }
                if (rectFB.bottom > 0.0f) {
                    float f13 = this.f1928j;
                    PointF pointF15 = pointF2;
                    float f14 = pointF15.x - f13;
                    float f15 = pointF15.y;
                    PointF pointF16 = pointF6;
                    c(canvas, this.f1925g.a(), f6 - f13, f3, f14, f15, pointF16.x + f13, pointF16.y, f5 + f13, f3);
                }
            } else if (fJ > 0.0f) {
                this.f1930l.setColor(n(iG, this.f1927i));
                this.f1930l.setStyle(Paint.Style.STROKE);
                this.f1930l.setStrokeWidth(fJ);
                Q1.j jVar = this.f1926h;
                if (jVar == null || !jVar.f()) {
                    Path path4 = this.f1934p;
                    if (path4 == null) {
                        throw new IllegalStateException("Required value was null.");
                    }
                    canvas.drawPath(path4, this.f1930l);
                } else {
                    RectF rectF2 = this.f1943y;
                    if (rectF2 != null) {
                        Q1.j jVar2 = this.f1926h;
                        float fA = ((jVar2 == null || (kVarC3 = jVar2.c()) == null || (kVarC4 = kVarC3.c()) == null) ? 0.0f : kVarC4.a()) - (rectFB.left * 0.5f);
                        Q1.j jVar3 = this.f1926h;
                        if (jVar3 != null && (kVarC = jVar3.c()) != null && (kVarC2 = kVarC.c()) != null) {
                            fB = kVarC2.b();
                        }
                        canvas.drawRoundRect(rectF2, fA, fB - (rectFB.top * 0.5f), this.f1930l);
                    }
                }
            }
        }
        canvas.restore();
    }

    private final int f(int i3, int i4, int i5, int i6, int i7, int i8, int i9, int i10) {
        int i11 = (i6 > 0 ? i10 : -1) & (i3 > 0 ? i7 : -1) & (i4 > 0 ? i8 : -1) & (i5 > 0 ? i9 : -1);
        if (i3 <= 0) {
            i7 = 0;
        }
        if (i4 <= 0) {
            i8 = 0;
        }
        int i12 = i7 | i8;
        if (i5 <= 0) {
            i9 = 0;
        }
        int i13 = i12 | i9;
        if (i6 <= 0) {
            i10 = 0;
        }
        if (i11 == (i13 | i10)) {
            return i11;
        }
        return 0;
    }

    private final void i(double d3, double d4, double d5, double d6, double d7, double d8, double d9, double d10, PointF pointF) {
        double d11 = 2;
        double d12 = (d3 + d5) / d11;
        double d13 = (d4 + d6) / d11;
        double d14 = d7 - d12;
        double d15 = d8 - d13;
        double dAbs = Math.abs(d5 - d3) / d11;
        double dAbs2 = Math.abs(d6 - d4) / d11;
        double d16 = ((d10 - d13) - d15) / ((d9 - d12) - d14);
        double d17 = d15 - (d14 * d16);
        double d18 = dAbs2 * dAbs2;
        double d19 = dAbs * dAbs;
        double d20 = d18 + (d19 * d16 * d16);
        double d21 = d11 * dAbs * dAbs * d17 * d16;
        double d22 = d11 * d20;
        double dSqrt = ((-d21) / d22) - Math.sqrt(((-(d19 * ((d17 * d17) - d18))) / d20) + Math.pow(d21 / d22, 2.0d));
        double d23 = (d16 * dSqrt) + d17;
        double d24 = dSqrt + d12;
        double d25 = d23 + d13;
        if (Double.isNaN(d24) || Double.isNaN(d25)) {
            return;
        }
        pointF.x = (float) d24;
        pointF.y = (float) d25;
    }

    private final float j() {
        C0483z0 c0483z0 = this.f1920b;
        float fB = c0483z0 != null ? c0483z0.b(8) : Float.NaN;
        if (Float.isNaN(fB)) {
            return 0.0f;
        }
        return fB;
    }

    private final float k(float f3, float f4) {
        return w2.d.b(f3 - f4, 0.0f);
    }

    private final PathEffect l(Q1.f fVar, float f3) {
        int i3 = a.f1944a[fVar.ordinal()];
        if (i3 == 1) {
            return null;
        }
        if (i3 == 2) {
            float f4 = f3 * 3;
            return new DashPathEffect(new float[]{f4, f4, f4, f4}, 0.0f);
        }
        if (i3 == 3) {
            return new DashPathEffect(new float[]{f3, f3, f3, f3}, 0.0f);
        }
        throw new C0562h();
    }

    private final v2.b m(Object obj) {
        return new b(obj, this);
    }

    private final int n(int i3, int i4) {
        if (i4 == 255) {
            return i3;
        }
        if (i4 == 0) {
            return i3 & 16777215;
        }
        return (i3 & 16777215) | ((((i3 >>> 24) * ((i4 + (i4 >> 7)) >> 7)) >> 8) << 24);
    }

    private final void t() {
        Q1.j jVarD;
        Q1.k kVar;
        Q1.k kVar2;
        Q1.k kVar3;
        Q1.k kVar4;
        Path path;
        Path path2;
        Path path3;
        Q1.k kVarB;
        Q1.k kVarA;
        Q1.k kVarD;
        Q1.k kVarC;
        if (this.f1931m) {
            this.f1931m = false;
            Path path4 = this.f1936r;
            if (path4 == null) {
                path4 = new Path();
            }
            this.f1936r = path4;
            Path path5 = this.f1935q;
            if (path5 == null) {
                path5 = new Path();
            }
            this.f1935q = path5;
            this.f1933o = new Path();
            RectF rectF = this.f1941w;
            if (rectF == null) {
                rectF = new RectF();
            }
            this.f1941w = rectF;
            RectF rectF2 = this.f1942x;
            if (rectF2 == null) {
                rectF2 = new RectF();
            }
            this.f1942x = rectF2;
            RectF rectF3 = this.f1943y;
            if (rectF3 == null) {
                rectF3 = new RectF();
            }
            this.f1943y = rectF3;
            Path path6 = this.f1936r;
            if (path6 != null) {
                path6.reset();
                r rVar = r.f9288a;
            }
            Path path7 = this.f1935q;
            if (path7 != null) {
                path7.reset();
                r rVar2 = r.f9288a;
            }
            RectF rectF4 = this.f1941w;
            if (rectF4 != null) {
                rectF4.set(getBounds());
                r rVar3 = r.f9288a;
            }
            RectF rectF5 = this.f1942x;
            if (rectF5 != null) {
                rectF5.set(getBounds());
                r rVar4 = r.f9288a;
            }
            RectF rectF6 = this.f1943y;
            if (rectF6 != null) {
                rectF6.set(getBounds());
                r rVar5 = r.f9288a;
            }
            RectF rectFB = b();
            if (Color.alpha(this.f1925g.b()) != 0 || Color.alpha(this.f1925g.d()) != 0 || Color.alpha(this.f1925g.c()) != 0 || Color.alpha(this.f1925g.a()) != 0) {
                RectF rectF7 = this.f1941w;
                if (rectF7 != null) {
                    rectF7.top = rectF7 != null ? rectF7.top + rectFB.top : 0.0f;
                    r rVar6 = r.f9288a;
                }
                if (rectF7 != null) {
                    rectF7.bottom = rectF7 != null ? rectF7.bottom - rectFB.bottom : 0.0f;
                    r rVar7 = r.f9288a;
                }
                if (rectF7 != null) {
                    rectF7.left = rectF7 != null ? rectF7.left + rectFB.left : 0.0f;
                    r rVar8 = r.f9288a;
                }
                if (rectF7 != null) {
                    rectF7.right = rectF7 != null ? rectF7.right - rectFB.right : 0.0f;
                    r rVar9 = r.f9288a;
                }
            }
            RectF rectF8 = this.f1943y;
            if (rectF8 != null) {
                rectF8.top = rectF8 != null ? rectF8.top + (rectFB.top * 0.5f) : 0.0f;
                r rVar10 = r.f9288a;
            }
            if (rectF8 != null) {
                rectF8.bottom = rectF8 != null ? rectF8.bottom - (rectFB.bottom * 0.5f) : 0.0f;
                r rVar11 = r.f9288a;
            }
            if (rectF8 != null) {
                rectF8.left = rectF8 != null ? rectF8.left + (rectFB.left * 0.5f) : 0.0f;
                r rVar12 = r.f9288a;
            }
            if (rectF8 != null) {
                rectF8.right = rectF8 != null ? rectF8.right - (rectFB.right * 0.5f) : 0.0f;
                r rVar13 = r.f9288a;
            }
            Q1.e eVar = this.f1921c;
            if (eVar != null) {
                int layoutDirection = getLayoutDirection();
                Context context = this.f1919a;
                RectF rectF9 = this.f1942x;
                float fD = rectF9 != null ? C0444f0.f7603a.d(rectF9.width()) : 0.0f;
                RectF rectF10 = this.f1942x;
                jVarD = eVar.d(layoutDirection, context, fD, rectF10 != null ? C0444f0.f7603a.d(rectF10.height()) : 0.0f);
            } else {
                jVarD = null;
            }
            this.f1926h = jVarD;
            if (jVarD == null || (kVarC = jVarD.c()) == null || (kVar = kVarC.c()) == null) {
                kVar = new Q1.k(0.0f, 0.0f);
            }
            Q1.j jVar = this.f1926h;
            if (jVar == null || (kVarD = jVar.d()) == null || (kVar2 = kVarD.c()) == null) {
                kVar2 = new Q1.k(0.0f, 0.0f);
            }
            Q1.j jVar2 = this.f1926h;
            if (jVar2 == null || (kVarA = jVar2.a()) == null || (kVar3 = kVarA.c()) == null) {
                kVar3 = new Q1.k(0.0f, 0.0f);
            }
            Q1.j jVar3 = this.f1926h;
            if (jVar3 == null || (kVarB = jVar3.b()) == null || (kVar4 = kVarB.c()) == null) {
                kVar4 = new Q1.k(0.0f, 0.0f);
            }
            float fK = k(kVar.a(), rectFB.left);
            float fK2 = k(kVar.b(), rectFB.top);
            float fK3 = k(kVar2.a(), rectFB.right);
            float fK4 = k(kVar2.b(), rectFB.top);
            float fK5 = k(kVar4.a(), rectFB.right);
            float fK6 = k(kVar4.b(), rectFB.bottom);
            float fK7 = k(kVar3.a(), rectFB.left);
            float fK8 = k(kVar3.b(), rectFB.bottom);
            RectF rectF11 = this.f1941w;
            if (rectF11 != null && (path3 = this.f1936r) != null) {
                path3.addRoundRect(rectF11, new float[]{fK, fK2, fK3, fK4, fK5, fK6, fK7, fK8}, Path.Direction.CW);
                r rVar14 = r.f9288a;
            }
            RectF rectF12 = this.f1942x;
            if (rectF12 != null && (path2 = this.f1935q) != null) {
                path2.addRoundRect(rectF12, new float[]{kVar.a(), kVar.b(), kVar2.a(), kVar2.b(), kVar4.a(), kVar4.b(), kVar3.a(), kVar3.b()}, Path.Direction.CW);
                r rVar15 = r.f9288a;
            }
            C0483z0 c0483z0 = this.f1920b;
            float fA = c0483z0 != null ? c0483z0.a(8) / 2.0f : 0.0f;
            Path path8 = this.f1933o;
            if (path8 != null) {
                path8.addRoundRect(new RectF(getBounds()), new float[]{kVar.a() + fA, kVar.b() + fA, kVar2.a() + fA, kVar2.b() + fA, kVar4.a() + fA, kVar4.b() + fA, kVar3.a() + fA, kVar3.b() + fA}, Path.Direction.CW);
                r rVar16 = r.f9288a;
            }
            Q1.j jVar4 = this.f1926h;
            if (jVar4 == null || !jVar4.f()) {
                Path path9 = this.f1934p;
                if (path9 == null) {
                    path9 = new Path();
                }
                this.f1934p = path9;
                path9.reset();
                r rVar17 = r.f9288a;
                RectF rectF13 = this.f1943y;
                if (rectF13 != null && (path = this.f1934p) != null) {
                    path.addRoundRect(rectF13, new float[]{kVar.a() - (rectFB.left * 0.5f), kVar.b() - (rectFB.top * 0.5f), kVar2.a() - (rectFB.right * 0.5f), kVar2.b() - (rectFB.top * 0.5f), kVar4.a() - (rectFB.right * 0.5f), kVar4.b() - (rectFB.bottom * 0.5f), kVar3.a() - (rectFB.left * 0.5f), kVar3.b() - (rectFB.bottom * 0.5f)}, Path.Direction.CW);
                    r rVar18 = r.f9288a;
                }
            }
            RectF rectF14 = this.f1941w;
            RectF rectF15 = this.f1942x;
            if (rectF14 == null || rectF15 == null) {
                return;
            }
            PointF pointF = this.f1939u;
            if (pointF == null) {
                pointF = new PointF();
            }
            PointF pointF2 = pointF;
            this.f1939u = pointF2;
            pointF2.x = rectF14.left;
            r rVar19 = r.f9288a;
            pointF2.y = rectF14.top;
            r rVar20 = r.f9288a;
            float f3 = rectF14.left;
            float f4 = rectF14.top;
            float f5 = 2;
            i(f3, f4, (fK * f5) + f3, (f5 * fK2) + f4, rectF15.left, rectF15.top, f3, f4, pointF2);
            r rVar21 = r.f9288a;
            PointF pointF3 = this.f1937s;
            if (pointF3 == null) {
                pointF3 = new PointF();
            }
            PointF pointF4 = pointF3;
            this.f1937s = pointF4;
            pointF4.x = rectF14.left;
            r rVar22 = r.f9288a;
            pointF4.y = rectF14.bottom;
            r rVar23 = r.f9288a;
            float f6 = rectF14.left;
            float f7 = rectF14.bottom;
            float f8 = 2;
            i(f6, f7 - (fK8 * f8), (f8 * fK7) + f6, f7, rectF15.left, rectF15.bottom, f6, f7, pointF4);
            r rVar24 = r.f9288a;
            PointF pointF5 = this.f1940v;
            if (pointF5 == null) {
                pointF5 = new PointF();
            }
            PointF pointF6 = pointF5;
            this.f1940v = pointF6;
            pointF6.x = rectF14.right;
            r rVar25 = r.f9288a;
            pointF6.y = rectF14.top;
            r rVar26 = r.f9288a;
            float f9 = rectF14.right;
            float f10 = 2;
            float f11 = rectF14.top;
            i(f9 - (fK3 * f10), f11, f9, (f10 * fK4) + f11, rectF15.right, rectF15.top, f9, f11, pointF6);
            r rVar27 = r.f9288a;
            PointF pointF7 = this.f1938t;
            if (pointF7 == null) {
                pointF7 = new PointF();
            }
            PointF pointF8 = pointF7;
            this.f1938t = pointF8;
            pointF8.x = rectF14.right;
            r rVar28 = r.f9288a;
            pointF8.y = rectF14.bottom;
            r rVar29 = r.f9288a;
            float f12 = rectF14.right;
            float f13 = 2;
            float f14 = rectF14.bottom;
            i(f12 - (fK5 * f13), f14 - (f13 * fK6), f12, f14, rectF15.right, rectF15.bottom, f12, f14, pointF8);
            r rVar30 = r.f9288a;
        }
    }

    private final void u() {
        Q1.f fVarH = h();
        if (fVarH != null) {
            this.f1930l.setPathEffect(h() != null ? l(fVarH, j()) : null);
        }
    }

    private final void v(int i3) {
        Q1.f fVarH = h();
        if (fVarH != null) {
            this.f1930l.setPathEffect(h() != null ? l(fVarH, i3) : null);
        }
    }

    @Override // android.graphics.drawable.Drawable
    public void draw(Canvas canvas) {
        Q1.h hVarC;
        t2.j.f(canvas, "canvas");
        u();
        Integer[] numArr = this.f1924f;
        if (numArr == null || (hVarC = Q1.b.c(numArr, getLayoutDirection(), this.f1919a)) == null) {
            hVarC = this.f1925g;
        }
        this.f1925g = hVarC;
        Q1.e eVar = this.f1921c;
        if (eVar == null || !eVar.c()) {
            d(canvas);
        } else {
            e(canvas);
        }
    }

    public final int g(n nVar) {
        Integer num;
        t2.j.f(nVar, "position");
        Integer[] numArr = this.f1924f;
        if (numArr == null || (num = numArr[nVar.ordinal()]) == null) {
            return -16777216;
        }
        return num.intValue();
    }

    @Override // android.graphics.drawable.Drawable
    public int getOpacity() {
        if (AbstractC0605a.d(Color.alpha(n(this.f1925g.b(), this.f1927i)), Color.alpha(n(this.f1925g.d(), this.f1927i)), Color.alpha(n(this.f1925g.c(), this.f1927i)), Color.alpha(n(this.f1925g.a(), this.f1927i))) == 0) {
            return -2;
        }
        return AbstractC0605a.e(Color.alpha(n(this.f1925g.b(), this.f1927i)), Color.alpha(n(this.f1925g.d(), this.f1927i)), Color.alpha(n(this.f1925g.c(), this.f1927i)), Color.alpha(n(this.f1925g.a(), this.f1927i))) == 255 ? -1 : -3;
    }

    public final Q1.f h() {
        return (Q1.f) this.f1923e.a(this, f1918z[0]);
    }

    @Override // android.graphics.drawable.Drawable
    public void invalidateSelf() {
        this.f1931m = true;
        super.invalidateSelf();
    }

    public final void o(n nVar, Integer num) {
        t2.j.f(nVar, "position");
        Integer[] numArrB = this.f1924f;
        if (numArrB == null) {
            numArrB = Q1.b.b(null, 1, null);
        }
        this.f1924f = numArrB;
        if (numArrB != null) {
            numArrB[nVar.ordinal()] = num;
        }
        this.f1931m = true;
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    protected void onBoundsChange(Rect rect) {
        t2.j.f(rect, "bounds");
        super.onBoundsChange(rect);
        this.f1931m = true;
    }

    public final void p(Q1.c cVar) {
        this.f1922d = cVar;
    }

    public final void q(Q1.e eVar) {
        this.f1921c = eVar;
    }

    public final void r(Q1.f fVar) {
        this.f1923e.b(this, f1918z[0], fVar);
    }

    public final void s(int i3, float f3) {
        C0483z0 c0483z0 = this.f1920b;
        if (L.b(c0483z0 != null ? Float.valueOf(c0483z0.b(i3)) : null, Float.valueOf(f3))) {
            return;
        }
        C0483z0 c0483z02 = this.f1920b;
        if (c0483z02 != null) {
            c0483z02.c(i3, f3);
        }
        if (i3 == 0 || i3 == 1 || i3 == 2 || i3 == 3 || i3 == 4 || i3 == 5 || i3 == 8) {
            this.f1931m = true;
        }
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public void setAlpha(int i3) {
        this.f1927i = i3;
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public void setColorFilter(ColorFilter colorFilter) {
    }
}
