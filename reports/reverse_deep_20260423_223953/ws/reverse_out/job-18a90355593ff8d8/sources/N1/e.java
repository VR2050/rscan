package N1;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.ColorFilter;
import android.graphics.ComposeShader;
import android.graphics.DashPathEffect;
import android.graphics.Outline;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.PathEffect;
import android.graphics.PointF;
import android.graphics.PorterDuff;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.Region;
import android.graphics.Shader;
import android.graphics.drawable.Drawable;
import com.facebook.react.uimanager.C0444f0;
import com.facebook.react.uimanager.C0483z0;
import com.facebook.react.uimanager.L;
import com.facebook.react.uimanager.W;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;

/* JADX INFO: loaded from: classes.dex */
public class e extends Drawable {

    /* JADX INFO: renamed from: B, reason: collision with root package name */
    private final Context f1947B;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private C0483z0 f1949a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private C0483z0 f1950b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private C0483z0 f1951c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private Q1.f f1952d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private Path f1953e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private Path f1954f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private Path f1955g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private Path f1956h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private Path f1957i;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private Path f1959k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private RectF f1960l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private RectF f1961m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private RectF f1962n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private RectF f1963o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private PointF f1964p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private PointF f1965q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private PointF f1966r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private PointF f1967s;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final Path f1958j = new Path();

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private boolean f1968t = false;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    private final Paint f1969u = new Paint(1);

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    private int f1970v = 0;

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    private List f1971w = null;

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    private int f1972x = 255;

    /* JADX INFO: renamed from: y, reason: collision with root package name */
    private final float f1973y = 0.8f;

    /* JADX INFO: renamed from: z, reason: collision with root package name */
    private Q1.e f1974z = new Q1.e();

    /* JADX INFO: renamed from: A, reason: collision with root package name */
    private Q1.j f1946A = new Q1.j();

    /* JADX INFO: renamed from: C, reason: collision with root package name */
    private int f1948C = -1;

    static /* synthetic */ class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        static final /* synthetic */ int[] f1975a;

        static {
            int[] iArr = new int[Q1.f.values().length];
            f1975a = iArr;
            try {
                iArr[Q1.f.f2432c.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                f1975a[Q1.f.f2433d.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                f1975a[Q1.f.f2434e.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
        }
    }

    public e(Context context) {
        this.f1947B = context;
    }

    private void D() {
        if (this.f1968t) {
            this.f1968t = false;
            if (this.f1953e == null) {
                this.f1953e = new Path();
            }
            if (this.f1954f == null) {
                this.f1954f = new Path();
            }
            if (this.f1955g == null) {
                this.f1955g = new Path();
            }
            if (this.f1956h == null) {
                this.f1956h = new Path();
            }
            if (this.f1959k == null) {
                this.f1959k = new Path();
            }
            if (this.f1960l == null) {
                this.f1960l = new RectF();
            }
            if (this.f1961m == null) {
                this.f1961m = new RectF();
            }
            if (this.f1962n == null) {
                this.f1962n = new RectF();
            }
            if (this.f1963o == null) {
                this.f1963o = new RectF();
            }
            this.f1953e.reset();
            this.f1954f.reset();
            this.f1955g.reset();
            this.f1956h.reset();
            this.f1959k.reset();
            this.f1960l.set(getBounds());
            this.f1961m.set(getBounds());
            this.f1962n.set(getBounds());
            this.f1963o.set(getBounds());
            RectF rectFL = l();
            int iG = g(0);
            int iG2 = g(1);
            int iG3 = g(2);
            int iG4 = g(3);
            int iG5 = g(8);
            int iG6 = g(9);
            int iG7 = g(11);
            int iG8 = g(10);
            if (t(9)) {
                iG2 = iG6;
                iG4 = iG2;
            }
            if (!t(10)) {
                iG8 = iG4;
            }
            if (!t(11)) {
                iG7 = iG2;
            }
            if (Color.alpha(iG) != 0 || Color.alpha(iG7) != 0 || Color.alpha(iG3) != 0 || Color.alpha(iG8) != 0 || Color.alpha(iG5) != 0) {
                RectF rectF = this.f1960l;
                rectF.top += rectFL.top;
                rectF.bottom -= rectFL.bottom;
                rectF.left += rectFL.left;
                rectF.right -= rectFL.right;
            }
            RectF rectF2 = this.f1963o;
            rectF2.top += rectFL.top * 0.5f;
            rectF2.bottom -= rectFL.bottom * 0.5f;
            rectF2.left += rectFL.left * 0.5f;
            rectF2.right -= rectFL.right * 0.5f;
            Q1.j jVarD = this.f1974z.d(getLayoutDirection(), this.f1947B, C0444f0.f(this.f1961m.width()), C0444f0.f(this.f1961m.height()));
            this.f1946A = jVarD;
            Q1.k kVarC = jVarD.c().c();
            Q1.k kVarC2 = this.f1946A.d().c();
            Q1.k kVarC3 = this.f1946A.a().c();
            Q1.k kVarC4 = this.f1946A.b().c();
            float fO = o(kVarC.a(), rectFL.left);
            float fO2 = o(kVarC.b(), rectFL.top);
            float fO3 = o(kVarC2.a(), rectFL.right);
            float fO4 = o(kVarC2.b(), rectFL.top);
            float fO5 = o(kVarC4.a(), rectFL.right);
            float fO6 = o(kVarC4.b(), rectFL.bottom);
            float fO7 = o(kVarC3.a(), rectFL.left);
            float fO8 = o(kVarC3.b(), rectFL.bottom);
            Path.Direction direction = Path.Direction.CW;
            this.f1953e.addRoundRect(this.f1960l, new float[]{fO, fO2, fO3, fO4, fO5, fO6, fO7, fO8}, direction);
            this.f1954f.addRoundRect(rectFL.left > 0.0f ? this.f1960l.left - 0.8f : this.f1960l.left, rectFL.top > 0.0f ? this.f1960l.top - 0.8f : this.f1960l.top, rectFL.right > 0.0f ? this.f1960l.right + 0.8f : this.f1960l.right, rectFL.bottom > 0.0f ? this.f1960l.bottom + 0.8f : this.f1960l.bottom, new float[]{fO, fO2, fO3, fO4, fO5, fO6, fO7, fO8}, direction);
            this.f1955g.addRoundRect(this.f1961m, new float[]{kVarC.a(), kVarC.b(), kVarC2.a(), kVarC2.b(), kVarC4.a(), kVarC4.b(), kVarC3.a(), kVarC3.b()}, direction);
            C0483z0 c0483z0 = this.f1949a;
            float fA = c0483z0 != null ? c0483z0.a(8) / 2.0f : 0.0f;
            this.f1956h.addRoundRect(this.f1962n, new float[]{kVarC.a() + fA, kVarC.b() + fA, kVarC2.a() + fA, kVarC2.b() + fA, kVarC4.a() + fA, kVarC4.b() + fA, kVarC3.a() + fA, kVarC3.b() + fA}, direction);
            this.f1959k.addRoundRect(this.f1963o, new float[]{kVarC.a() - (rectFL.left * 0.5f), kVarC.b() - (rectFL.top * 0.5f), kVarC2.a() - (rectFL.right * 0.5f), kVarC2.b() - (rectFL.top * 0.5f), kVarC4.a() - (rectFL.right * 0.5f), kVarC4.b() - (rectFL.bottom * 0.5f), kVarC3.a() - (rectFL.left * 0.5f), kVarC3.b() - (rectFL.bottom * 0.5f)}, direction);
            if (this.f1964p == null) {
                this.f1964p = new PointF();
            }
            PointF pointF = this.f1964p;
            RectF rectF3 = this.f1960l;
            float f3 = rectF3.left;
            pointF.x = f3;
            float f4 = rectF3.top;
            pointF.y = f4;
            RectF rectF4 = this.f1961m;
            m(f3, f4, (fO * 2.0f) + f3, (fO2 * 2.0f) + f4, rectF4.left, rectF4.top, f3, f4, pointF);
            if (this.f1967s == null) {
                this.f1967s = new PointF();
            }
            PointF pointF2 = this.f1967s;
            RectF rectF5 = this.f1960l;
            float f5 = rectF5.left;
            pointF2.x = f5;
            float f6 = rectF5.bottom;
            pointF2.y = f6;
            RectF rectF6 = this.f1961m;
            m(f5, f6 - (fO8 * 2.0f), (fO7 * 2.0f) + f5, f6, rectF6.left, rectF6.bottom, f5, f6, pointF2);
            if (this.f1965q == null) {
                this.f1965q = new PointF();
            }
            PointF pointF3 = this.f1965q;
            RectF rectF7 = this.f1960l;
            float f7 = rectF7.right;
            pointF3.x = f7;
            float f8 = rectF7.top;
            pointF3.y = f8;
            RectF rectF8 = this.f1961m;
            m(f7 - (fO3 * 2.0f), f8, f7, (fO4 * 2.0f) + f8, rectF8.right, rectF8.top, f7, f8, pointF3);
            if (this.f1966r == null) {
                this.f1966r = new PointF();
            }
            PointF pointF4 = this.f1966r;
            RectF rectF9 = this.f1960l;
            float f9 = rectF9.right;
            pointF4.x = f9;
            float f10 = rectF9.bottom;
            pointF4.y = f10;
            RectF rectF10 = this.f1961m;
            m(f9 - (fO5 * 2.0f), f10 - (fO6 * 2.0f), f9, f10, rectF10.right, rectF10.bottom, f9, f10, pointF4);
        }
    }

    private void E() {
        Q1.f fVar = this.f1952d;
        this.f1969u.setPathEffect(fVar != null ? r(fVar, n()) : null);
    }

    private void F(int i3) {
        Q1.f fVar = this.f1952d;
        this.f1969u.setPathEffect(fVar != null ? r(fVar, i3) : null);
    }

    private static int a(float f3, float f4) {
        return ((((int) f3) << 24) & (-16777216)) | (((int) f4) & 16777215);
    }

    private void b(Canvas canvas, int i3, float f3, float f4, float f5, float f6, float f7, float f8, float f9, float f10) {
        if (i3 == 0) {
            return;
        }
        if (this.f1957i == null) {
            this.f1957i = new Path();
        }
        this.f1969u.setColor(i3);
        this.f1957i.reset();
        this.f1957i.moveTo(f3, f4);
        this.f1957i.lineTo(f5, f6);
        this.f1957i.lineTo(f7, f8);
        this.f1957i.lineTo(f9, f10);
        this.f1957i.lineTo(f3, f4);
        canvas.drawPath(this.f1957i, this.f1969u);
    }

    private void c(Canvas canvas) {
        int i3;
        int i4;
        int i5;
        this.f1969u.setStyle(Paint.Style.FILL);
        int iU = u(this.f1970v, this.f1972x);
        if (Color.alpha(iU) != 0) {
            this.f1969u.setColor(iU);
            canvas.drawRect(getBounds(), this.f1969u);
        }
        List list = this.f1971w;
        if (list != null && !list.isEmpty()) {
            this.f1969u.setShader(f());
            canvas.drawRect(getBounds(), this.f1969u);
            this.f1969u.setShader(null);
        }
        RectF rectFL = l();
        int iRound = Math.round(rectFL.left);
        int iRound2 = Math.round(rectFL.top);
        int iRound3 = Math.round(rectFL.right);
        int iRound4 = Math.round(rectFL.bottom);
        if (iRound > 0 || iRound3 > 0 || iRound2 > 0 || iRound4 > 0) {
            Rect bounds = getBounds();
            int iG = g(0);
            int iG2 = g(1);
            int iG3 = g(2);
            int iG4 = g(3);
            int iG5 = g(9);
            int iG6 = g(11);
            int iG7 = g(10);
            if (t(9)) {
                iG2 = iG5;
                iG4 = iG2;
            }
            if (!t(10)) {
                iG7 = iG4;
            }
            if (!t(11)) {
                iG6 = iG2;
            }
            boolean z3 = getLayoutDirection() == 1;
            int iG8 = g(4);
            int iG9 = g(5);
            if (com.facebook.react.modules.i18nmanager.a.f().d(this.f1947B)) {
                if (t(4)) {
                    iG = iG8;
                }
                if (t(5)) {
                    iG3 = iG9;
                }
                int i6 = z3 ? iG3 : iG;
                if (!z3) {
                    iG = iG3;
                }
                i4 = iG;
                i3 = i6;
            } else {
                int i7 = z3 ? iG9 : iG8;
                if (!z3) {
                    iG8 = iG9;
                }
                boolean zT = t(4);
                boolean zT2 = t(5);
                boolean z4 = z3 ? zT2 : zT;
                if (!z3) {
                    zT = zT2;
                }
                if (z4) {
                    iG = i7;
                }
                i3 = iG;
                i4 = zT ? iG8 : iG3;
            }
            int i8 = bounds.left;
            int i9 = bounds.top;
            int i10 = i3;
            int iE = e(iRound, iRound2, iRound3, iRound4, i3, iG6, i4, iG7);
            if (iE == 0) {
                this.f1969u.setAntiAlias(false);
                int iWidth = bounds.width();
                int iHeight = bounds.height();
                if (iRound > 0) {
                    float f3 = i8;
                    float f4 = i8 + iRound;
                    i5 = i9;
                    b(canvas, i10, f3, i9, f4, i9 + iRound2, f4, r8 - iRound4, f3, i9 + iHeight);
                } else {
                    i5 = i9;
                }
                if (iRound2 > 0) {
                    float f5 = i5;
                    float f6 = i5 + iRound2;
                    b(canvas, iG6, i8, f5, i8 + iRound, f6, r9 - iRound3, f6, i8 + iWidth, f5);
                }
                if (iRound3 > 0) {
                    int i11 = i8 + iWidth;
                    float f7 = i11;
                    float f8 = i11 - iRound3;
                    b(canvas, i4, f7, i5, f7, i5 + iHeight, f8, r8 - iRound4, f8, i5 + iRound2);
                }
                if (iRound4 > 0) {
                    int i12 = i5 + iHeight;
                    float f9 = i12;
                    float f10 = i12 - iRound4;
                    b(canvas, iG7, i8, f9, i8 + iWidth, f9, r9 - iRound3, f10, i8 + iRound, f10);
                }
                this.f1969u.setAntiAlias(true);
                return;
            }
            if (Color.alpha(iE) != 0) {
                int i13 = bounds.right;
                int i14 = bounds.bottom;
                this.f1969u.setColor(iE);
                this.f1969u.setStyle(Paint.Style.STROKE);
                if (iRound > 0) {
                    this.f1958j.reset();
                    int iRound5 = Math.round(rectFL.left);
                    F(iRound5);
                    this.f1969u.setStrokeWidth(iRound5);
                    float f11 = i8 + (iRound5 / 2);
                    this.f1958j.moveTo(f11, i9);
                    this.f1958j.lineTo(f11, i14);
                    canvas.drawPath(this.f1958j, this.f1969u);
                }
                if (iRound2 > 0) {
                    this.f1958j.reset();
                    int iRound6 = Math.round(rectFL.top);
                    F(iRound6);
                    this.f1969u.setStrokeWidth(iRound6);
                    float f12 = i9 + (iRound6 / 2);
                    this.f1958j.moveTo(i8, f12);
                    this.f1958j.lineTo(i13, f12);
                    canvas.drawPath(this.f1958j, this.f1969u);
                }
                if (iRound3 > 0) {
                    this.f1958j.reset();
                    int iRound7 = Math.round(rectFL.right);
                    F(iRound7);
                    this.f1969u.setStrokeWidth(iRound7);
                    float f13 = i13 - (iRound7 / 2);
                    this.f1958j.moveTo(f13, i9);
                    this.f1958j.lineTo(f13, i14);
                    canvas.drawPath(this.f1958j, this.f1969u);
                }
                if (iRound4 > 0) {
                    this.f1958j.reset();
                    int iRound8 = Math.round(rectFL.bottom);
                    F(iRound8);
                    this.f1969u.setStrokeWidth(iRound8);
                    float f14 = i14 - (iRound8 / 2);
                    this.f1958j.moveTo(i8, f14);
                    this.f1958j.lineTo(i13, f14);
                    canvas.drawPath(this.f1958j, this.f1969u);
                }
            }
        }
    }

    private void d(Canvas canvas) {
        int i3;
        int i4;
        PointF pointF;
        PointF pointF2;
        PointF pointF3;
        float f3;
        float f4;
        float f5;
        float f6;
        int i5;
        PointF pointF4;
        D();
        canvas.save();
        int i6 = this.f1970v;
        int iG = androidx.core.graphics.a.g(i6, (Color.alpha(i6) * this.f1972x) >> 8);
        if (Color.alpha(iG) != 0) {
            this.f1969u.setColor(iG);
            this.f1969u.setStyle(Paint.Style.FILL);
            canvas.drawPath((Path) q.g.f(this.f1954f), this.f1969u);
        }
        List list = this.f1971w;
        if (list != null && !list.isEmpty()) {
            this.f1969u.setShader(f());
            this.f1969u.setStyle(Paint.Style.FILL);
            canvas.drawPath((Path) q.g.f(this.f1954f), this.f1969u);
            this.f1969u.setShader(null);
        }
        RectF rectFL = l();
        int iG2 = g(0);
        int iG3 = g(1);
        int iG4 = g(2);
        int iG5 = g(3);
        int iG6 = g(9);
        int iG7 = g(11);
        int iG8 = g(10);
        if (t(9)) {
            iG3 = iG6;
            iG5 = iG3;
        }
        if (!t(10)) {
            iG8 = iG5;
        }
        int i7 = t(11) ? iG7 : iG3;
        if (rectFL.top > 0.0f || rectFL.bottom > 0.0f || rectFL.left > 0.0f || rectFL.right > 0.0f) {
            canvas.clipPath((Path) q.g.f(this.f1955g), Region.Op.INTERSECT);
            float fN = n();
            int iG9 = g(8);
            if (rectFL.top != fN || rectFL.bottom != fN || rectFL.left != fN || rectFL.right != fN || iG2 != iG9 || i7 != iG9 || iG4 != iG9 || iG8 != iG9) {
                this.f1969u.setStyle(Paint.Style.FILL);
                canvas.clipPath((Path) q.g.f(this.f1953e), Region.Op.DIFFERENCE);
                boolean z3 = getLayoutDirection() == 1;
                int iG10 = g(4);
                int iG11 = g(5);
                if (com.facebook.react.modules.i18nmanager.a.f().d(this.f1947B)) {
                    if (t(4)) {
                        iG2 = iG10;
                    }
                    if (t(5)) {
                        iG4 = iG11;
                    }
                    i3 = z3 ? iG4 : iG2;
                    if (!z3) {
                        iG2 = iG4;
                    }
                    i4 = iG2;
                } else {
                    int i8 = z3 ? iG11 : iG10;
                    if (!z3) {
                        iG10 = iG11;
                    }
                    boolean zT = t(4);
                    boolean zT2 = t(5);
                    boolean z4 = z3 ? zT2 : zT;
                    if (!z3) {
                        zT = zT2;
                    }
                    if (z4) {
                        iG2 = i8;
                    }
                    if (zT) {
                        i3 = iG2;
                        i4 = iG10;
                    } else {
                        i3 = iG2;
                        i4 = iG4;
                    }
                }
                RectF rectF = (RectF) q.g.f(this.f1961m);
                float f7 = rectF.left;
                float f8 = rectF.right;
                float f9 = rectF.top;
                float f10 = rectF.bottom;
                PointF pointF5 = (PointF) q.g.f(this.f1964p);
                PointF pointF6 = (PointF) q.g.f(this.f1965q);
                PointF pointF7 = (PointF) q.g.f(this.f1967s);
                PointF pointF8 = (PointF) q.g.f(this.f1966r);
                if (rectFL.left > 0.0f) {
                    pointF = pointF8;
                    i5 = iG8;
                    pointF4 = pointF6;
                    pointF2 = pointF7;
                    pointF3 = pointF5;
                    f3 = f10;
                    f4 = f9;
                    f5 = f8;
                    f6 = f7;
                    b(canvas, i3, f7, f9 - 0.8f, pointF5.x, pointF5.y - 0.8f, pointF7.x, pointF7.y + 0.8f, f7, f10 + 0.8f);
                } else {
                    pointF = pointF8;
                    pointF2 = pointF7;
                    pointF3 = pointF5;
                    f3 = f10;
                    f4 = f9;
                    f5 = f8;
                    f6 = f7;
                    i5 = iG8;
                    pointF4 = pointF6;
                }
                if (rectFL.top > 0.0f) {
                    b(canvas, i7, f6 - 0.8f, f4, pointF3.x - 0.8f, pointF3.y, pointF4.x + 0.8f, pointF4.y, f5 + 0.8f, f4);
                }
                if (rectFL.right > 0.0f) {
                    b(canvas, i4, f5, f4 - 0.8f, pointF4.x, pointF4.y - 0.8f, pointF.x, pointF.y + 0.8f, f5, f3 + 0.8f);
                }
                if (rectFL.bottom > 0.0f) {
                    PointF pointF9 = pointF2;
                    b(canvas, i5, f6 - 0.8f, f3, pointF9.x - 0.8f, pointF9.y, pointF.x + 0.8f, pointF.y, f5 + 0.8f, f3);
                }
            } else if (fN > 0.0f) {
                this.f1969u.setColor(u(iG9, this.f1972x));
                this.f1969u.setStyle(Paint.Style.STROKE);
                this.f1969u.setStrokeWidth(fN);
                canvas.drawPath((Path) q.g.f(this.f1959k), this.f1969u);
            }
        }
        canvas.restore();
    }

    private static int e(int i3, int i4, int i5, int i6, int i7, int i8, int i9, int i10) {
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

    private Shader f() {
        List list = this.f1971w;
        Shader composeShader = null;
        if (list == null) {
            return null;
        }
        Iterator it = list.iterator();
        while (it.hasNext()) {
            Shader shaderA = ((Q1.a) it.next()).a(getBounds());
            if (shaderA != null) {
                composeShader = composeShader == null ? shaderA : new ComposeShader(shaderA, composeShader, PorterDuff.Mode.SRC_OVER);
            }
        }
        return composeShader;
    }

    private static void m(double d3, double d4, double d5, double d6, double d7, double d8, double d9, double d10, PointF pointF) {
        double d11 = (d3 + d5) / 2.0d;
        double d12 = (d4 + d6) / 2.0d;
        double d13 = d7 - d11;
        double d14 = d8 - d12;
        double dAbs = Math.abs(d5 - d3) / 2.0d;
        double dAbs2 = Math.abs(d6 - d4) / 2.0d;
        double d15 = ((d10 - d12) - d14) / ((d9 - d11) - d13);
        double d16 = d14 - (d13 * d15);
        double d17 = dAbs2 * dAbs2;
        double d18 = dAbs * dAbs;
        double d19 = d17 + (d18 * d15 * d15);
        double d20 = dAbs * 2.0d * dAbs * d16 * d15;
        double d21 = (-(d18 * ((d16 * d16) - d17))) / d19;
        double d22 = d19 * 2.0d;
        double dSqrt = ((-d20) / d22) - Math.sqrt(d21 + Math.pow(d20 / d22, 2.0d));
        double d23 = (d15 * dSqrt) + d16;
        double d24 = dSqrt + d11;
        double d25 = d23 + d12;
        if (Double.isNaN(d24) || Double.isNaN(d25)) {
            return;
        }
        pointF.x = (float) d24;
        pointF.y = (float) d25;
    }

    private static PathEffect r(Q1.f fVar, float f3) {
        int i3 = a.f1975a[fVar.ordinal()];
        if (i3 == 2) {
            float f4 = f3 * 3.0f;
            return new DashPathEffect(new float[]{f4, f4, f4, f4}, 0.0f);
        }
        if (i3 != 3) {
            return null;
        }
        return new DashPathEffect(new float[]{f3, f3, f3, f3}, 0.0f);
    }

    private boolean t(int i3) {
        C0483z0 c0483z0 = this.f1950b;
        float fA = c0483z0 != null ? c0483z0.a(i3) : Float.NaN;
        C0483z0 c0483z02 = this.f1951c;
        return (Float.isNaN(fA) || Float.isNaN(c0483z02 != null ? c0483z02.a(i3) : Float.NaN)) ? false : true;
    }

    private static int u(int i3, int i4) {
        if (i4 == 255) {
            return i3;
        }
        if (i4 == 0) {
            return i3 & 16777215;
        }
        return (i3 & 16777215) | ((((i3 >>> 24) * (i4 + (i4 >> 7))) >> 8) << 24);
    }

    private void w(int i3, float f3) {
        if (this.f1951c == null) {
            this.f1951c = new C0483z0(255.0f);
        }
        if (L.a(this.f1951c.b(i3), f3)) {
            return;
        }
        this.f1951c.c(i3, f3);
        invalidateSelf();
    }

    private void y(int i3, float f3) {
        if (this.f1950b == null) {
            this.f1950b = new C0483z0(0.0f);
        }
        if (L.a(this.f1950b.b(i3), f3)) {
            return;
        }
        this.f1950b.c(i3, f3);
        invalidateSelf();
    }

    public void A(Q1.f fVar) {
        if (this.f1952d != fVar) {
            this.f1952d = fVar;
            this.f1968t = true;
            invalidateSelf();
        }
    }

    public void B(int i3, float f3) {
        if (this.f1949a == null) {
            this.f1949a = new C0483z0();
        }
        if (L.a(this.f1949a.b(i3), f3)) {
            return;
        }
        this.f1949a.c(i3, f3);
        if (i3 == 0 || i3 == 1 || i3 == 2 || i3 == 3 || i3 == 4 || i3 == 5 || i3 == 8) {
            this.f1968t = true;
        }
        invalidateSelf();
    }

    public void C(int i3) {
        this.f1970v = i3;
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public void draw(Canvas canvas) {
        E();
        if (s()) {
            d(canvas);
        } else {
            c(canvas);
        }
    }

    public int g(int i3) {
        C0483z0 c0483z0 = this.f1950b;
        float fA = c0483z0 != null ? c0483z0.a(i3) : 0.0f;
        C0483z0 c0483z02 = this.f1951c;
        return a(c0483z02 != null ? c0483z02.a(i3) : 255.0f, fA);
    }

    @Override // android.graphics.drawable.Drawable
    public int getAlpha() {
        return this.f1972x;
    }

    @Override // android.graphics.drawable.Drawable
    public int getLayoutDirection() {
        int i3 = this.f1948C;
        return i3 == -1 ? super.getLayoutDirection() : i3;
    }

    @Override // android.graphics.drawable.Drawable
    public int getOpacity() {
        int iAlpha = (Color.alpha(this.f1970v) * this.f1972x) >> 8;
        if (iAlpha != 0) {
            return iAlpha != 255 ? -3 : -1;
        }
        return -2;
    }

    @Override // android.graphics.drawable.Drawable
    public void getOutline(Outline outline) {
        if (!s()) {
            outline.setRect(getBounds());
        } else {
            D();
            outline.setConvexPath((Path) q.g.f(this.f1956h));
        }
    }

    public Q1.e h() {
        return this.f1974z;
    }

    public Float i(int i3) {
        C0483z0 c0483z0 = this.f1949a;
        if (c0483z0 == null) {
            return null;
        }
        float fB = c0483z0.b(i3);
        if (Float.isNaN(fB)) {
            return null;
        }
        return Float.valueOf(fB);
    }

    public float j(float f3, int i3) {
        Float fI = i(i3);
        return fI == null ? f3 : fI.floatValue();
    }

    public int k() {
        return this.f1970v;
    }

    public RectF l() {
        float fJ = j(0.0f, 8);
        float fJ2 = j(fJ, 1);
        float fJ3 = j(fJ, 3);
        float fJ4 = j(fJ, 0);
        float fJ5 = j(fJ, 2);
        if (this.f1949a != null) {
            boolean z3 = getLayoutDirection() == 1;
            float fB = this.f1949a.b(4);
            float fB2 = this.f1949a.b(5);
            if (com.facebook.react.modules.i18nmanager.a.f().d(this.f1947B)) {
                if (!Float.isNaN(fB)) {
                    fJ4 = fB;
                }
                if (!Float.isNaN(fB2)) {
                    fJ5 = fB2;
                }
                float f3 = z3 ? fJ5 : fJ4;
                if (z3) {
                    fJ5 = fJ4;
                }
                fJ4 = f3;
            } else {
                float f4 = z3 ? fB2 : fB;
                if (!z3) {
                    fB = fB2;
                }
                if (!Float.isNaN(f4)) {
                    fJ4 = f4;
                }
                if (!Float.isNaN(fB)) {
                    fJ5 = fB;
                }
            }
        }
        return new RectF(fJ4, fJ2, fJ5, fJ3);
    }

    public float n() {
        C0483z0 c0483z0 = this.f1949a;
        if (c0483z0 == null || Float.isNaN(c0483z0.b(8))) {
            return 0.0f;
        }
        return this.f1949a.b(8);
    }

    public float o(float f3, float f4) {
        return Math.max(f3 - f4, 0.0f);
    }

    @Override // android.graphics.drawable.Drawable
    protected void onBoundsChange(Rect rect) {
        super.onBoundsChange(rect);
        this.f1968t = true;
    }

    public Path p() {
        if (!s()) {
            return null;
        }
        D();
        return new Path((Path) q.g.f(this.f1953e));
    }

    public RectF q() {
        RectF rectFL = l();
        return rectFL == null ? new RectF(0.0f, 0.0f, getBounds().width(), getBounds().height()) : new RectF(rectFL.left, rectFL.top, getBounds().width() - rectFL.right, getBounds().height() - rectFL.bottom);
    }

    public boolean s() {
        return this.f1974z.c();
    }

    @Override // android.graphics.drawable.Drawable
    public void setAlpha(int i3) {
        if (i3 != this.f1972x) {
            this.f1972x = i3;
            invalidateSelf();
        }
    }

    public void v(List list) {
        this.f1971w = list;
        invalidateSelf();
    }

    public void x(int i3, Integer num) {
        float fIntValue = num == null ? Float.NaN : num.intValue() & 16777215;
        float fIntValue2 = num != null ? num.intValue() >>> 24 : Float.NaN;
        y(i3, fIntValue);
        w(i3, fIntValue2);
        this.f1968t = true;
    }

    public void z(Q1.d dVar, W w3) {
        if (Objects.equals(w3, this.f1974z.b(dVar))) {
            return;
        }
        this.f1974z.e(dVar, w3);
        this.f1968t = true;
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public void setColorFilter(ColorFilter colorFilter) {
    }
}
