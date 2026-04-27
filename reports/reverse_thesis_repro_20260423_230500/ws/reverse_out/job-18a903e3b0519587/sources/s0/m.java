package s0;

import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Matrix;
import android.graphics.Path;
import android.graphics.PorterDuff;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import java.util.Arrays;

/* JADX INFO: loaded from: classes.dex */
public abstract class m extends Drawable implements i, C {

    /* JADX INFO: renamed from: D, reason: collision with root package name */
    private D f10081D;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final Drawable f10082b;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    float[] f10092l;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    RectF f10097q;

    /* JADX INFO: renamed from: w, reason: collision with root package name */
    Matrix f10103w;

    /* JADX INFO: renamed from: x, reason: collision with root package name */
    Matrix f10104x;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    protected boolean f10083c = false;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    protected boolean f10084d = false;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    protected float f10085e = 0.0f;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    protected final Path f10086f = new Path();

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    protected boolean f10087g = true;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    protected int f10088h = 0;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    protected final Path f10089i = new Path();

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final float[] f10090j = new float[8];

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    final float[] f10091k = new float[8];

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    final RectF f10093m = new RectF();

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    final RectF f10094n = new RectF();

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    final RectF f10095o = new RectF();

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    final RectF f10096p = new RectF();

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    final Matrix f10098r = new Matrix();

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    final Matrix f10099s = new Matrix();

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    final Matrix f10100t = new Matrix();

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    final Matrix f10101u = new Matrix();

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    final Matrix f10102v = new Matrix();

    /* JADX INFO: renamed from: y, reason: collision with root package name */
    final Matrix f10105y = new Matrix();

    /* JADX INFO: renamed from: z, reason: collision with root package name */
    private float f10106z = 0.0f;

    /* JADX INFO: renamed from: A, reason: collision with root package name */
    private boolean f10078A = false;

    /* JADX INFO: renamed from: B, reason: collision with root package name */
    private boolean f10079B = false;

    /* JADX INFO: renamed from: C, reason: collision with root package name */
    private boolean f10080C = true;

    m(Drawable drawable) {
        this.f10082b = drawable;
    }

    private static Matrix b(Matrix matrix) {
        if (matrix == null) {
            return null;
        }
        return new Matrix(matrix);
    }

    private static boolean d(Matrix matrix, Matrix matrix2) {
        if (matrix == null && matrix2 == null) {
            return true;
        }
        if (matrix == null || matrix2 == null) {
            return false;
        }
        return matrix.equals(matrix2);
    }

    @Override // s0.i
    public void a(int i3, float f3) {
        if (this.f10088h == i3 && this.f10085e == f3) {
            return;
        }
        this.f10088h = i3;
        this.f10085e = f3;
        this.f10080C = true;
        invalidateSelf();
    }

    public boolean c() {
        return this.f10079B;
    }

    @Override // android.graphics.drawable.Drawable
    public void clearColorFilter() {
        this.f10082b.clearColorFilter();
    }

    @Override // android.graphics.drawable.Drawable
    public void draw(Canvas canvas) {
        if (U0.b.d()) {
            U0.b.a("RoundedDrawable#draw");
        }
        this.f10082b.draw(canvas);
        if (U0.b.d()) {
            U0.b.b();
        }
    }

    boolean f() {
        return this.f10083c || this.f10084d || this.f10085e > 0.0f;
    }

    @Override // s0.i
    public void g(boolean z3) {
        this.f10083c = z3;
        this.f10080C = true;
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public int getAlpha() {
        return this.f10082b.getAlpha();
    }

    @Override // android.graphics.drawable.Drawable
    public ColorFilter getColorFilter() {
        return this.f10082b.getColorFilter();
    }

    @Override // android.graphics.drawable.Drawable
    public int getIntrinsicHeight() {
        return this.f10082b.getIntrinsicHeight();
    }

    @Override // android.graphics.drawable.Drawable
    public int getIntrinsicWidth() {
        return this.f10082b.getIntrinsicWidth();
    }

    @Override // android.graphics.drawable.Drawable
    public int getOpacity() {
        return this.f10082b.getOpacity();
    }

    @Override // s0.i
    public void h(float f3) {
        if (this.f10106z != f3) {
            this.f10106z = f3;
            this.f10080C = true;
            invalidateSelf();
        }
    }

    @Override // s0.C
    public void i(D d3) {
        this.f10081D = d3;
    }

    protected void j() {
        float[] fArr;
        if (this.f10080C) {
            this.f10089i.reset();
            RectF rectF = this.f10093m;
            float f3 = this.f10085e;
            rectF.inset(f3 / 2.0f, f3 / 2.0f);
            if (this.f10083c) {
                this.f10089i.addCircle(this.f10093m.centerX(), this.f10093m.centerY(), Math.min(this.f10093m.width(), this.f10093m.height()) / 2.0f, Path.Direction.CW);
            } else {
                int i3 = 0;
                while (true) {
                    fArr = this.f10091k;
                    if (i3 >= fArr.length) {
                        break;
                    }
                    fArr[i3] = (this.f10090j[i3] + this.f10106z) - (this.f10085e / 2.0f);
                    i3++;
                }
                this.f10089i.addRoundRect(this.f10093m, fArr, Path.Direction.CW);
            }
            RectF rectF2 = this.f10093m;
            float f4 = this.f10085e;
            rectF2.inset((-f4) / 2.0f, (-f4) / 2.0f);
            this.f10086f.reset();
            float f5 = this.f10106z + (this.f10078A ? this.f10085e : 0.0f);
            this.f10093m.inset(f5, f5);
            if (this.f10083c) {
                this.f10086f.addCircle(this.f10093m.centerX(), this.f10093m.centerY(), Math.min(this.f10093m.width(), this.f10093m.height()) / 2.0f, Path.Direction.CW);
            } else if (this.f10078A) {
                if (this.f10092l == null) {
                    this.f10092l = new float[8];
                }
                for (int i4 = 0; i4 < this.f10091k.length; i4++) {
                    this.f10092l[i4] = this.f10090j[i4] - this.f10085e;
                }
                this.f10086f.addRoundRect(this.f10093m, this.f10092l, Path.Direction.CW);
            } else {
                this.f10086f.addRoundRect(this.f10093m, this.f10090j, Path.Direction.CW);
            }
            float f6 = -f5;
            this.f10093m.inset(f6, f6);
            this.f10086f.setFillType(Path.FillType.WINDING);
            this.f10080C = false;
        }
    }

    protected void k() {
        Matrix matrix;
        Matrix matrix2;
        D d3 = this.f10081D;
        if (d3 != null) {
            d3.n(this.f10100t);
            this.f10081D.f(this.f10093m);
        } else {
            this.f10100t.reset();
            this.f10093m.set(getBounds());
        }
        this.f10095o.set(0.0f, 0.0f, getIntrinsicWidth(), getIntrinsicHeight());
        this.f10096p.set(this.f10082b.getBounds());
        Matrix matrix3 = this.f10098r;
        RectF rectF = this.f10095o;
        RectF rectF2 = this.f10096p;
        Matrix.ScaleToFit scaleToFit = Matrix.ScaleToFit.FILL;
        matrix3.setRectToRect(rectF, rectF2, scaleToFit);
        if (this.f10078A) {
            RectF rectF3 = this.f10097q;
            if (rectF3 == null) {
                this.f10097q = new RectF(this.f10093m);
            } else {
                rectF3.set(this.f10093m);
            }
            RectF rectF4 = this.f10097q;
            float f3 = this.f10085e;
            rectF4.inset(f3, f3);
            if (this.f10103w == null) {
                this.f10103w = new Matrix();
            }
            this.f10103w.setRectToRect(this.f10093m, this.f10097q, scaleToFit);
        } else {
            Matrix matrix4 = this.f10103w;
            if (matrix4 != null) {
                matrix4.reset();
            }
        }
        if (!this.f10100t.equals(this.f10101u) || !this.f10098r.equals(this.f10099s) || ((matrix2 = this.f10103w) != null && !d(matrix2, this.f10104x))) {
            this.f10087g = true;
            this.f10100t.invert(this.f10102v);
            this.f10105y.set(this.f10100t);
            if (this.f10078A && (matrix = this.f10103w) != null) {
                this.f10105y.postConcat(matrix);
            }
            this.f10105y.preConcat(this.f10098r);
            this.f10101u.set(this.f10100t);
            this.f10099s.set(this.f10098r);
            if (this.f10078A) {
                Matrix matrix5 = this.f10104x;
                if (matrix5 == null) {
                    this.f10104x = b(this.f10103w);
                } else {
                    matrix5.set(this.f10103w);
                }
            } else {
                Matrix matrix6 = this.f10104x;
                if (matrix6 != null) {
                    matrix6.reset();
                }
            }
        }
        if (this.f10093m.equals(this.f10094n)) {
            return;
        }
        this.f10080C = true;
        this.f10094n.set(this.f10093m);
    }

    @Override // s0.i
    public void m(float f3) {
        X.k.i(f3 >= 0.0f);
        Arrays.fill(this.f10090j, f3);
        this.f10084d = f3 != 0.0f;
        this.f10080C = true;
        invalidateSelf();
    }

    @Override // s0.i
    public void o(boolean z3) {
        if (this.f10079B != z3) {
            this.f10079B = z3;
            invalidateSelf();
        }
    }

    @Override // android.graphics.drawable.Drawable
    protected void onBoundsChange(Rect rect) {
        this.f10082b.setBounds(rect);
    }

    @Override // s0.i
    public void r(boolean z3) {
        if (this.f10078A != z3) {
            this.f10078A = z3;
            this.f10080C = true;
            invalidateSelf();
        }
    }

    @Override // android.graphics.drawable.Drawable
    public void setAlpha(int i3) {
        this.f10082b.setAlpha(i3);
    }

    @Override // android.graphics.drawable.Drawable
    public void setColorFilter(int i3, PorterDuff.Mode mode) {
        this.f10082b.setColorFilter(i3, mode);
    }

    @Override // s0.i
    public void t(float[] fArr) {
        if (fArr == null) {
            Arrays.fill(this.f10090j, 0.0f);
            this.f10084d = false;
        } else {
            X.k.c(fArr.length == 8, "radii should have exactly 8 values");
            System.arraycopy(fArr, 0, this.f10090j, 0, 8);
            this.f10084d = false;
            for (int i3 = 0; i3 < 8; i3++) {
                this.f10084d |= fArr[i3] > 0.0f;
            }
        }
        this.f10080C = true;
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public void setColorFilter(ColorFilter colorFilter) {
        this.f10082b.setColorFilter(colorFilter);
    }

    public void e(boolean z3) {
    }
}
