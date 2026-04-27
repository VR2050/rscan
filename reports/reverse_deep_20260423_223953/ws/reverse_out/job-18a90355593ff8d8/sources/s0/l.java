package s0;

import android.graphics.Canvas;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import java.util.Arrays;

/* JADX INFO: loaded from: classes.dex */
public class l extends g implements i {

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    b f10057f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final RectF f10058g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private RectF f10059h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private Matrix f10060i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private final float[] f10061j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    final float[] f10062k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    final Paint f10063l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private boolean f10064m;

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private float f10065n;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private int f10066o;

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private int f10067p;

    /* JADX INFO: renamed from: q, reason: collision with root package name */
    private float f10068q;

    /* JADX INFO: renamed from: r, reason: collision with root package name */
    private boolean f10069r;

    /* JADX INFO: renamed from: s, reason: collision with root package name */
    private boolean f10070s;

    /* JADX INFO: renamed from: t, reason: collision with root package name */
    private final Path f10071t;

    /* JADX INFO: renamed from: u, reason: collision with root package name */
    private final Path f10072u;

    /* JADX INFO: renamed from: v, reason: collision with root package name */
    private final RectF f10073v;

    static /* synthetic */ class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        static final /* synthetic */ int[] f10074a;

        static {
            int[] iArr = new int[b.values().length];
            f10074a = iArr;
            try {
                iArr[b.CLIPPING.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                f10074a[b.OVERLAY_COLOR.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
        }
    }

    public enum b {
        OVERLAY_COLOR,
        CLIPPING
    }

    public l(Drawable drawable) {
        super((Drawable) X.k.g(drawable));
        this.f10057f = b.OVERLAY_COLOR;
        this.f10058g = new RectF();
        this.f10061j = new float[8];
        this.f10062k = new float[8];
        this.f10063l = new Paint(1);
        this.f10064m = false;
        this.f10065n = 0.0f;
        this.f10066o = 0;
        this.f10067p = 0;
        this.f10068q = 0.0f;
        this.f10069r = false;
        this.f10070s = false;
        this.f10071t = new Path();
        this.f10072u = new Path();
        this.f10073v = new RectF();
    }

    private void z() {
        float[] fArr;
        this.f10071t.reset();
        this.f10072u.reset();
        this.f10073v.set(getBounds());
        RectF rectF = this.f10073v;
        float f3 = this.f10068q;
        rectF.inset(f3, f3);
        if (this.f10057f == b.OVERLAY_COLOR) {
            this.f10071t.addRect(this.f10073v, Path.Direction.CW);
        }
        if (this.f10064m) {
            this.f10071t.addCircle(this.f10073v.centerX(), this.f10073v.centerY(), Math.min(this.f10073v.width(), this.f10073v.height()) / 2.0f, Path.Direction.CW);
        } else {
            this.f10071t.addRoundRect(this.f10073v, this.f10061j, Path.Direction.CW);
        }
        RectF rectF2 = this.f10073v;
        float f4 = this.f10068q;
        rectF2.inset(-f4, -f4);
        RectF rectF3 = this.f10073v;
        float f5 = this.f10065n;
        rectF3.inset(f5 / 2.0f, f5 / 2.0f);
        if (this.f10064m) {
            this.f10072u.addCircle(this.f10073v.centerX(), this.f10073v.centerY(), Math.min(this.f10073v.width(), this.f10073v.height()) / 2.0f, Path.Direction.CW);
        } else {
            int i3 = 0;
            while (true) {
                fArr = this.f10062k;
                if (i3 >= fArr.length) {
                    break;
                }
                fArr[i3] = (this.f10061j[i3] + this.f10068q) - (this.f10065n / 2.0f);
                i3++;
            }
            this.f10072u.addRoundRect(this.f10073v, fArr, Path.Direction.CW);
        }
        RectF rectF4 = this.f10073v;
        float f6 = this.f10065n;
        rectF4.inset((-f6) / 2.0f, (-f6) / 2.0f);
    }

    @Override // s0.i
    public void a(int i3, float f3) {
        this.f10066o = i3;
        this.f10065n = f3;
        z();
        invalidateSelf();
    }

    @Override // s0.g, android.graphics.drawable.Drawable
    public void draw(Canvas canvas) {
        this.f10058g.set(getBounds());
        int i3 = a.f10074a[this.f10057f.ordinal()];
        if (i3 == 1) {
            int iSave = canvas.save();
            canvas.clipPath(this.f10071t);
            super.draw(canvas);
            canvas.restoreToCount(iSave);
        } else if (i3 == 2) {
            if (this.f10069r) {
                RectF rectF = this.f10059h;
                if (rectF == null) {
                    this.f10059h = new RectF(this.f10058g);
                    this.f10060i = new Matrix();
                } else {
                    rectF.set(this.f10058g);
                }
                RectF rectF2 = this.f10059h;
                float f3 = this.f10065n;
                rectF2.inset(f3, f3);
                Matrix matrix = this.f10060i;
                if (matrix != null) {
                    matrix.setRectToRect(this.f10058g, this.f10059h, Matrix.ScaleToFit.FILL);
                }
                int iSave2 = canvas.save();
                canvas.clipRect(this.f10058g);
                canvas.concat(this.f10060i);
                super.draw(canvas);
                canvas.restoreToCount(iSave2);
            } else {
                super.draw(canvas);
            }
            this.f10063l.setStyle(Paint.Style.FILL);
            this.f10063l.setColor(this.f10067p);
            this.f10063l.setStrokeWidth(0.0f);
            this.f10063l.setFilterBitmap(x());
            this.f10071t.setFillType(Path.FillType.EVEN_ODD);
            canvas.drawPath(this.f10071t, this.f10063l);
            if (this.f10064m) {
                float fWidth = ((this.f10058g.width() - this.f10058g.height()) + this.f10065n) / 2.0f;
                float fHeight = ((this.f10058g.height() - this.f10058g.width()) + this.f10065n) / 2.0f;
                if (fWidth > 0.0f) {
                    RectF rectF3 = this.f10058g;
                    float f4 = rectF3.left;
                    canvas.drawRect(f4, rectF3.top, f4 + fWidth, rectF3.bottom, this.f10063l);
                    RectF rectF4 = this.f10058g;
                    float f5 = rectF4.right;
                    canvas.drawRect(f5 - fWidth, rectF4.top, f5, rectF4.bottom, this.f10063l);
                }
                if (fHeight > 0.0f) {
                    RectF rectF5 = this.f10058g;
                    float f6 = rectF5.left;
                    float f7 = rectF5.top;
                    canvas.drawRect(f6, f7, rectF5.right, f7 + fHeight, this.f10063l);
                    RectF rectF6 = this.f10058g;
                    float f8 = rectF6.left;
                    float f9 = rectF6.bottom;
                    canvas.drawRect(f8, f9 - fHeight, rectF6.right, f9, this.f10063l);
                }
            }
        }
        if (this.f10066o != 0) {
            this.f10063l.setStyle(Paint.Style.STROKE);
            this.f10063l.setColor(this.f10066o);
            this.f10063l.setStrokeWidth(this.f10065n);
            this.f10071t.setFillType(Path.FillType.EVEN_ODD);
            canvas.drawPath(this.f10072u, this.f10063l);
        }
    }

    @Override // s0.i
    public void g(boolean z3) {
        this.f10064m = z3;
        z();
        invalidateSelf();
    }

    @Override // s0.i
    public void h(float f3) {
        this.f10068q = f3;
        z();
        invalidateSelf();
    }

    @Override // s0.i
    public void m(float f3) {
        Arrays.fill(this.f10061j, f3);
        z();
        invalidateSelf();
    }

    @Override // s0.i
    public void o(boolean z3) {
        if (this.f10070s != z3) {
            this.f10070s = z3;
            invalidateSelf();
        }
    }

    @Override // s0.g, android.graphics.drawable.Drawable
    protected void onBoundsChange(Rect rect) {
        super.onBoundsChange(rect);
        z();
    }

    @Override // s0.i
    public void r(boolean z3) {
        this.f10069r = z3;
        z();
        invalidateSelf();
    }

    @Override // s0.i
    public void t(float[] fArr) {
        if (fArr == null) {
            Arrays.fill(this.f10061j, 0.0f);
        } else {
            X.k.c(fArr.length == 8, "radii should have exactly 8 values");
            System.arraycopy(fArr, 0, this.f10061j, 0, 8);
        }
        z();
        invalidateSelf();
    }

    public boolean x() {
        return this.f10070s;
    }

    public void y(int i3) {
        this.f10067p = i3;
        invalidateSelf();
    }

    @Override // s0.i
    public void e(boolean z3) {
    }
}
