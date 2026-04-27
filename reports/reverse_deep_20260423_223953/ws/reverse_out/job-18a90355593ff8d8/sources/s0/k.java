package s0;

import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import java.util.Arrays;

/* JADX INFO: loaded from: classes.dex */
public class k extends Drawable implements i {

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    float[] f10044d;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final float[] f10042b = new float[8];

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    final float[] f10043c = new float[8];

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    final Paint f10045e = new Paint(1);

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private boolean f10046f = false;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private float f10047g = 0.0f;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private float f10048h = 0.0f;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private int f10049i = 0;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private boolean f10050j = false;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private boolean f10051k = false;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    final Path f10052l = new Path();

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    final Path f10053m = new Path();

    /* JADX INFO: renamed from: n, reason: collision with root package name */
    private int f10054n = 0;

    /* JADX INFO: renamed from: o, reason: collision with root package name */
    private final RectF f10055o = new RectF();

    /* JADX INFO: renamed from: p, reason: collision with root package name */
    private int f10056p = 255;

    public k(int i3) {
        d(i3);
    }

    public static k b(ColorDrawable colorDrawable) {
        return new k(colorDrawable.getColor());
    }

    private void f() {
        float[] fArr;
        float[] fArr2;
        this.f10052l.reset();
        this.f10053m.reset();
        this.f10055o.set(getBounds());
        RectF rectF = this.f10055o;
        float f3 = this.f10047g;
        rectF.inset(f3 / 2.0f, f3 / 2.0f);
        int i3 = 0;
        if (this.f10046f) {
            this.f10053m.addCircle(this.f10055o.centerX(), this.f10055o.centerY(), Math.min(this.f10055o.width(), this.f10055o.height()) / 2.0f, Path.Direction.CW);
        } else {
            int i4 = 0;
            while (true) {
                fArr = this.f10043c;
                if (i4 >= fArr.length) {
                    break;
                }
                fArr[i4] = (this.f10042b[i4] + this.f10048h) - (this.f10047g / 2.0f);
                i4++;
            }
            this.f10053m.addRoundRect(this.f10055o, fArr, Path.Direction.CW);
        }
        RectF rectF2 = this.f10055o;
        float f4 = this.f10047g;
        rectF2.inset((-f4) / 2.0f, (-f4) / 2.0f);
        float f5 = this.f10048h + (this.f10050j ? this.f10047g : 0.0f);
        this.f10055o.inset(f5, f5);
        if (this.f10046f) {
            this.f10052l.addCircle(this.f10055o.centerX(), this.f10055o.centerY(), Math.min(this.f10055o.width(), this.f10055o.height()) / 2.0f, Path.Direction.CW);
        } else if (this.f10050j) {
            if (this.f10044d == null) {
                this.f10044d = new float[8];
            }
            while (true) {
                fArr2 = this.f10044d;
                if (i3 >= fArr2.length) {
                    break;
                }
                fArr2[i3] = this.f10042b[i3] - this.f10047g;
                i3++;
            }
            this.f10052l.addRoundRect(this.f10055o, fArr2, Path.Direction.CW);
        } else {
            this.f10052l.addRoundRect(this.f10055o, this.f10042b, Path.Direction.CW);
        }
        float f6 = -f5;
        this.f10055o.inset(f6, f6);
    }

    @Override // s0.i
    public void a(int i3, float f3) {
        if (this.f10049i != i3) {
            this.f10049i = i3;
            invalidateSelf();
        }
        if (this.f10047g != f3) {
            this.f10047g = f3;
            f();
            invalidateSelf();
        }
    }

    public boolean c() {
        return this.f10051k;
    }

    public void d(int i3) {
        if (this.f10054n != i3) {
            this.f10054n = i3;
            invalidateSelf();
        }
    }

    @Override // android.graphics.drawable.Drawable
    public void draw(Canvas canvas) {
        this.f10045e.setColor(C0685e.c(this.f10054n, this.f10056p));
        this.f10045e.setStyle(Paint.Style.FILL);
        this.f10045e.setFilterBitmap(c());
        canvas.drawPath(this.f10052l, this.f10045e);
        if (this.f10047g != 0.0f) {
            this.f10045e.setColor(C0685e.c(this.f10049i, this.f10056p));
            this.f10045e.setStyle(Paint.Style.STROKE);
            this.f10045e.setStrokeWidth(this.f10047g);
            canvas.drawPath(this.f10053m, this.f10045e);
        }
    }

    @Override // s0.i
    public void g(boolean z3) {
        this.f10046f = z3;
        f();
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public int getAlpha() {
        return this.f10056p;
    }

    @Override // android.graphics.drawable.Drawable
    public int getOpacity() {
        return C0685e.b(C0685e.c(this.f10054n, this.f10056p));
    }

    @Override // s0.i
    public void h(float f3) {
        if (this.f10048h != f3) {
            this.f10048h = f3;
            f();
            invalidateSelf();
        }
    }

    @Override // s0.i
    public void m(float f3) {
        X.k.c(f3 >= 0.0f, "radius should be non negative");
        Arrays.fill(this.f10042b, f3);
        f();
        invalidateSelf();
    }

    @Override // s0.i
    public void o(boolean z3) {
        if (this.f10051k != z3) {
            this.f10051k = z3;
            invalidateSelf();
        }
    }

    @Override // android.graphics.drawable.Drawable
    protected void onBoundsChange(Rect rect) {
        super.onBoundsChange(rect);
        f();
    }

    @Override // s0.i
    public void r(boolean z3) {
        if (this.f10050j != z3) {
            this.f10050j = z3;
            f();
            invalidateSelf();
        }
    }

    @Override // android.graphics.drawable.Drawable
    public void setAlpha(int i3) {
        if (i3 != this.f10056p) {
            this.f10056p = i3;
            invalidateSelf();
        }
    }

    @Override // s0.i
    public void t(float[] fArr) {
        if (fArr == null) {
            Arrays.fill(this.f10042b, 0.0f);
        } else {
            X.k.c(fArr.length == 8, "radii should have exactly 8 values");
            System.arraycopy(fArr, 0, this.f10042b, 0, 8);
        }
        f();
        invalidateSelf();
    }

    @Override // s0.i
    public void e(boolean z3) {
    }

    @Override // android.graphics.drawable.Drawable
    public void setColorFilter(ColorFilter colorFilter) {
    }
}
