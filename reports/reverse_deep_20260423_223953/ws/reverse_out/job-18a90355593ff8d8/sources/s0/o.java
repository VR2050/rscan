package s0;

import android.graphics.Canvas;
import android.graphics.Matrix;
import android.graphics.PointF;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;

/* JADX INFO: loaded from: classes.dex */
public final class o extends g {

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private q f10107f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    public Object f10108g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    public PointF f10109h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    public int f10110i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    public int f10111j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    public Matrix f10112k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private final Matrix f10113l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public o(Drawable drawable, q qVar) {
        super(drawable);
        t2.j.f(qVar, "scaleType");
        this.f10113l = new Matrix();
        this.f10107f = qVar;
    }

    private final void y() {
        Drawable current = getCurrent();
        if (current == null) {
            return;
        }
        if (this.f10110i == current.getIntrinsicWidth() && this.f10111j == current.getIntrinsicHeight()) {
            return;
        }
        x();
    }

    public final q A() {
        return this.f10107f;
    }

    public final void B(PointF pointF) {
        if (X.i.a(this.f10109h, pointF)) {
            return;
        }
        if (pointF == null) {
            this.f10109h = null;
        } else {
            if (this.f10109h == null) {
                this.f10109h = new PointF();
            }
            PointF pointF2 = this.f10109h;
            t2.j.c(pointF2);
            pointF2.set(pointF);
        }
        x();
        invalidateSelf();
    }

    public final void C(q qVar) {
        t2.j.f(qVar, "scaleType");
        if (X.i.a(this.f10107f, qVar)) {
            return;
        }
        this.f10107f = qVar;
        this.f10108g = null;
        x();
        invalidateSelf();
    }

    @Override // s0.g, android.graphics.drawable.Drawable
    public void draw(Canvas canvas) {
        t2.j.f(canvas, "canvas");
        y();
        if (this.f10112k == null) {
            super.draw(canvas);
            return;
        }
        int iSave = canvas.save();
        canvas.clipRect(getBounds());
        canvas.concat(this.f10112k);
        super.draw(canvas);
        canvas.restoreToCount(iSave);
    }

    @Override // s0.g, s0.D
    public void n(Matrix matrix) {
        t2.j.f(matrix, "transform");
        u(matrix);
        y();
        Matrix matrix2 = this.f10112k;
        if (matrix2 != null) {
            matrix.preConcat(matrix2);
        }
    }

    @Override // s0.g, android.graphics.drawable.Drawable
    protected void onBoundsChange(Rect rect) {
        t2.j.f(rect, "bounds");
        x();
    }

    @Override // s0.g
    public Drawable v(Drawable drawable) {
        Drawable drawableV = super.v(drawable);
        x();
        return drawableV;
    }

    public final void x() {
        float f3;
        float f4;
        Drawable current = getCurrent();
        if (current == null) {
            this.f10111j = 0;
            this.f10110i = 0;
            this.f10112k = null;
            return;
        }
        Rect bounds = getBounds();
        t2.j.e(bounds, "getBounds(...)");
        int iWidth = bounds.width();
        int iHeight = bounds.height();
        int intrinsicWidth = current.getIntrinsicWidth();
        this.f10110i = intrinsicWidth;
        int intrinsicHeight = current.getIntrinsicHeight();
        this.f10111j = intrinsicHeight;
        if (intrinsicWidth <= 0 || intrinsicHeight <= 0) {
            current.setBounds(bounds);
            this.f10112k = null;
            return;
        }
        if (intrinsicWidth == iWidth && intrinsicHeight == iHeight) {
            current.setBounds(bounds);
            this.f10112k = null;
            return;
        }
        if (this.f10107f == q.f10114a) {
            current.setBounds(bounds);
            this.f10112k = null;
            return;
        }
        current.setBounds(0, 0, intrinsicWidth, intrinsicHeight);
        this.f10113l.reset();
        q qVar = this.f10107f;
        Matrix matrix = this.f10113l;
        PointF pointF = this.f10109h;
        if (pointF != null) {
            t2.j.c(pointF);
            f3 = pointF.x;
        } else {
            f3 = 0.5f;
        }
        PointF pointF2 = this.f10109h;
        if (pointF2 != null) {
            t2.j.c(pointF2);
            f4 = pointF2.y;
        } else {
            f4 = 0.5f;
        }
        qVar.a(matrix, bounds, intrinsicWidth, intrinsicHeight, f3, f4);
        this.f10112k = this.f10113l;
    }

    public final PointF z() {
        return this.f10109h;
    }
}
