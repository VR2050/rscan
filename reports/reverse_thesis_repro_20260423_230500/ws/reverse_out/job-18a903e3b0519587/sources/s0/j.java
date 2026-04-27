package s0;

import android.content.res.Resources;
import android.graphics.Bitmap;
import android.graphics.BitmapShader;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.Shader;
import android.graphics.drawable.BitmapDrawable;
import java.lang.ref.WeakReference;

/* JADX INFO: loaded from: classes.dex */
public class j extends m {

    /* JADX INFO: renamed from: K, reason: collision with root package name */
    private static boolean f10035K = false;

    /* JADX INFO: renamed from: E, reason: collision with root package name */
    private final Paint f10036E;

    /* JADX INFO: renamed from: F, reason: collision with root package name */
    private final Paint f10037F;

    /* JADX INFO: renamed from: G, reason: collision with root package name */
    private final Bitmap f10038G;

    /* JADX INFO: renamed from: H, reason: collision with root package name */
    private WeakReference f10039H;

    /* JADX INFO: renamed from: I, reason: collision with root package name */
    private boolean f10040I;

    /* JADX INFO: renamed from: J, reason: collision with root package name */
    private RectF f10041J;

    public j(Resources resources, Bitmap bitmap, Paint paint, boolean z3) {
        super(new BitmapDrawable(resources, bitmap));
        Paint paint2 = new Paint();
        this.f10036E = paint2;
        Paint paint3 = new Paint(1);
        this.f10037F = paint3;
        this.f10041J = null;
        this.f10038G = bitmap;
        if (paint != null) {
            paint2.set(paint);
        }
        paint2.setFlags(1);
        paint3.setStyle(Paint.Style.STROKE);
        this.f10040I = z3;
    }

    public static boolean l() {
        return f10035K;
    }

    private void n() {
        Shader shader;
        WeakReference weakReference = this.f10039H;
        if (weakReference == null || weakReference.get() != this.f10038G) {
            this.f10039H = new WeakReference(this.f10038G);
            if (this.f10038G != null) {
                Paint paint = this.f10036E;
                Bitmap bitmap = this.f10038G;
                Shader.TileMode tileMode = Shader.TileMode.CLAMP;
                paint.setShader(new BitmapShader(bitmap, tileMode, tileMode));
                this.f10087g = true;
            }
        }
        if (this.f10087g && (shader = this.f10036E.getShader()) != null) {
            shader.setLocalMatrix(this.f10105y);
            this.f10087g = false;
        }
        this.f10036E.setFilterBitmap(c());
    }

    @Override // s0.m, android.graphics.drawable.Drawable
    public void draw(Canvas canvas) {
        if (U0.b.d()) {
            U0.b.a("RoundedBitmapDrawable#draw");
        }
        if (!f()) {
            super.draw(canvas);
            if (U0.b.d()) {
                U0.b.b();
                return;
            }
            return;
        }
        k();
        j();
        n();
        int iSave = canvas.save();
        canvas.concat(this.f10102v);
        if (this.f10040I || this.f10041J == null) {
            canvas.drawPath(this.f10086f, this.f10036E);
        } else {
            int iSave2 = canvas.save();
            canvas.clipRect(this.f10041J);
            canvas.drawPath(this.f10086f, this.f10036E);
            canvas.restoreToCount(iSave2);
        }
        float f3 = this.f10085e;
        if (f3 > 0.0f) {
            this.f10037F.setStrokeWidth(f3);
            this.f10037F.setColor(C0685e.c(this.f10088h, this.f10036E.getAlpha()));
            canvas.drawPath(this.f10089i, this.f10037F);
        }
        canvas.restoreToCount(iSave);
        if (U0.b.d()) {
            U0.b.b();
        }
    }

    @Override // s0.m, s0.i
    public void e(boolean z3) {
        this.f10040I = z3;
    }

    @Override // s0.m
    boolean f() {
        return super.f() && this.f10038G != null;
    }

    @Override // s0.m
    protected void k() {
        super.k();
        if (this.f10040I) {
            return;
        }
        if (this.f10041J == null) {
            this.f10041J = new RectF();
        }
        this.f10105y.mapRect(this.f10041J, this.f10095o);
    }

    @Override // s0.m, android.graphics.drawable.Drawable
    public void setAlpha(int i3) {
        super.setAlpha(i3);
        if (i3 != this.f10036E.getAlpha()) {
            this.f10036E.setAlpha(i3);
            super.setAlpha(i3);
            invalidateSelf();
        }
    }

    @Override // s0.m, android.graphics.drawable.Drawable
    public void setColorFilter(ColorFilter colorFilter) {
        super.setColorFilter(colorFilter);
        this.f10036E.setColorFilter(colorFilter);
    }
}
