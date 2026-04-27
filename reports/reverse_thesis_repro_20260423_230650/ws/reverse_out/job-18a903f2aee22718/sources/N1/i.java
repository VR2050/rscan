package N1;

import android.content.Context;
import android.graphics.BlurMaskFilter;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import com.facebook.react.uimanager.C0444f0;
import com.facebook.react.uimanager.K;
import i2.AbstractC0586n;
import java.util.ArrayList;

/* JADX INFO: loaded from: classes.dex */
public final class i extends Drawable {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Context f1988a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final int f1989b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final float f1990c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final float f1991d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final float f1992e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final float f1993f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private Q1.c f1994g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private Q1.e f1995h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final Paint f1996i;

    public i(Context context, int i3, float f3, float f4, float f5, float f6, Q1.c cVar, Q1.e eVar) {
        t2.j.f(context, "context");
        this.f1988a = context;
        this.f1989b = i3;
        this.f1990c = f3;
        this.f1991d = f4;
        this.f1992e = f5;
        this.f1993f = f6;
        this.f1994g = cVar;
        this.f1995h = eVar;
        Paint paint = new Paint();
        paint.setColor(i3);
        float fX = K.f7382a.x(f5 * 0.5f);
        if (fX > 0.0f) {
            paint.setMaskFilter(new BlurMaskFilter(fX, BlurMaskFilter.Blur.NORMAL));
        }
        this.f1996i = paint;
    }

    private final RectF a() {
        RectF rectFA;
        Q1.c cVar = this.f1994g;
        if (cVar == null || (rectFA = cVar.a(getLayoutDirection(), this.f1988a)) == null) {
            return null;
        }
        C0444f0 c0444f0 = C0444f0.f7603a;
        return new RectF(c0444f0.b(rectFA.left), c0444f0.b(rectFA.top), c0444f0.b(rectFA.right), c0444f0.b(rectFA.bottom));
    }

    private final Q1.j b() {
        Q1.j jVarD;
        Q1.e eVar = this.f1995h;
        if (eVar != null) {
            int layoutDirection = getLayoutDirection();
            Context context = this.f1988a;
            C0444f0 c0444f0 = C0444f0.f7603a;
            jVarD = eVar.d(layoutDirection, context, c0444f0.d(getBounds().width()), c0444f0.d(getBounds().height()));
        } else {
            jVarD = null;
        }
        if (jVarD == null || !jVarD.e()) {
            return null;
        }
        C0444f0 c0444f02 = C0444f0.f7603a;
        return new Q1.j(new Q1.k(c0444f02.b(jVarD.c().a()), c0444f02.b(jVarD.c().b())), new Q1.k(c0444f02.b(jVarD.d().a()), c0444f02.b(jVarD.d().b())), new Q1.k(c0444f02.b(jVarD.a().a()), c0444f02.b(jVarD.a().b())), new Q1.k(c0444f02.b(jVarD.b().a()), c0444f02.b(jVarD.b().b())));
    }

    private final float c(float f3, Float f4) {
        return w2.d.b(f3 - (f4 != null ? f4.floatValue() : 0.0f), 0.0f);
    }

    public final void d(Q1.c cVar) {
        this.f1994g = cVar;
    }

    @Override // android.graphics.drawable.Drawable
    public void draw(Canvas canvas) {
        t2.j.f(canvas, "canvas");
        Q1.j jVarB = b();
        RectF rectFA = a();
        RectF rectF = new RectF(getBounds().left + (rectFA != null ? rectFA.left : 0.0f), getBounds().top + (rectFA != null ? rectFA.top : 0.0f), getBounds().right - (rectFA != null ? rectFA.right : 0.0f), getBounds().bottom - (rectFA != null ? rectFA.bottom : 0.0f));
        float[] fArr = jVarB != null ? new float[]{c(jVarB.c().a(), rectFA != null ? Float.valueOf(rectFA.left) : null), c(jVarB.c().b(), rectFA != null ? Float.valueOf(rectFA.top) : null), c(jVarB.d().a(), rectFA != null ? Float.valueOf(rectFA.right) : null), c(jVarB.d().b(), rectFA != null ? Float.valueOf(rectFA.top) : null), c(jVarB.b().a(), rectFA != null ? Float.valueOf(rectFA.right) : null), c(jVarB.b().b(), rectFA != null ? Float.valueOf(rectFA.bottom) : null), c(jVarB.a().a(), rectFA != null ? Float.valueOf(rectFA.left) : null), c(jVarB.a().b(), rectFA != null ? Float.valueOf(rectFA.bottom) : null)} : null;
        C0444f0 c0444f0 = C0444f0.f7603a;
        float fB = c0444f0.b(this.f1990c);
        float fB2 = c0444f0.b(this.f1991d);
        float fB3 = c0444f0.b(this.f1993f);
        RectF rectF2 = new RectF(rectF);
        rectF2.inset(fB3, fB3);
        rectF2.offset(fB, fB2);
        float fX = K.f7382a.x(this.f1992e);
        RectF rectF3 = new RectF(rectF);
        float f3 = -fX;
        rectF3.inset(f3, f3);
        if (fB3 < 0.0f) {
            rectF3.inset(fB3, fB3);
        }
        RectF rectF4 = new RectF(rectF3);
        rectF4.offset(-fB, -fB2);
        rectF3.union(rectF4);
        int iSave = canvas.save();
        if (fArr != null) {
            Path path = new Path();
            path.addRoundRect(rectF, fArr, Path.Direction.CW);
            canvas.clipPath(path);
            ArrayList arrayList = new ArrayList(fArr.length);
            for (float f4 : fArr) {
                arrayList.add(Float.valueOf(d.a(f4, -fB3)));
            }
            canvas.drawDoubleRoundRect(rectF3, j.f1997a, rectF2, AbstractC0586n.S(arrayList), this.f1996i);
        } else {
            canvas.clipRect(rectF);
            canvas.drawDoubleRoundRect(rectF3, j.f1997a, rectF2, j.f1997a, this.f1996i);
        }
        canvas.restoreToCount(iSave);
    }

    public final void e(Q1.e eVar) {
        this.f1995h = eVar;
    }

    @Override // android.graphics.drawable.Drawable
    public int getOpacity() {
        int alpha = this.f1996i.getAlpha();
        if (alpha == 255) {
            return -1;
        }
        return (1 > alpha || alpha >= 255) ? -2 : -3;
    }

    @Override // android.graphics.drawable.Drawable
    public void setAlpha(int i3) {
        this.f1996i.setAlpha(u2.a.c((i3 / 255.0f) * (Color.alpha(this.f1989b) / 255.0f) * 255.0f));
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public void setColorFilter(ColorFilter colorFilter) {
        this.f1996i.setColorFilter(colorFilter);
        invalidateSelf();
    }
}
