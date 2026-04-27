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

/* JADX INFO: loaded from: classes.dex */
public final class m extends Drawable {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Context f2010a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final int f2011b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final float f2012c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final float f2013d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final float f2014e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final float f2015f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private Q1.e f2016g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final Paint f2017h;

    public m(Context context, int i3, float f3, float f4, float f5, float f6, Q1.e eVar) {
        t2.j.f(context, "context");
        this.f2010a = context;
        this.f2011b = i3;
        this.f2012c = f3;
        this.f2013d = f4;
        this.f2014e = f5;
        this.f2015f = f6;
        this.f2016g = eVar;
        Paint paint = new Paint();
        paint.setColor(i3);
        float fX = K.f7382a.x(f5 * 0.5f);
        if (fX > 0.0f) {
            paint.setMaskFilter(new BlurMaskFilter(fX, BlurMaskFilter.Blur.NORMAL));
        }
        this.f2017h = paint;
    }

    private final void a(Canvas canvas, RectF rectF) {
        canvas.clipOutRect(getBounds());
        canvas.drawRect(rectF, this.f2017h);
    }

    private final void b(Canvas canvas, RectF rectF, float f3, Q1.j jVar) {
        RectF rectF2 = new RectF(getBounds());
        rectF2.inset(0.4f, 0.4f);
        Path path = new Path();
        float[] fArr = {jVar.c().a(), jVar.c().b(), jVar.d().a(), jVar.d().b(), jVar.b().a(), jVar.b().b(), jVar.a().a(), jVar.a().b()};
        Path.Direction direction = Path.Direction.CW;
        path.addRoundRect(rectF2, fArr, direction);
        canvas.clipOutPath(path);
        Path path2 = new Path();
        path2.addRoundRect(rectF, new float[]{d.a(jVar.c().a(), f3), d.a(jVar.c().b(), f3), d.a(jVar.d().a(), f3), d.a(jVar.d().b(), f3), d.a(jVar.b().a(), f3), d.a(jVar.b().b(), f3), d.a(jVar.a().a(), f3), d.a(jVar.a().b(), f3)}, direction);
        canvas.drawPath(path2, this.f2017h);
    }

    public final void c(Q1.e eVar) {
        this.f2016g = eVar;
    }

    @Override // android.graphics.drawable.Drawable
    public void draw(Canvas canvas) {
        Q1.j jVarD;
        t2.j.f(canvas, "canvas");
        C0444f0 c0444f0 = C0444f0.f7603a;
        float fD = c0444f0.d(getBounds().width());
        float fD2 = c0444f0.d(getBounds().height());
        Q1.e eVar = this.f2016g;
        Q1.j jVar = (eVar == null || (jVarD = eVar.d(getLayoutDirection(), this.f2010a, fD, fD2)) == null) ? null : new Q1.j(new Q1.k(c0444f0.b(jVarD.c().a()), c0444f0.b(jVarD.c().b())), new Q1.k(c0444f0.b(jVarD.d().a()), c0444f0.b(jVarD.d().b())), new Q1.k(c0444f0.b(jVarD.a().a()), c0444f0.b(jVarD.a().b())), new Q1.k(c0444f0.b(jVarD.b().a()), c0444f0.b(jVarD.b().b())));
        float fB = c0444f0.b(this.f2015f);
        RectF rectF = new RectF(getBounds());
        float f3 = -fB;
        rectF.inset(f3, f3);
        rectF.offset(c0444f0.b(this.f2012c), c0444f0.b(this.f2013d));
        int iSave = canvas.save();
        if (jVar == null || !jVar.e()) {
            a(canvas, rectF);
        } else {
            b(canvas, rectF, fB, jVar);
        }
        canvas.restoreToCount(iSave);
    }

    @Override // android.graphics.drawable.Drawable
    public int getOpacity() {
        int alpha = this.f2017h.getAlpha();
        if (alpha == 255) {
            return -1;
        }
        return (1 > alpha || alpha >= 255) ? -2 : -3;
    }

    @Override // android.graphics.drawable.Drawable
    public void setAlpha(int i3) {
        this.f2017h.setAlpha(u2.a.c((i3 / 255.0f) * (Color.alpha(this.f2011b) / 255.0f) * 255.0f));
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public void setColorFilter(ColorFilter colorFilter) {
        this.f2017h.setColorFilter(colorFilter);
        invalidateSelf();
    }
}
