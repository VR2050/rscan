package N1;

import Q1.o;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.ColorFilter;
import android.graphics.DashPathEffect;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.PathEffect;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import com.facebook.react.uimanager.C0444f0;
import h2.C0562h;

/* JADX INFO: loaded from: classes.dex */
public final class k extends Drawable {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Context f1998a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private Q1.e f1999b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final float f2000c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private float f2001d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private o f2002e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private int f2003f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private float f2004g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private final Paint f2005h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private Q1.j f2006i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private RectF f2007j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private final Path f2008k;

    public /* synthetic */ class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        public static final /* synthetic */ int[] f2009a;

        static {
            int[] iArr = new int[o.values().length];
            try {
                iArr[o.f2493c.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                iArr[o.f2494d.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                iArr[o.f2495e.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            f2009a = iArr;
        }
    }

    public k(Context context, Q1.e eVar, int i3, float f3, o oVar, float f4) {
        t2.j.f(context, "context");
        t2.j.f(oVar, "outlineStyle");
        this.f1998a = context;
        this.f1999b = eVar;
        this.f2000c = 0.8f;
        this.f2001d = f3;
        this.f2002e = oVar;
        this.f2003f = i3;
        this.f2004g = f4;
        Paint paint = new Paint();
        paint.setStyle(Paint.Style.STROKE);
        paint.setColor(i3);
        paint.setStrokeWidth(f4);
        paint.setPathEffect(d(oVar, f4));
        this.f2005h = paint;
        this.f2007j = new RectF();
        this.f2008k = new Path();
    }

    private final float a(float f3, float f4) {
        if (f3 == 0.0f) {
            return 0.0f;
        }
        return f3 + (f4 * 0.5f);
    }

    private final void b(Canvas canvas) {
        this.f2008k.addRect(this.f2007j, Path.Direction.CW);
        canvas.drawPath(this.f2008k, this.f2005h);
    }

    private final void c(Canvas canvas) {
        Q1.k kVar;
        Q1.k kVar2;
        Q1.k kVar3;
        Q1.k kVar4;
        Q1.k kVarB;
        Q1.k kVarA;
        Q1.k kVarD;
        Q1.k kVarC;
        Q1.j jVar = this.f2006i;
        if (jVar == null || (kVarC = jVar.c()) == null || (kVar = kVarC.c()) == null) {
            kVar = new Q1.k(0.0f, 0.0f);
        }
        Q1.j jVar2 = this.f2006i;
        if (jVar2 == null || (kVarD = jVar2.d()) == null || (kVar2 = kVarD.c()) == null) {
            kVar2 = new Q1.k(0.0f, 0.0f);
        }
        Q1.j jVar3 = this.f2006i;
        if (jVar3 == null || (kVarA = jVar3.a()) == null || (kVar3 = kVarA.c()) == null) {
            kVar3 = new Q1.k(0.0f, 0.0f);
        }
        Q1.j jVar4 = this.f2006i;
        if (jVar4 == null || (kVarB = jVar4.b()) == null || (kVar4 = kVarB.c()) == null) {
            kVar4 = new Q1.k(0.0f, 0.0f);
        }
        this.f2008k.addRoundRect(this.f2007j, new float[]{a(kVar.a(), this.f2004g), a(kVar.b(), this.f2004g), a(kVar2.a(), this.f2004g), a(kVar2.b(), this.f2004g), a(kVar4.a(), this.f2004g), a(kVar4.b(), this.f2004g), a(kVar3.a(), this.f2004g), a(kVar3.b(), this.f2004g)}, Path.Direction.CW);
        canvas.drawPath(this.f2008k, this.f2005h);
    }

    private final PathEffect d(o oVar, float f3) {
        int i3 = a.f2009a[oVar.ordinal()];
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

    private final void j() {
        this.f2007j.set(getBounds());
        RectF rectF = this.f2007j;
        float f3 = rectF.top;
        float f4 = this.f2004g;
        float f5 = this.f2001d;
        float f6 = this.f2000c;
        rectF.top = f3 - (((f4 * 0.5f) + f5) - f6);
        rectF.bottom += ((f4 * 0.5f) + f5) - f6;
        rectF.left -= ((f4 * 0.5f) + f5) - f6;
        rectF.right += ((f4 * 0.5f) + f5) - f6;
    }

    @Override // android.graphics.drawable.Drawable
    public void draw(Canvas canvas) {
        Q1.j jVarD;
        t2.j.f(canvas, "canvas");
        if (this.f2004g == 0.0f) {
            return;
        }
        this.f2008k.reset();
        Q1.e eVar = this.f1999b;
        if (eVar != null) {
            int layoutDirection = getLayoutDirection();
            Context context = this.f1998a;
            C0444f0 c0444f0 = C0444f0.f7603a;
            jVarD = eVar.d(layoutDirection, context, c0444f0.e(getBounds().width()), c0444f0.e(getBounds().height()));
        } else {
            jVarD = null;
        }
        this.f2006i = jVarD;
        j();
        Q1.j jVar = this.f2006i;
        if (jVar == null || jVar == null || !jVar.e()) {
            b(canvas);
        } else {
            c(canvas);
        }
    }

    public final void e(Q1.e eVar) {
        this.f1999b = eVar;
    }

    public final void f(int i3) {
        if (i3 != this.f2003f) {
            this.f2003f = i3;
            this.f2005h.setColor(i3);
            invalidateSelf();
        }
    }

    public final void g(float f3) {
        if (f3 == this.f2001d) {
            return;
        }
        this.f2001d = f3;
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public int getOpacity() {
        int alpha = this.f2005h.getAlpha();
        if (alpha == 255) {
            return -1;
        }
        return (1 > alpha || alpha >= 255) ? -2 : -3;
    }

    public final void h(o oVar) {
        t2.j.f(oVar, "value");
        if (oVar != this.f2002e) {
            this.f2002e = oVar;
            this.f2005h.setPathEffect(d(oVar, this.f2004g));
            invalidateSelf();
        }
    }

    public final void i(float f3) {
        if (f3 == this.f2004g) {
            return;
        }
        this.f2004g = f3;
        this.f2005h.setStrokeWidth(f3);
        this.f2005h.setPathEffect(d(this.f2002e, f3));
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public void setAlpha(int i3) {
        this.f2005h.setAlpha(u2.a.c((i3 / 255.0f) * (Color.alpha(this.f2003f) / 255.0f) * 255.0f));
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public void setColorFilter(ColorFilter colorFilter) {
        this.f2005h.setColorFilter(colorFilter);
        invalidateSelf();
    }
}
