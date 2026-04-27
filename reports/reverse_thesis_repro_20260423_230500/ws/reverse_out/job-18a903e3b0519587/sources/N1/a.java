package N1;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.ColorFilter;
import android.graphics.ComposeShader;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.PorterDuff;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.Shader;
import android.graphics.drawable.Drawable;
import com.facebook.react.uimanager.C0444f0;
import java.util.List;

/* JADX INFO: loaded from: classes.dex */
public final class a extends Drawable {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Context f1906a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private Q1.e f1907b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private Q1.c f1908c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final float f1909d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private RectF f1910e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private Q1.j f1911f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private boolean f1912g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private int f1913h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private RectF f1914i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private Path f1915j;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private List f1916k;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private final Paint f1917l;

    public a(Context context, Q1.e eVar, Q1.c cVar) {
        t2.j.f(context, "context");
        this.f1906a = context;
        this.f1907b = eVar;
        this.f1908c = cVar;
        this.f1909d = 0.8f;
        this.f1912g = true;
        this.f1914i = new RectF();
        Paint paint = new Paint(1);
        paint.setStyle(Paint.Style.FILL);
        paint.setColor(this.f1913h);
        this.f1917l = paint;
    }

    private final RectF a() {
        Q1.c cVar = this.f1908c;
        RectF rectFA = cVar != null ? cVar.a(getLayoutDirection(), this.f1906a) : null;
        return new RectF(rectFA != null ? C0444f0.f7603a.b(rectFA.left) : 0.0f, rectFA != null ? C0444f0.f7603a.b(rectFA.top) : 0.0f, rectFA != null ? C0444f0.f7603a.b(rectFA.right) : 0.0f, rectFA != null ? C0444f0.f7603a.b(rectFA.bottom) : 0.0f);
    }

    private final Shader c() {
        List<Q1.a> list = this.f1916k;
        Shader composeShader = null;
        if (list != null) {
            for (Q1.a aVar : list) {
                Rect bounds = getBounds();
                t2.j.e(bounds, "getBounds(...)");
                Shader shaderA = aVar.a(bounds);
                if (shaderA != null) {
                    composeShader = composeShader == null ? shaderA : new ComposeShader(shaderA, composeShader, PorterDuff.Mode.SRC_OVER);
                }
            }
        }
        return composeShader;
    }

    /* JADX WARN: Removed duplicated region for block: B:34:0x008f  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private final void h() {
        /*
            Method dump skipped, instruction units count: 448
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: N1.a.h():void");
    }

    public final int b() {
        return this.f1913h;
    }

    public final void d(int i3) {
        if (this.f1913h != i3) {
            this.f1913h = i3;
            this.f1917l.setColor(i3);
            invalidateSelf();
        }
    }

    @Override // android.graphics.drawable.Drawable
    public void draw(Canvas canvas) {
        Q1.e eVar;
        Q1.k kVarC;
        Q1.k kVarC2;
        Q1.e eVar2;
        Q1.k kVarC3;
        Q1.k kVarC4;
        t2.j.f(canvas, "canvas");
        h();
        canvas.save();
        float fB = 0.0f;
        if (this.f1917l.getAlpha() != 0) {
            Q1.j jVar = this.f1911f;
            if (jVar == null || !jVar.f() || (eVar2 = this.f1907b) == null || !eVar2.c()) {
                Q1.e eVar3 = this.f1907b;
                if (eVar3 == null || !eVar3.c()) {
                    canvas.drawRect(this.f1914i, this.f1917l);
                } else {
                    Path path = this.f1915j;
                    if (path == null) {
                        throw new IllegalStateException("Required value was null.");
                    }
                    canvas.drawPath(path, this.f1917l);
                }
            } else {
                RectF rectF = this.f1914i;
                Q1.j jVar2 = this.f1911f;
                float fB2 = (jVar2 == null || (kVarC4 = jVar2.c()) == null) ? 0.0f : C0444f0.f7603a.b(kVarC4.a());
                Q1.j jVar3 = this.f1911f;
                canvas.drawRoundRect(rectF, fB2, (jVar3 == null || (kVarC3 = jVar3.c()) == null) ? 0.0f : C0444f0.f7603a.b(kVarC3.b()), this.f1917l);
            }
        }
        List list = this.f1916k;
        if (list != null && list != null && (!list.isEmpty())) {
            this.f1917l.setShader(c());
            Q1.j jVar4 = this.f1911f;
            if (jVar4 == null || !jVar4.f() || (eVar = this.f1907b) == null || !eVar.c()) {
                Q1.e eVar4 = this.f1907b;
                if (eVar4 == null || !eVar4.c()) {
                    canvas.drawRect(this.f1914i, this.f1917l);
                } else {
                    Path path2 = this.f1915j;
                    if (path2 == null) {
                        throw new IllegalStateException("Required value was null.");
                    }
                    canvas.drawPath(path2, this.f1917l);
                }
            } else {
                RectF rectF2 = this.f1914i;
                Q1.j jVar5 = this.f1911f;
                float fB3 = (jVar5 == null || (kVarC2 = jVar5.c()) == null) ? 0.0f : C0444f0.f7603a.b(kVarC2.a());
                Q1.j jVar6 = this.f1911f;
                if (jVar6 != null && (kVarC = jVar6.c()) != null) {
                    fB = C0444f0.f7603a.b(kVarC.b());
                }
                canvas.drawRoundRect(rectF2, fB3, fB, this.f1917l);
            }
            this.f1917l.setShader(null);
        }
        canvas.restore();
    }

    public final void e(List list) {
        if (t2.j.b(this.f1916k, list)) {
            return;
        }
        this.f1916k = list;
        invalidateSelf();
    }

    public final void f(Q1.c cVar) {
        this.f1908c = cVar;
    }

    public final void g(Q1.e eVar) {
        this.f1907b = eVar;
    }

    @Override // android.graphics.drawable.Drawable
    public int getOpacity() {
        int alpha = this.f1917l.getAlpha();
        if (alpha == 255) {
            return -1;
        }
        return (1 > alpha || alpha >= 255) ? -2 : -3;
    }

    @Override // android.graphics.drawable.Drawable
    public void invalidateSelf() {
        this.f1912g = true;
        super.invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    protected void onBoundsChange(Rect rect) {
        t2.j.f(rect, "bounds");
        super.onBoundsChange(rect);
        this.f1912g = true;
    }

    @Override // android.graphics.drawable.Drawable
    public void setAlpha(int i3) {
        this.f1917l.setAlpha(u2.a.c((i3 / 255.0f) * (Color.alpha(this.f1913h) / 255.0f) * 255.0f));
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public void setColorFilter(ColorFilter colorFilter) {
    }
}
