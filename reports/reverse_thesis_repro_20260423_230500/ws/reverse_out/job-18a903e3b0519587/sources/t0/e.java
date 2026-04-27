package t0;

import android.content.res.Resources;
import android.graphics.PointF;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.NinePatchDrawable;
import s0.InterfaceC0683c;
import s0.g;
import s0.i;
import s0.j;
import s0.k;
import s0.l;
import s0.n;
import s0.o;
import s0.q;
import t0.C0693d;

/* JADX INFO: loaded from: classes.dex */
public abstract class e {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private static final Drawable f10178a = new ColorDrawable(0);

    private static Drawable a(Drawable drawable, C0693d c0693d, Resources resources) {
        if (drawable instanceof BitmapDrawable) {
            BitmapDrawable bitmapDrawable = (BitmapDrawable) drawable;
            j jVar = new j(resources, bitmapDrawable.getBitmap(), bitmapDrawable.getPaint(), c0693d.i());
            b(jVar, c0693d);
            return jVar;
        }
        if (drawable instanceof NinePatchDrawable) {
            n nVar = new n((NinePatchDrawable) drawable);
            b(nVar, c0693d);
            return nVar;
        }
        if (!(drawable instanceof ColorDrawable)) {
            Y.a.K("WrappingUtils", "Don't know how to round that drawable: %s", drawable);
            return drawable;
        }
        k kVarB = k.b((ColorDrawable) drawable);
        b(kVarB, c0693d);
        return kVarB;
    }

    static void b(i iVar, C0693d c0693d) {
        iVar.g(c0693d.j());
        iVar.t(c0693d.d());
        iVar.a(c0693d.b(), c0693d.c());
        iVar.h(c0693d.g());
        iVar.r(c0693d.l());
        iVar.o(c0693d.h());
        iVar.e(c0693d.i());
    }

    static InterfaceC0683c c(InterfaceC0683c interfaceC0683c) {
        while (true) {
            Object objP = interfaceC0683c.p();
            if (objP == interfaceC0683c || !(objP instanceof InterfaceC0683c)) {
                break;
            }
            interfaceC0683c = (InterfaceC0683c) objP;
        }
        return interfaceC0683c;
    }

    static Drawable d(Drawable drawable, C0693d c0693d, Resources resources) {
        try {
            if (U0.b.d()) {
                U0.b.a("WrappingUtils#maybeApplyLeafRounding");
            }
            if (drawable != null && c0693d != null && c0693d.k() == C0693d.a.BITMAP_ONLY) {
                if (!(drawable instanceof g)) {
                    Drawable drawableA = a(drawable, c0693d, resources);
                    if (U0.b.d()) {
                        U0.b.b();
                    }
                    return drawableA;
                }
                InterfaceC0683c interfaceC0683cC = c((g) drawable);
                interfaceC0683cC.d(a(interfaceC0683cC.d(f10178a), c0693d, resources));
                if (U0.b.d()) {
                    U0.b.b();
                }
                return drawable;
            }
            return drawable;
        } finally {
            if (U0.b.d()) {
                U0.b.b();
            }
        }
    }

    static Drawable e(Drawable drawable, C0693d c0693d) {
        try {
            if (U0.b.d()) {
                U0.b.a("WrappingUtils#maybeWrapWithRoundedOverlayColor");
            }
            if (drawable != null && c0693d != null && c0693d.k() == C0693d.a.OVERLAY_COLOR) {
                l lVar = new l(drawable);
                b(lVar, c0693d);
                lVar.y(c0693d.f());
                if (U0.b.d()) {
                    U0.b.b();
                }
                return lVar;
            }
            return drawable;
        } finally {
            if (U0.b.d()) {
                U0.b.b();
            }
        }
    }

    static Drawable f(Drawable drawable, q qVar) {
        return g(drawable, qVar, null);
    }

    static Drawable g(Drawable drawable, q qVar, PointF pointF) {
        if (U0.b.d()) {
            U0.b.a("WrappingUtils#maybeWrapWithScaleType");
        }
        if (drawable == null || qVar == null) {
            if (U0.b.d()) {
                U0.b.b();
            }
            return drawable;
        }
        o oVar = new o(drawable, qVar);
        if (pointF != null) {
            oVar.B(pointF);
        }
        if (U0.b.d()) {
            U0.b.b();
        }
        return oVar;
    }

    static void h(i iVar) {
        iVar.g(false);
        iVar.m(0.0f);
        iVar.a(0, 0.0f);
        iVar.h(0.0f);
        iVar.r(false);
        iVar.o(false);
        iVar.e(j.l());
    }

    /* JADX WARN: Multi-variable type inference failed */
    static void i(InterfaceC0683c interfaceC0683c, C0693d c0693d, Resources resources) {
        InterfaceC0683c interfaceC0683cC = c(interfaceC0683c);
        Drawable drawableP = interfaceC0683cC.p();
        if (c0693d == null || c0693d.k() != C0693d.a.BITMAP_ONLY) {
            if (drawableP instanceof i) {
                h((i) drawableP);
            }
        } else if (drawableP instanceof i) {
            b((i) drawableP, c0693d);
        } else if (drawableP != 0) {
            interfaceC0683cC.d(f10178a);
            interfaceC0683cC.d(a(drawableP, c0693d, resources));
        }
    }

    static void j(InterfaceC0683c interfaceC0683c, C0693d c0693d) {
        Drawable drawableP = interfaceC0683c.p();
        if (c0693d == null || c0693d.k() != C0693d.a.OVERLAY_COLOR) {
            if (drawableP instanceof l) {
                Drawable drawable = f10178a;
                interfaceC0683c.d(((l) drawableP).v(drawable));
                drawable.setCallback(null);
                return;
            }
            return;
        }
        if (!(drawableP instanceof l)) {
            interfaceC0683c.d(e(interfaceC0683c.d(f10178a), c0693d));
            return;
        }
        l lVar = (l) drawableP;
        b(lVar, c0693d);
        lVar.y(c0693d.f());
    }

    static o k(InterfaceC0683c interfaceC0683c, q qVar) {
        Drawable drawableF = f(interfaceC0683c.d(f10178a), qVar);
        interfaceC0683c.d(drawableF);
        X.k.h(drawableF, "Parent has no child drawable!");
        return (o) drawableF;
    }
}
