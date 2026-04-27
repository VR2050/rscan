package com.facebook.react.uimanager;

import Q1.g;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Path;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.view.View;
import android.widget.ImageView;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import i2.AbstractC0586n;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import q1.C0655b;

/* JADX INFO: renamed from: com.facebook.react.uimanager.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0433a {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final C0433a f7567a = new C0433a();

    private C0433a() {
    }

    public static final void a(View view, Canvas canvas) {
        RectF rectFA;
        float fB;
        float fB2;
        float fB3;
        t2.j.f(view, "view");
        t2.j.f(canvas, "canvas");
        if (!C0655b.h()) {
            Rect rect = new Rect();
            view.getDrawingRect(rect);
            N1.e eVarJ = f7567a.j(view);
            if (eVarJ == null) {
                canvas.clipRect(rect);
                return;
            }
            Path pathP = eVarJ.p();
            if (pathP != null) {
                pathP.offset(rect.left, rect.top);
                canvas.clipPath(pathP);
                return;
            } else {
                RectF rectFQ = eVarJ.q();
                t2.j.e(rectFQ, "getPaddingBoxRect(...)");
                rectFQ.offset(rect.left, rect.top);
                canvas.clipRect(rectFQ);
                return;
            }
        }
        view.getDrawingRect(new Rect());
        C0433a c0433a = f7567a;
        N1.g gVarF = c0433a.f(view);
        RectF rectF = new RectF();
        Q1.c cVarC = gVarF.c();
        if (cVarC != null) {
            int layoutDirection = gVarF.getLayoutDirection();
            Context context = view.getContext();
            t2.j.e(context, "getContext(...)");
            rectFA = cVarC.a(layoutDirection, context);
        } else {
            rectFA = null;
        }
        float f3 = gVarF.getBounds().left;
        float fB4 = 0.0f;
        if (rectFA != null) {
            fB = C0444f0.f7603a.b(rectFA.left);
        } else {
            fB = 0.0f;
        }
        rectF.left = f3 + fB;
        float f4 = gVarF.getBounds().top;
        if (rectFA != null) {
            fB2 = C0444f0.f7603a.b(rectFA.top);
        } else {
            fB2 = 0.0f;
        }
        rectF.top = f4 + fB2;
        float f5 = gVarF.getBounds().right;
        if (rectFA != null) {
            fB3 = C0444f0.f7603a.b(rectFA.right);
        } else {
            fB3 = 0.0f;
        }
        rectF.right = f5 - fB3;
        float f6 = gVarF.getBounds().bottom;
        if (rectFA != null) {
            fB4 = C0444f0.f7603a.b(rectFA.bottom);
        }
        rectF.bottom = f6 - fB4;
        Q1.e eVarD = gVarF.d();
        if (eVarD == null || !eVarD.c()) {
            rectF.offset(r0.left, r0.top);
            canvas.clipRect(rectF);
        } else {
            Path pathB = c0433a.b(view, gVarF, rectF, rectFA);
            pathB.offset(r0.left, r0.top);
            canvas.clipPath(pathB);
        }
    }

    private final Path b(View view, N1.g gVar, RectF rectF, RectF rectF2) {
        Q1.j jVarD;
        Q1.k kVarA;
        Q1.k kVarA2;
        Q1.k kVarB;
        Q1.k kVarB2;
        Q1.k kVarD;
        Q1.k kVarD2;
        Q1.k kVarC;
        Q1.k kVarC2;
        Q1.e eVarD = gVar.d();
        if (eVarD != null) {
            int layoutDirection = gVar.getLayoutDirection();
            Context context = view.getContext();
            t2.j.e(context, "getContext(...)");
            jVarD = eVarD.d(layoutDirection, context, C0444f0.f(gVar.getBounds().width()), C0444f0.f(gVar.getBounds().height()));
        } else {
            jVarD = null;
        }
        Path path = new Path();
        path.addRoundRect(rectF, new float[]{l((jVarD == null || (kVarC2 = jVarD.c()) == null) ? null : Float.valueOf(C0444f0.f7603a.b(kVarC2.a())), rectF2 != null ? Float.valueOf(C0444f0.f7603a.b(rectF2.left)) : null), l((jVarD == null || (kVarC = jVarD.c()) == null) ? null : Float.valueOf(C0444f0.f7603a.b(kVarC.b())), rectF2 != null ? Float.valueOf(C0444f0.f7603a.b(rectF2.top)) : null), l((jVarD == null || (kVarD2 = jVarD.d()) == null) ? null : Float.valueOf(C0444f0.f7603a.b(kVarD2.a())), rectF2 != null ? Float.valueOf(C0444f0.f7603a.b(rectF2.right)) : null), l((jVarD == null || (kVarD = jVarD.d()) == null) ? null : Float.valueOf(C0444f0.f7603a.b(kVarD.b())), rectF2 != null ? Float.valueOf(C0444f0.f7603a.b(rectF2.top)) : null), l((jVarD == null || (kVarB2 = jVarD.b()) == null) ? null : Float.valueOf(C0444f0.f7603a.b(kVarB2.a())), rectF2 != null ? Float.valueOf(C0444f0.f7603a.b(rectF2.right)) : null), l((jVarD == null || (kVarB = jVarD.b()) == null) ? null : Float.valueOf(C0444f0.f7603a.b(kVarB.b())), rectF2 != null ? Float.valueOf(C0444f0.f7603a.b(rectF2.bottom)) : null), l((jVarD == null || (kVarA2 = jVarD.a()) == null) ? null : Float.valueOf(C0444f0.f7603a.b(kVarA2.a())), rectF2 != null ? Float.valueOf(C0444f0.f7603a.b(rectF2.left)) : null), l((jVarD == null || (kVarA = jVarD.a()) == null) ? null : Float.valueOf(C0444f0.f7603a.b(kVarA.b())), rectF2 != null ? Float.valueOf(C0444f0.f7603a.b(rectF2.bottom)) : null)}, Path.Direction.CW);
        return path;
    }

    private final N1.a c(View view) {
        N1.g gVarF = f(view);
        N1.a aVarA = gVarF.a();
        if (aVarA != null) {
            return aVarA;
        }
        Context context = view.getContext();
        t2.j.e(context, "getContext(...)");
        N1.a aVar = new N1.a(context, gVarF.d(), gVarF.c());
        view.setBackground(gVarF.l(aVar));
        return aVar;
    }

    private final N1.c d(View view) {
        N1.g gVarF = f(view);
        N1.c cVarB = gVarF.b();
        if (cVarB != null) {
            return cVarB;
        }
        Context context = view.getContext();
        t2.j.e(context, "getContext(...)");
        Q1.e eVarD = gVarF.d();
        N1.c cVar = new N1.c(context, new C0483z0(0.0f), eVarD, gVarF.c(), Q1.f.f2432c);
        view.setBackground(gVarF.m(cVar));
        return cVar;
    }

    private final N1.e e(View view) {
        N1.g gVarF = f(view);
        N1.e eVarE = gVarF.e();
        if (eVarE != null) {
            return eVarE;
        }
        N1.e eVar = new N1.e(view.getContext());
        view.setBackground(gVarF.n(eVar));
        return eVar;
    }

    private final N1.g f(View view) {
        if (view.getBackground() instanceof N1.g) {
            Drawable background = view.getBackground();
            t2.j.d(background, "null cannot be cast to non-null type com.facebook.react.uimanager.drawable.CompositeBackgroundDrawable");
            return (N1.g) background;
        }
        Context context = view.getContext();
        t2.j.e(context, "getContext(...)");
        N1.g gVar = new N1.g(context, view.getBackground(), null, null, null, null, null, null, null, null, null, 2044, null);
        view.setBackground(gVar);
        return gVar;
    }

    private final N1.k g(View view) {
        N1.g gVarF = f(view);
        N1.k kVarI = gVarF.i();
        if (kVarI != null) {
            return kVarI;
        }
        Q1.e eVarD = C0655b.h() ? gVarF.d() : e(view).h();
        Context context = view.getContext();
        t2.j.e(context, "getContext(...)");
        N1.k kVar = new N1.k(context, eVarD, -16777216, 0.0f, Q1.o.f2493c, 0.0f);
        view.setBackground(gVarF.p(kVar));
        return kVar;
    }

    private final N1.a h(View view) {
        N1.g gVarK = k(view);
        if (gVarK != null) {
            return gVarK.a();
        }
        return null;
    }

    public static final Integer i(View view) {
        t2.j.f(view, "view");
        if (C0655b.h()) {
            N1.a aVarH = f7567a.h(view);
            if (aVarH != null) {
                return Integer.valueOf(aVarH.b());
            }
            return null;
        }
        N1.e eVarJ = f7567a.j(view);
        if (eVarJ != null) {
            return Integer.valueOf(eVarJ.k());
        }
        return null;
    }

    private final N1.e j(View view) {
        N1.g gVarK = k(view);
        if (gVarK != null) {
            return gVarK.e();
        }
        return null;
    }

    private final N1.g k(View view) {
        Drawable background = view.getBackground();
        if (background instanceof N1.g) {
            return (N1.g) background;
        }
        return null;
    }

    private final float l(Float f3, Float f4) {
        return w2.d.b((f3 != null ? f3.floatValue() : 0.0f) - (f4 != null ? f4.floatValue() : 0.0f), 0.0f);
    }

    public static final void m(View view) {
        t2.j.f(view, "view");
        if (view.getBackground() instanceof N1.g) {
            Drawable background = view.getBackground();
            t2.j.d(background, "null cannot be cast to non-null type com.facebook.react.uimanager.drawable.CompositeBackgroundDrawable");
            view.setBackground(((N1.g) background).g());
        }
    }

    public static final void n(View view, Integer num) {
        t2.j.f(view, "view");
        if ((num == null || num.intValue() == 0) && !(view.getBackground() instanceof N1.g)) {
            return;
        }
        if (C0655b.h()) {
            f7567a.c(view).d(num != null ? num.intValue() : 0);
        } else {
            f7567a.e(view).C(num != null ? num.intValue() : 0);
        }
    }

    public static final void o(View view, List list) {
        t2.j.f(view, "view");
        if (C0655b.h()) {
            f7567a.c(view).e(list);
        } else {
            f7567a.e(view).v(list);
        }
    }

    public static final void p(View view, Q1.n nVar, Integer num) {
        t2.j.f(view, "view");
        t2.j.f(nVar, "edge");
        if (C0655b.h()) {
            f7567a.d(view).o(nVar, num);
        } else {
            f7567a.e(view).x(nVar.b(), num);
        }
    }

    public static final void q(View view, Q1.d dVar, W w3) {
        t2.j.f(view, "view");
        t2.j.f(dVar, "corner");
        C0433a c0433a = f7567a;
        N1.g gVarF = c0433a.f(view);
        Q1.e eVarD = gVarF.d();
        if (eVarD == null) {
            eVarD = new Q1.e(null, null, null, null, null, null, null, null, null, null, null, null, null, 8191, null);
        }
        gVarF.k(eVarD);
        Q1.e eVarD2 = gVarF.d();
        if (eVarD2 != null) {
            eVarD2.e(dVar, w3);
        }
        if (C0655b.h()) {
            if (view instanceof ImageView) {
                c0433a.c(view);
            }
            N1.a aVarA = gVarF.a();
            if (aVarA != null) {
                aVarA.g(gVarF.d());
            }
            N1.c cVarB = gVarF.b();
            if (cVarB != null) {
                cVarB.q(gVarF.d());
            }
            N1.a aVarA2 = gVarF.a();
            if (aVarA2 != null) {
                aVarA2.invalidateSelf();
            }
            N1.c cVarB2 = gVarF.b();
            if (cVarB2 != null) {
                cVarB2.invalidateSelf();
            }
        } else {
            c0433a.e(view).z(dVar, w3);
        }
        if (Build.VERSION.SDK_INT >= 28) {
            List listH = gVarF.h();
            ArrayList arrayList = new ArrayList();
            for (Object obj : listH) {
                if (obj instanceof N1.m) {
                    arrayList.add(obj);
                }
            }
            Iterator it = arrayList.iterator();
            while (it.hasNext()) {
                ((N1.m) it.next()).c(gVarF.d());
            }
        }
        if (Build.VERSION.SDK_INT >= 29) {
            List listF = gVarF.f();
            ArrayList arrayList2 = new ArrayList();
            for (Object obj2 : listF) {
                if (obj2 instanceof N1.i) {
                    arrayList2.add(obj2);
                }
            }
            Iterator it2 = arrayList2.iterator();
            while (it2.hasNext()) {
                ((N1.i) it2.next()).e(gVarF.d());
            }
        }
        N1.k kVarI = gVarF.i();
        if (kVarI != null) {
            kVarI.e(gVarF.d());
        }
        gVarF.invalidateSelf();
    }

    public static final void r(View view, Q1.f fVar) {
        t2.j.f(view, "view");
        if (C0655b.h()) {
            f7567a.d(view).r(fVar);
        } else {
            f7567a.e(view).A(fVar);
        }
    }

    public static final void s(View view, Q1.n nVar, Float f3) {
        t2.j.f(view, "view");
        t2.j.f(nVar, "edge");
        C0433a c0433a = f7567a;
        N1.g gVarF = c0433a.f(view);
        Q1.c cVarC = gVarF.c();
        if (cVarC == null) {
            cVarC = new Q1.c();
        }
        gVarF.j(cVarC);
        Q1.c cVarC2 = gVarF.c();
        if (cVarC2 != null) {
            cVarC2.b(nVar, f3);
        }
        if (C0655b.h()) {
            c0433a.d(view).s(nVar.b(), f3 != null ? C0444f0.f7603a.b(f3.floatValue()) : Float.NaN);
            N1.a aVarA = gVarF.a();
            if (aVarA != null) {
                aVarA.f(gVarF.c());
            }
            N1.c cVarB = gVarF.b();
            if (cVarB != null) {
                cVarB.p(gVarF.c());
            }
            N1.a aVarA2 = gVarF.a();
            if (aVarA2 != null) {
                aVarA2.invalidateSelf();
            }
            N1.c cVarB2 = gVarF.b();
            if (cVarB2 != null) {
                cVarB2.invalidateSelf();
            }
        } else {
            c0433a.e(view).B(nVar.b(), f3 != null ? C0444f0.f7603a.b(f3.floatValue()) : Float.NaN);
        }
        Q1.c cVarC3 = gVarF.c();
        if (cVarC3 == null) {
            cVarC3 = new Q1.c();
        }
        gVarF.j(cVarC3);
        Q1.c cVarC4 = gVarF.c();
        if (cVarC4 != null) {
            cVarC4.b(nVar, f3);
        }
        if (Build.VERSION.SDK_INT >= 29) {
            List listF = gVarF.f();
            ArrayList arrayList = new ArrayList();
            for (Object obj : listF) {
                if (obj instanceof N1.i) {
                    arrayList.add(obj);
                }
            }
            Iterator it = arrayList.iterator();
            while (it.hasNext()) {
                ((N1.i) it.next()).d(gVarF.c());
            }
        }
    }

    public static final void t(View view, ReadableArray readableArray) {
        t2.j.f(view, "view");
        if (readableArray == null) {
            u(view, AbstractC0586n.g());
            return;
        }
        ArrayList arrayList = new ArrayList();
        int size = readableArray.size();
        for (int i3 = 0; i3 < size; i3++) {
            g.a aVar = Q1.g.f2437g;
            ReadableMap map = readableArray.getMap(i3);
            Context context = view.getContext();
            t2.j.e(context, "getContext(...)");
            Q1.g gVarA = aVar.a(map, context);
            if (gVarA == null) {
                throw new IllegalStateException("Required value was null.");
            }
            arrayList.add(gVarA);
        }
        u(view, arrayList);
    }

    public static final void u(View view, List list) {
        t2.j.f(view, "view");
        t2.j.f(list, "shadows");
        if (L1.a.c(view) != 2) {
            return;
        }
        ArrayList arrayList = new ArrayList();
        ArrayList arrayList2 = new ArrayList();
        N1.g gVarF = f7567a.f(view);
        Q1.c cVarC = gVarF.c();
        Q1.e eVarD = gVarF.d();
        Iterator it = list.iterator();
        while (it.hasNext()) {
            Q1.g gVar = (Q1.g) it.next();
            float fD = gVar.d();
            float fE = gVar.e();
            Integer numB = gVar.b();
            int iIntValue = numB != null ? numB.intValue() : -16777216;
            Float fA = gVar.a();
            float fFloatValue = fA != null ? fA.floatValue() : 0.0f;
            Float f3 = gVar.f();
            float fFloatValue2 = f3 != null ? f3.floatValue() : 0.0f;
            Boolean boolC = gVar.c();
            boolean zBooleanValue = boolC != null ? boolC.booleanValue() : false;
            if (zBooleanValue && Build.VERSION.SDK_INT >= 29) {
                Context context = view.getContext();
                t2.j.e(context, "getContext(...)");
                arrayList.add(new N1.i(context, iIntValue, fD, fE, fFloatValue, fFloatValue2, cVarC, eVarD));
            } else if (!zBooleanValue && Build.VERSION.SDK_INT >= 28) {
                Context context2 = view.getContext();
                t2.j.e(context2, "getContext(...)");
                arrayList2.add(new N1.m(context2, iIntValue, fD, fE, fFloatValue, fFloatValue2, eVarD));
            }
        }
        view.setBackground(f7567a.f(view).q(arrayList2, arrayList));
    }

    public static final void v(View view, Drawable drawable) {
        t2.j.f(view, "view");
        if (C0655b.h()) {
            f7567a.f(view).o(drawable);
        } else {
            view.setBackground(f7567a.f(view).o(drawable));
        }
    }

    public static final void w(View view, Integer num) {
        t2.j.f(view, "view");
        if (L1.a.c(view) != 2) {
            return;
        }
        N1.k kVarG = f7567a.g(view);
        if (num != null) {
            kVarG.f(num.intValue());
        }
    }

    public static final void x(View view, float f3) {
        t2.j.f(view, "view");
        if (L1.a.c(view) != 2) {
            return;
        }
        f7567a.g(view).g(C0444f0.f7603a.b(f3));
    }

    public static final void y(View view, Q1.o oVar) {
        t2.j.f(view, "view");
        if (L1.a.c(view) != 2) {
            return;
        }
        N1.k kVarG = f7567a.g(view);
        if (oVar != null) {
            kVarG.h(oVar);
        }
    }

    public static final void z(View view, float f3) {
        t2.j.f(view, "view");
        if (L1.a.c(view) != 2) {
            return;
        }
        f7567a.g(view).i(C0444f0.f7603a.b(f3));
    }
}
