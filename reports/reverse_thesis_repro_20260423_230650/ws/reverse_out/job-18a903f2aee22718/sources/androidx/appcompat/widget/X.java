package androidx.appcompat.widget;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.content.res.XmlResourceParser;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.LayerDrawable;
import android.util.AttributeSet;
import android.util.Log;
import android.util.TypedValue;
import android.util.Xml;
import g.AbstractC0530a;
import java.lang.ref.WeakReference;
import java.util.WeakHashMap;
import l.C0609d;
import l.C0610e;
import l.C0612g;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

/* JADX INFO: loaded from: classes.dex */
public final class X {

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private static X f3930i;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private WeakHashMap f3932a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private C0612g f3933b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private l.h f3934c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final WeakHashMap f3935d = new WeakHashMap(0);

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private TypedValue f3936e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private boolean f3937f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private c f3938g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private static final PorterDuff.Mode f3929h = PorterDuff.Mode.SRC_IN;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private static final a f3931j = new a(6);

    private static class a extends C0610e {
        public a(int i3) {
            super(i3);
        }

        private static int h(int i3, PorterDuff.Mode mode) {
            return ((i3 + 31) * 31) + mode.hashCode();
        }

        PorterDuffColorFilter i(int i3, PorterDuff.Mode mode) {
            return (PorterDuffColorFilter) c(Integer.valueOf(h(i3, mode)));
        }

        PorterDuffColorFilter j(int i3, PorterDuff.Mode mode, PorterDuffColorFilter porterDuffColorFilter) {
            return (PorterDuffColorFilter) d(Integer.valueOf(h(i3, mode)), porterDuffColorFilter);
        }
    }

    private interface b {
        Drawable a(Context context, XmlPullParser xmlPullParser, AttributeSet attributeSet, Resources.Theme theme);
    }

    public interface c {
        boolean a(Context context, int i3, Drawable drawable);

        PorterDuff.Mode b(int i3);

        Drawable c(X x3, Context context, int i3);

        ColorStateList d(Context context, int i3);

        boolean e(Context context, int i3, Drawable drawable);
    }

    private synchronized boolean a(Context context, long j3, Drawable drawable) {
        try {
            Drawable.ConstantState constantState = drawable.getConstantState();
            if (constantState == null) {
                return false;
            }
            C0609d c0609d = (C0609d) this.f3935d.get(context);
            if (c0609d == null) {
                c0609d = new C0609d();
                this.f3935d.put(context, c0609d);
            }
            c0609d.h(j3, new WeakReference(constantState));
            return true;
        } catch (Throwable th) {
            throw th;
        }
    }

    private void b(Context context, int i3, ColorStateList colorStateList) {
        if (this.f3932a == null) {
            this.f3932a = new WeakHashMap();
        }
        l.h hVar = (l.h) this.f3932a.get(context);
        if (hVar == null) {
            hVar = new l.h();
            this.f3932a.put(context, hVar);
        }
        hVar.a(i3, colorStateList);
    }

    private void c(Context context) {
        if (this.f3937f) {
            return;
        }
        this.f3937f = true;
        Drawable drawableI = i(context, AbstractC0530a.f9202a);
        if (drawableI == null || !p(drawableI)) {
            this.f3937f = false;
            throw new IllegalStateException("This app has been built with an incorrect configuration. Please configure your build for VectorDrawableCompat.");
        }
    }

    private static long d(TypedValue typedValue) {
        return (((long) typedValue.assetCookie) << 32) | ((long) typedValue.data);
    }

    private Drawable e(Context context, int i3) {
        if (this.f3936e == null) {
            this.f3936e = new TypedValue();
        }
        TypedValue typedValue = this.f3936e;
        context.getResources().getValue(i3, typedValue, true);
        long jD = d(typedValue);
        Drawable drawableH = h(context, jD);
        if (drawableH != null) {
            return drawableH;
        }
        c cVar = this.f3938g;
        Drawable drawableC = cVar == null ? null : cVar.c(this, context, i3);
        if (drawableC != null) {
            drawableC.setChangingConfigurations(typedValue.changingConfigurations);
            a(context, jD, drawableC);
        }
        return drawableC;
    }

    private static PorterDuffColorFilter f(ColorStateList colorStateList, PorterDuff.Mode mode, int[] iArr) {
        if (colorStateList == null || mode == null) {
            return null;
        }
        return k(colorStateList.getColorForState(iArr, 0), mode);
    }

    public static synchronized X g() {
        try {
            if (f3930i == null) {
                X x3 = new X();
                f3930i = x3;
                o(x3);
            }
        } catch (Throwable th) {
            throw th;
        }
        return f3930i;
    }

    private synchronized Drawable h(Context context, long j3) {
        C0609d c0609d = (C0609d) this.f3935d.get(context);
        if (c0609d == null) {
            return null;
        }
        WeakReference weakReference = (WeakReference) c0609d.e(j3);
        if (weakReference != null) {
            Drawable.ConstantState constantState = (Drawable.ConstantState) weakReference.get();
            if (constantState != null) {
                return constantState.newDrawable(context.getResources());
            }
            c0609d.j(j3);
        }
        return null;
    }

    public static synchronized PorterDuffColorFilter k(int i3, PorterDuff.Mode mode) {
        PorterDuffColorFilter porterDuffColorFilterI;
        a aVar = f3931j;
        porterDuffColorFilterI = aVar.i(i3, mode);
        if (porterDuffColorFilterI == null) {
            porterDuffColorFilterI = new PorterDuffColorFilter(i3, mode);
            aVar.j(i3, mode, porterDuffColorFilterI);
        }
        return porterDuffColorFilterI;
    }

    private ColorStateList m(Context context, int i3) {
        l.h hVar;
        WeakHashMap weakHashMap = this.f3932a;
        if (weakHashMap == null || (hVar = (l.h) weakHashMap.get(context)) == null) {
            return null;
        }
        return (ColorStateList) hVar.g(i3);
    }

    private static void o(X x3) {
    }

    private static boolean p(Drawable drawable) {
        return (drawable instanceof J.b) || "android.graphics.drawable.VectorDrawable".equals(drawable.getClass().getName());
    }

    private Drawable q(Context context, int i3) {
        int next;
        C0612g c0612g = this.f3933b;
        if (c0612g == null || c0612g.isEmpty()) {
            return null;
        }
        l.h hVar = this.f3934c;
        if (hVar != null) {
            String str = (String) hVar.g(i3);
            if ("appcompat_skip_skip".equals(str) || (str != null && this.f3933b.get(str) == null)) {
                return null;
            }
        } else {
            this.f3934c = new l.h();
        }
        if (this.f3936e == null) {
            this.f3936e = new TypedValue();
        }
        TypedValue typedValue = this.f3936e;
        Resources resources = context.getResources();
        resources.getValue(i3, typedValue, true);
        long jD = d(typedValue);
        Drawable drawableH = h(context, jD);
        if (drawableH != null) {
            return drawableH;
        }
        CharSequence charSequence = typedValue.string;
        if (charSequence != null && charSequence.toString().endsWith(".xml")) {
            try {
                XmlResourceParser xml = resources.getXml(i3);
                AttributeSet attributeSetAsAttributeSet = Xml.asAttributeSet(xml);
                do {
                    next = xml.next();
                    if (next == 2) {
                        break;
                    }
                } while (next != 1);
                if (next != 2) {
                    throw new XmlPullParserException("No start tag found");
                }
                String name = xml.getName();
                this.f3934c.a(i3, name);
                b bVar = (b) this.f3933b.get(name);
                if (bVar != null) {
                    drawableH = bVar.a(context, xml, attributeSetAsAttributeSet, context.getTheme());
                }
                if (drawableH != null) {
                    drawableH.setChangingConfigurations(typedValue.changingConfigurations);
                    a(context, jD, drawableH);
                }
            } catch (Exception e3) {
                Log.e("ResourceManagerInternal", "Exception while inflating drawable", e3);
            }
        }
        if (drawableH == null) {
            this.f3934c.a(i3, "appcompat_skip_skip");
        }
        return drawableH;
    }

    private Drawable u(Context context, int i3, boolean z3, Drawable drawable) {
        ColorStateList colorStateListL = l(context, i3);
        if (colorStateListL != null) {
            Drawable drawableJ = androidx.core.graphics.drawable.a.j(drawable.mutate());
            androidx.core.graphics.drawable.a.g(drawableJ, colorStateListL);
            PorterDuff.Mode modeN = n(i3);
            if (modeN == null) {
                return drawableJ;
            }
            androidx.core.graphics.drawable.a.h(drawableJ, modeN);
            return drawableJ;
        }
        c cVar = this.f3938g;
        if ((cVar == null || !cVar.e(context, i3, drawable)) && !w(context, i3, drawable) && z3) {
            return null;
        }
        return drawable;
    }

    static void v(Drawable drawable, e0 e0Var, int[] iArr) {
        int[] state = drawable.getState();
        if (drawable.mutate() != drawable) {
            Log.d("ResourceManagerInternal", "Mutated drawable is not the same instance as the input.");
            return;
        }
        if ((drawable instanceof LayerDrawable) && drawable.isStateful()) {
            drawable.setState(new int[0]);
            drawable.setState(state);
        }
        boolean z3 = e0Var.f4063d;
        if (z3 || e0Var.f4062c) {
            drawable.setColorFilter(f(z3 ? e0Var.f4060a : null, e0Var.f4062c ? e0Var.f4061b : f3929h, iArr));
        } else {
            drawable.clearColorFilter();
        }
    }

    public synchronized Drawable i(Context context, int i3) {
        return j(context, i3, false);
    }

    synchronized Drawable j(Context context, int i3, boolean z3) {
        Drawable drawableQ;
        try {
            c(context);
            drawableQ = q(context, i3);
            if (drawableQ == null) {
                drawableQ = e(context, i3);
            }
            if (drawableQ == null) {
                drawableQ = androidx.core.content.a.d(context, i3);
            }
            if (drawableQ != null) {
                drawableQ = u(context, i3, z3, drawableQ);
            }
            if (drawableQ != null) {
                O.a(drawableQ);
            }
        } catch (Throwable th) {
            throw th;
        }
        return drawableQ;
    }

    synchronized ColorStateList l(Context context, int i3) {
        ColorStateList colorStateListM;
        colorStateListM = m(context, i3);
        if (colorStateListM == null) {
            c cVar = this.f3938g;
            colorStateListM = cVar == null ? null : cVar.d(context, i3);
            if (colorStateListM != null) {
                b(context, i3, colorStateListM);
            }
        }
        return colorStateListM;
    }

    PorterDuff.Mode n(int i3) {
        c cVar = this.f3938g;
        if (cVar == null) {
            return null;
        }
        return cVar.b(i3);
    }

    public synchronized void r(Context context) {
        C0609d c0609d = (C0609d) this.f3935d.get(context);
        if (c0609d != null) {
            c0609d.a();
        }
    }

    synchronized Drawable s(Context context, q0 q0Var, int i3) {
        try {
            Drawable drawableQ = q(context, i3);
            if (drawableQ == null) {
                drawableQ = q0Var.a(i3);
            }
            if (drawableQ == null) {
                return null;
            }
            return u(context, i3, false, drawableQ);
        } catch (Throwable th) {
            throw th;
        }
    }

    public synchronized void t(c cVar) {
        this.f3938g = cVar;
    }

    boolean w(Context context, int i3, Drawable drawable) {
        c cVar = this.f3938g;
        return cVar != null && cVar.a(context, i3, drawable);
    }
}
