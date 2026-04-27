package androidx.appcompat.widget;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.graphics.PorterDuff;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.os.LocaleList;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputConnection;
import android.widget.TextView;
import androidx.core.content.res.f;
import java.lang.ref.WeakReference;
import u.AbstractC0701c;

/* JADX INFO: loaded from: classes.dex */
class C {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final TextView f3707a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private e0 f3708b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private e0 f3709c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private e0 f3710d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private e0 f3711e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private e0 f3712f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private e0 f3713g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private e0 f3714h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private final E f3715i;

    /* JADX INFO: renamed from: j, reason: collision with root package name */
    private int f3716j = 0;

    /* JADX INFO: renamed from: k, reason: collision with root package name */
    private int f3717k = -1;

    /* JADX INFO: renamed from: l, reason: collision with root package name */
    private Typeface f3718l;

    /* JADX INFO: renamed from: m, reason: collision with root package name */
    private boolean f3719m;

    class a extends f.e {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ int f3720a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ int f3721b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ WeakReference f3722c;

        a(int i3, int i4, WeakReference weakReference) {
            this.f3720a = i3;
            this.f3721b = i4;
            this.f3722c = weakReference;
        }

        @Override // androidx.core.content.res.f.e
        /* JADX INFO: renamed from: h */
        public void f(int i3) {
        }

        @Override // androidx.core.content.res.f.e
        /* JADX INFO: renamed from: i */
        public void g(Typeface typeface) {
            int i3;
            if (Build.VERSION.SDK_INT >= 28 && (i3 = this.f3720a) != -1) {
                typeface = e.a(typeface, i3, (this.f3721b & 2) != 0);
            }
            C.this.n(this.f3722c, typeface);
        }
    }

    class b implements Runnable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        final /* synthetic */ TextView f3724b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        final /* synthetic */ Typeface f3725c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        final /* synthetic */ int f3726d;

        b(TextView textView, Typeface typeface, int i3) {
            this.f3724b = textView;
            this.f3725c = typeface;
            this.f3726d = i3;
        }

        @Override // java.lang.Runnable
        public void run() {
            this.f3724b.setTypeface(this.f3725c, this.f3726d);
        }
    }

    static class c {
        static LocaleList a(String str) {
            return LocaleList.forLanguageTags(str);
        }

        static void b(TextView textView, LocaleList localeList) {
            textView.setTextLocales(localeList);
        }
    }

    static class d {
        static int a(TextView textView) {
            return textView.getAutoSizeStepGranularity();
        }

        static void b(TextView textView, int i3, int i4, int i5, int i6) {
            textView.setAutoSizeTextTypeUniformWithConfiguration(i3, i4, i5, i6);
        }

        static void c(TextView textView, int[] iArr, int i3) {
            textView.setAutoSizeTextTypeUniformWithPresetSizes(iArr, i3);
        }

        static boolean d(TextView textView, String str) {
            return textView.setFontVariationSettings(str);
        }
    }

    static class e {
        static Typeface a(Typeface typeface, int i3, boolean z3) {
            return Typeface.create(typeface, i3, z3);
        }
    }

    C(TextView textView) {
        this.f3707a = textView;
        this.f3715i = new E(textView);
    }

    private void B(int i3, float f3) {
        this.f3715i.t(i3, f3);
    }

    private void C(Context context, g0 g0Var) {
        String strN;
        this.f3716j = g0Var.j(d.j.f8964E2, this.f3716j);
        int i3 = Build.VERSION.SDK_INT;
        if (i3 >= 28) {
            int iJ = g0Var.j(d.j.f8976H2, -1);
            this.f3717k = iJ;
            if (iJ != -1) {
                this.f3716j &= 2;
            }
        }
        if (!g0Var.r(d.j.f8972G2) && !g0Var.r(d.j.f8980I2)) {
            if (g0Var.r(d.j.f8960D2)) {
                this.f3719m = false;
                int iJ2 = g0Var.j(d.j.f8960D2, 1);
                if (iJ2 == 1) {
                    this.f3718l = Typeface.SANS_SERIF;
                    return;
                } else if (iJ2 == 2) {
                    this.f3718l = Typeface.SERIF;
                    return;
                } else {
                    if (iJ2 != 3) {
                        return;
                    }
                    this.f3718l = Typeface.MONOSPACE;
                    return;
                }
            }
            return;
        }
        this.f3718l = null;
        int i4 = g0Var.r(d.j.f8980I2) ? d.j.f8980I2 : d.j.f8972G2;
        int i5 = this.f3717k;
        int i6 = this.f3716j;
        if (!context.isRestricted()) {
            try {
                Typeface typefaceI = g0Var.i(i4, this.f3716j, new a(i5, i6, new WeakReference(this.f3707a)));
                if (typefaceI != null) {
                    if (i3 < 28 || this.f3717k == -1) {
                        this.f3718l = typefaceI;
                    } else {
                        this.f3718l = e.a(Typeface.create(typefaceI, 0), this.f3717k, (this.f3716j & 2) != 0);
                    }
                }
                this.f3719m = this.f3718l == null;
            } catch (Resources.NotFoundException | UnsupportedOperationException unused) {
            }
        }
        if (this.f3718l != null || (strN = g0Var.n(i4)) == null) {
            return;
        }
        if (Build.VERSION.SDK_INT < 28 || this.f3717k == -1) {
            this.f3718l = Typeface.create(strN, this.f3716j);
        } else {
            this.f3718l = e.a(Typeface.create(strN, 0), this.f3717k, (this.f3716j & 2) != 0);
        }
    }

    private void a(Drawable drawable, e0 e0Var) {
        if (drawable == null || e0Var == null) {
            return;
        }
        C0237k.i(drawable, e0Var, this.f3707a.getDrawableState());
    }

    private static e0 d(Context context, C0237k c0237k, int i3) {
        ColorStateList colorStateListF = c0237k.f(context, i3);
        if (colorStateListF == null) {
            return null;
        }
        e0 e0Var = new e0();
        e0Var.f4063d = true;
        e0Var.f4060a = colorStateListF;
        return e0Var;
    }

    private void y(Drawable drawable, Drawable drawable2, Drawable drawable3, Drawable drawable4, Drawable drawable5, Drawable drawable6) {
        if (drawable5 != null || drawable6 != null) {
            Drawable[] compoundDrawablesRelative = this.f3707a.getCompoundDrawablesRelative();
            if (drawable5 == null) {
                drawable5 = compoundDrawablesRelative[0];
            }
            if (drawable2 == null) {
                drawable2 = compoundDrawablesRelative[1];
            }
            if (drawable6 == null) {
                drawable6 = compoundDrawablesRelative[2];
            }
            TextView textView = this.f3707a;
            if (drawable4 == null) {
                drawable4 = compoundDrawablesRelative[3];
            }
            textView.setCompoundDrawablesRelativeWithIntrinsicBounds(drawable5, drawable2, drawable6, drawable4);
            return;
        }
        if (drawable == null && drawable2 == null && drawable3 == null && drawable4 == null) {
            return;
        }
        Drawable[] compoundDrawablesRelative2 = this.f3707a.getCompoundDrawablesRelative();
        Drawable drawable7 = compoundDrawablesRelative2[0];
        if (drawable7 != null || compoundDrawablesRelative2[2] != null) {
            if (drawable2 == null) {
                drawable2 = compoundDrawablesRelative2[1];
            }
            if (drawable4 == null) {
                drawable4 = compoundDrawablesRelative2[3];
            }
            this.f3707a.setCompoundDrawablesRelativeWithIntrinsicBounds(drawable7, drawable2, compoundDrawablesRelative2[2], drawable4);
            return;
        }
        Drawable[] compoundDrawables = this.f3707a.getCompoundDrawables();
        TextView textView2 = this.f3707a;
        if (drawable == null) {
            drawable = compoundDrawables[0];
        }
        if (drawable2 == null) {
            drawable2 = compoundDrawables[1];
        }
        if (drawable3 == null) {
            drawable3 = compoundDrawables[2];
        }
        if (drawable4 == null) {
            drawable4 = compoundDrawables[3];
        }
        textView2.setCompoundDrawablesWithIntrinsicBounds(drawable, drawable2, drawable3, drawable4);
    }

    private void z() {
        e0 e0Var = this.f3714h;
        this.f3708b = e0Var;
        this.f3709c = e0Var;
        this.f3710d = e0Var;
        this.f3711e = e0Var;
        this.f3712f = e0Var;
        this.f3713g = e0Var;
    }

    void A(int i3, float f3) {
        if (r0.f4172c || l()) {
            return;
        }
        B(i3, f3);
    }

    void b() {
        if (this.f3708b != null || this.f3709c != null || this.f3710d != null || this.f3711e != null) {
            Drawable[] compoundDrawables = this.f3707a.getCompoundDrawables();
            a(compoundDrawables[0], this.f3708b);
            a(compoundDrawables[1], this.f3709c);
            a(compoundDrawables[2], this.f3710d);
            a(compoundDrawables[3], this.f3711e);
        }
        if (this.f3712f == null && this.f3713g == null) {
            return;
        }
        Drawable[] compoundDrawablesRelative = this.f3707a.getCompoundDrawablesRelative();
        a(compoundDrawablesRelative[0], this.f3712f);
        a(compoundDrawablesRelative[2], this.f3713g);
    }

    void c() {
        this.f3715i.a();
    }

    int e() {
        return this.f3715i.f();
    }

    int f() {
        return this.f3715i.g();
    }

    int g() {
        return this.f3715i.h();
    }

    int[] h() {
        return this.f3715i.i();
    }

    int i() {
        return this.f3715i.j();
    }

    ColorStateList j() {
        e0 e0Var = this.f3714h;
        if (e0Var != null) {
            return e0Var.f4060a;
        }
        return null;
    }

    PorterDuff.Mode k() {
        e0 e0Var = this.f3714h;
        if (e0Var != null) {
            return e0Var.f4061b;
        }
        return null;
    }

    boolean l() {
        return this.f3715i.n();
    }

    /* JADX WARN: Removed duplicated region for block: B:125:0x029b  */
    /* JADX WARN: Removed duplicated region for block: B:127:0x02a2  */
    /* JADX WARN: Removed duplicated region for block: B:130:0x02ab  */
    /* JADX WARN: Removed duplicated region for block: B:134:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    void m(android.util.AttributeSet r17, int r18) {
        /*
            Method dump skipped, instruction units count: 698
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.widget.C.m(android.util.AttributeSet, int):void");
    }

    void n(WeakReference weakReference, Typeface typeface) {
        if (this.f3719m) {
            this.f3718l = typeface;
            TextView textView = (TextView) weakReference.get();
            if (textView != null) {
                if (textView.isAttachedToWindow()) {
                    textView.post(new b(textView, typeface, this.f3716j));
                } else {
                    textView.setTypeface(typeface, this.f3716j);
                }
            }
        }
    }

    void o(boolean z3, int i3, int i4, int i5, int i6) {
        if (r0.f4172c) {
            return;
        }
        c();
    }

    void p() {
        b();
    }

    void q(Context context, int i3) {
        String strN;
        g0 g0VarS = g0.s(context, i3, d.j.f8952B2);
        if (g0VarS.r(d.j.f8988K2)) {
            s(g0VarS.a(d.j.f8988K2, false));
        }
        int i4 = Build.VERSION.SDK_INT;
        if (g0VarS.r(d.j.f8956C2) && g0VarS.e(d.j.f8956C2, -1) == 0) {
            this.f3707a.setTextSize(0, 0.0f);
        }
        C(context, g0VarS);
        if (i4 >= 26 && g0VarS.r(d.j.f8984J2) && (strN = g0VarS.n(d.j.f8984J2)) != null) {
            d.d(this.f3707a, strN);
        }
        g0VarS.w();
        Typeface typeface = this.f3718l;
        if (typeface != null) {
            this.f3707a.setTypeface(typeface, this.f3716j);
        }
    }

    void r(TextView textView, InputConnection inputConnection, EditorInfo editorInfo) {
        if (Build.VERSION.SDK_INT >= 30 || inputConnection == null) {
            return;
        }
        AbstractC0701c.f(editorInfo, textView.getText());
    }

    void s(boolean z3) {
        this.f3707a.setAllCaps(z3);
    }

    void t(int i3, int i4, int i5, int i6) {
        this.f3715i.p(i3, i4, i5, i6);
    }

    void u(int[] iArr, int i3) {
        this.f3715i.q(iArr, i3);
    }

    void v(int i3) {
        this.f3715i.r(i3);
    }

    void w(ColorStateList colorStateList) {
        if (this.f3714h == null) {
            this.f3714h = new e0();
        }
        e0 e0Var = this.f3714h;
        e0Var.f4060a = colorStateList;
        e0Var.f4063d = colorStateList != null;
        z();
    }

    void x(PorterDuff.Mode mode) {
        if (this.f3714h == null) {
            this.f3714h = new e0();
        }
        e0 e0Var = this.f3714h;
        e0Var.f4061b = mode;
        e0Var.f4062c = mode != null;
        z();
    }
}
