package androidx.appcompat.widget;

import android.content.res.ColorStateList;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import android.view.View;

/* JADX INFO: renamed from: androidx.appcompat.widget.e, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
class C0231e {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final View f4054a;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private e0 f4057d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private e0 f4058e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private e0 f4059f;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private int f4056c = -1;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final C0237k f4055b = C0237k.b();

    C0231e(View view) {
        this.f4054a = view;
    }

    private boolean a(Drawable drawable) {
        if (this.f4059f == null) {
            this.f4059f = new e0();
        }
        e0 e0Var = this.f4059f;
        e0Var.a();
        ColorStateList colorStateListM = androidx.core.view.V.m(this.f4054a);
        if (colorStateListM != null) {
            e0Var.f4063d = true;
            e0Var.f4060a = colorStateListM;
        }
        PorterDuff.Mode modeN = androidx.core.view.V.n(this.f4054a);
        if (modeN != null) {
            e0Var.f4062c = true;
            e0Var.f4061b = modeN;
        }
        if (!e0Var.f4063d && !e0Var.f4062c) {
            return false;
        }
        C0237k.i(drawable, e0Var, this.f4054a.getDrawableState());
        return true;
    }

    private boolean k() {
        return this.f4057d != null;
    }

    void b() {
        Drawable background = this.f4054a.getBackground();
        if (background != null) {
            if (k() && a(background)) {
                return;
            }
            e0 e0Var = this.f4058e;
            if (e0Var != null) {
                C0237k.i(background, e0Var, this.f4054a.getDrawableState());
                return;
            }
            e0 e0Var2 = this.f4057d;
            if (e0Var2 != null) {
                C0237k.i(background, e0Var2, this.f4054a.getDrawableState());
            }
        }
    }

    ColorStateList c() {
        e0 e0Var = this.f4058e;
        if (e0Var != null) {
            return e0Var.f4060a;
        }
        return null;
    }

    PorterDuff.Mode d() {
        e0 e0Var = this.f4058e;
        if (e0Var != null) {
            return e0Var.f4061b;
        }
        return null;
    }

    void e(AttributeSet attributeSet, int i3) {
        g0 g0VarU = g0.u(this.f4054a.getContext(), attributeSet, d.j.t3, i3, 0);
        View view = this.f4054a;
        androidx.core.view.V.V(view, view.getContext(), d.j.t3, attributeSet, g0VarU.q(), i3, 0);
        try {
            if (g0VarU.r(d.j.u3)) {
                this.f4056c = g0VarU.m(d.j.u3, -1);
                ColorStateList colorStateListF = this.f4055b.f(this.f4054a.getContext(), this.f4056c);
                if (colorStateListF != null) {
                    h(colorStateListF);
                }
            }
            if (g0VarU.r(d.j.v3)) {
                androidx.core.view.V.c0(this.f4054a, g0VarU.c(d.j.v3));
            }
            if (g0VarU.r(d.j.w3)) {
                androidx.core.view.V.d0(this.f4054a, O.d(g0VarU.j(d.j.w3, -1), null));
            }
            g0VarU.w();
        } catch (Throwable th) {
            g0VarU.w();
            throw th;
        }
    }

    void f(Drawable drawable) {
        this.f4056c = -1;
        h(null);
        b();
    }

    void g(int i3) {
        this.f4056c = i3;
        C0237k c0237k = this.f4055b;
        h(c0237k != null ? c0237k.f(this.f4054a.getContext(), i3) : null);
        b();
    }

    void h(ColorStateList colorStateList) {
        if (colorStateList != null) {
            if (this.f4057d == null) {
                this.f4057d = new e0();
            }
            e0 e0Var = this.f4057d;
            e0Var.f4060a = colorStateList;
            e0Var.f4063d = true;
        } else {
            this.f4057d = null;
        }
        b();
    }

    void i(ColorStateList colorStateList) {
        if (this.f4058e == null) {
            this.f4058e = new e0();
        }
        e0 e0Var = this.f4058e;
        e0Var.f4060a = colorStateList;
        e0Var.f4063d = true;
        b();
    }

    void j(PorterDuff.Mode mode) {
        if (this.f4058e == null) {
            this.f4058e = new e0();
        }
        e0 e0Var = this.f4058e;
        e0Var.f4061b = mode;
        e0Var.f4062c = true;
        b();
    }
}
