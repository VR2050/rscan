package androidx.appcompat.widget;

import android.content.res.ColorStateList;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.RippleDrawable;
import android.util.AttributeSet;
import android.widget.ImageView;
import e.AbstractC0510a;

/* JADX INFO: renamed from: androidx.appcompat.widget.q, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0243q {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final ImageView f4160a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private e0 f4161b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private e0 f4162c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private e0 f4163d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private int f4164e = 0;

    public C0243q(ImageView imageView) {
        this.f4160a = imageView;
    }

    private boolean a(Drawable drawable) {
        if (this.f4163d == null) {
            this.f4163d = new e0();
        }
        e0 e0Var = this.f4163d;
        e0Var.a();
        ColorStateList colorStateListA = androidx.core.widget.e.a(this.f4160a);
        if (colorStateListA != null) {
            e0Var.f4063d = true;
            e0Var.f4060a = colorStateListA;
        }
        PorterDuff.Mode modeB = androidx.core.widget.e.b(this.f4160a);
        if (modeB != null) {
            e0Var.f4062c = true;
            e0Var.f4061b = modeB;
        }
        if (!e0Var.f4063d && !e0Var.f4062c) {
            return false;
        }
        C0237k.i(drawable, e0Var, this.f4160a.getDrawableState());
        return true;
    }

    private boolean l() {
        return this.f4161b != null;
    }

    void b() {
        if (this.f4160a.getDrawable() != null) {
            this.f4160a.getDrawable().setLevel(this.f4164e);
        }
    }

    void c() {
        Drawable drawable = this.f4160a.getDrawable();
        if (drawable != null) {
            O.a(drawable);
        }
        if (drawable != null) {
            if (l() && a(drawable)) {
                return;
            }
            e0 e0Var = this.f4162c;
            if (e0Var != null) {
                C0237k.i(drawable, e0Var, this.f4160a.getDrawableState());
                return;
            }
            e0 e0Var2 = this.f4161b;
            if (e0Var2 != null) {
                C0237k.i(drawable, e0Var2, this.f4160a.getDrawableState());
            }
        }
    }

    ColorStateList d() {
        e0 e0Var = this.f4162c;
        if (e0Var != null) {
            return e0Var.f4060a;
        }
        return null;
    }

    PorterDuff.Mode e() {
        e0 e0Var = this.f4162c;
        if (e0Var != null) {
            return e0Var.f4061b;
        }
        return null;
    }

    boolean f() {
        return !(this.f4160a.getBackground() instanceof RippleDrawable);
    }

    public void g(AttributeSet attributeSet, int i3) {
        int iM;
        g0 g0VarU = g0.u(this.f4160a.getContext(), attributeSet, d.j.f9005P, i3, 0);
        ImageView imageView = this.f4160a;
        androidx.core.view.V.V(imageView, imageView.getContext(), d.j.f9005P, attributeSet, g0VarU.q(), i3, 0);
        try {
            Drawable drawable = this.f4160a.getDrawable();
            if (drawable == null && (iM = g0VarU.m(d.j.f9009Q, -1)) != -1 && (drawable = AbstractC0510a.b(this.f4160a.getContext(), iM)) != null) {
                this.f4160a.setImageDrawable(drawable);
            }
            if (drawable != null) {
                O.a(drawable);
            }
            if (g0VarU.r(d.j.f9013R)) {
                androidx.core.widget.e.c(this.f4160a, g0VarU.c(d.j.f9013R));
            }
            if (g0VarU.r(d.j.f9017S)) {
                androidx.core.widget.e.d(this.f4160a, O.d(g0VarU.j(d.j.f9017S, -1), null));
            }
            g0VarU.w();
        } catch (Throwable th) {
            g0VarU.w();
            throw th;
        }
    }

    void h(Drawable drawable) {
        this.f4164e = drawable.getLevel();
    }

    public void i(int i3) {
        if (i3 != 0) {
            Drawable drawableB = AbstractC0510a.b(this.f4160a.getContext(), i3);
            if (drawableB != null) {
                O.a(drawableB);
            }
            this.f4160a.setImageDrawable(drawableB);
        } else {
            this.f4160a.setImageDrawable(null);
        }
        c();
    }

    void j(ColorStateList colorStateList) {
        if (this.f4162c == null) {
            this.f4162c = new e0();
        }
        e0 e0Var = this.f4162c;
        e0Var.f4060a = colorStateList;
        e0Var.f4063d = true;
        c();
    }

    void k(PorterDuff.Mode mode) {
        if (this.f4162c == null) {
            this.f4162c = new e0();
        }
        e0 e0Var = this.f4162c;
        e0Var.f4061b = mode;
        e0Var.f4062c = true;
        c();
    }
}
