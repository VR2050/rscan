package androidx.appcompat.widget;

import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import android.widget.CompoundButton;
import e.AbstractC0510a;

/* JADX INFO: renamed from: androidx.appcompat.widget.j, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
class C0236j {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final CompoundButton f4087a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private ColorStateList f4088b = null;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private PorterDuff.Mode f4089c = null;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private boolean f4090d = false;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private boolean f4091e = false;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private boolean f4092f;

    C0236j(CompoundButton compoundButton) {
        this.f4087a = compoundButton;
    }

    void a() {
        Drawable drawableA = androidx.core.widget.c.a(this.f4087a);
        if (drawableA != null) {
            if (this.f4090d || this.f4091e) {
                Drawable drawableMutate = androidx.core.graphics.drawable.a.j(drawableA).mutate();
                if (this.f4090d) {
                    androidx.core.graphics.drawable.a.g(drawableMutate, this.f4088b);
                }
                if (this.f4091e) {
                    androidx.core.graphics.drawable.a.h(drawableMutate, this.f4089c);
                }
                if (drawableMutate.isStateful()) {
                    drawableMutate.setState(this.f4087a.getDrawableState());
                }
                this.f4087a.setButtonDrawable(drawableMutate);
            }
        }
    }

    ColorStateList b() {
        return this.f4088b;
    }

    PorterDuff.Mode c() {
        return this.f4089c;
    }

    void d(AttributeSet attributeSet, int i3) {
        int iM;
        int iM2;
        g0 g0VarU = g0.u(this.f4087a.getContext(), attributeSet, d.j.f9025U0, i3, 0);
        CompoundButton compoundButton = this.f4087a;
        androidx.core.view.V.V(compoundButton, compoundButton.getContext(), d.j.f9025U0, attributeSet, g0VarU.q(), i3, 0);
        try {
            if (g0VarU.r(d.j.f9031W0) && (iM2 = g0VarU.m(d.j.f9031W0, 0)) != 0) {
                try {
                    CompoundButton compoundButton2 = this.f4087a;
                    compoundButton2.setButtonDrawable(AbstractC0510a.b(compoundButton2.getContext(), iM2));
                } catch (Resources.NotFoundException unused) {
                    if (g0VarU.r(d.j.f9028V0)) {
                        CompoundButton compoundButton3 = this.f4087a;
                        compoundButton3.setButtonDrawable(AbstractC0510a.b(compoundButton3.getContext(), iM));
                    }
                }
            } else if (g0VarU.r(d.j.f9028V0) && (iM = g0VarU.m(d.j.f9028V0, 0)) != 0) {
                CompoundButton compoundButton32 = this.f4087a;
                compoundButton32.setButtonDrawable(AbstractC0510a.b(compoundButton32.getContext(), iM));
            }
            if (g0VarU.r(d.j.f9034X0)) {
                androidx.core.widget.c.b(this.f4087a, g0VarU.c(d.j.f9034X0));
            }
            if (g0VarU.r(d.j.f9037Y0)) {
                androidx.core.widget.c.c(this.f4087a, O.d(g0VarU.j(d.j.f9037Y0, -1), null));
            }
        } finally {
            g0VarU.w();
        }
    }

    void e() {
        if (this.f4092f) {
            this.f4092f = false;
        } else {
            this.f4092f = true;
            a();
        }
    }

    void f(ColorStateList colorStateList) {
        this.f4088b = colorStateList;
        this.f4090d = true;
        a();
    }

    void g(PorterDuff.Mode mode) {
        this.f4089c = mode;
        this.f4091e = true;
        a();
    }
}
