package androidx.appcompat.widget;

import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import android.widget.CheckedTextView;
import e.AbstractC0510a;

/* JADX INFO: renamed from: androidx.appcompat.widget.i, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
class C0235i {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final CheckedTextView f4080a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private ColorStateList f4081b = null;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private PorterDuff.Mode f4082c = null;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private boolean f4083d = false;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private boolean f4084e = false;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private boolean f4085f;

    C0235i(CheckedTextView checkedTextView) {
        this.f4080a = checkedTextView;
    }

    void a() {
        Drawable drawableA = androidx.core.widget.b.a(this.f4080a);
        if (drawableA != null) {
            if (this.f4083d || this.f4084e) {
                Drawable drawableMutate = androidx.core.graphics.drawable.a.j(drawableA).mutate();
                if (this.f4083d) {
                    androidx.core.graphics.drawable.a.g(drawableMutate, this.f4081b);
                }
                if (this.f4084e) {
                    androidx.core.graphics.drawable.a.h(drawableMutate, this.f4082c);
                }
                if (drawableMutate.isStateful()) {
                    drawableMutate.setState(this.f4080a.getDrawableState());
                }
                this.f4080a.setCheckMarkDrawable(drawableMutate);
            }
        }
    }

    ColorStateList b() {
        return this.f4081b;
    }

    PorterDuff.Mode c() {
        return this.f4082c;
    }

    void d(AttributeSet attributeSet, int i3) {
        int iM;
        int iM2;
        g0 g0VarU = g0.u(this.f4080a.getContext(), attributeSet, d.j.f9006P0, i3, 0);
        CheckedTextView checkedTextView = this.f4080a;
        androidx.core.view.V.V(checkedTextView, checkedTextView.getContext(), d.j.f9006P0, attributeSet, g0VarU.q(), i3, 0);
        try {
            if (g0VarU.r(d.j.f9014R0) && (iM2 = g0VarU.m(d.j.f9014R0, 0)) != 0) {
                try {
                    CheckedTextView checkedTextView2 = this.f4080a;
                    checkedTextView2.setCheckMarkDrawable(AbstractC0510a.b(checkedTextView2.getContext(), iM2));
                } catch (Resources.NotFoundException unused) {
                    if (g0VarU.r(d.j.f9010Q0)) {
                        CheckedTextView checkedTextView3 = this.f4080a;
                        checkedTextView3.setCheckMarkDrawable(AbstractC0510a.b(checkedTextView3.getContext(), iM));
                    }
                }
            } else if (g0VarU.r(d.j.f9010Q0) && (iM = g0VarU.m(d.j.f9010Q0, 0)) != 0) {
                CheckedTextView checkedTextView32 = this.f4080a;
                checkedTextView32.setCheckMarkDrawable(AbstractC0510a.b(checkedTextView32.getContext(), iM));
            }
            if (g0VarU.r(d.j.f9018S0)) {
                androidx.core.widget.b.b(this.f4080a, g0VarU.c(d.j.f9018S0));
            }
            if (g0VarU.r(d.j.f9022T0)) {
                androidx.core.widget.b.c(this.f4080a, O.d(g0VarU.j(d.j.f9022T0, -1), null));
            }
        } finally {
            g0VarU.w();
        }
    }

    void e() {
        if (this.f4085f) {
            this.f4085f = false;
        } else {
            this.f4085f = true;
            a();
        }
    }

    void f(ColorStateList colorStateList) {
        this.f4081b = colorStateList;
        this.f4083d = true;
        a();
    }

    void g(PorterDuff.Mode mode) {
        this.f4082c = mode;
        this.f4084e = true;
        a();
    }
}
