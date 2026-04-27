package androidx.appcompat.widget;

import android.content.res.ColorStateList;
import android.graphics.Canvas;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import android.widget.SeekBar;

/* JADX INFO: renamed from: androidx.appcompat.widget.z, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
class C0251z extends C0246u {

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final SeekBar f4188d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private Drawable f4189e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private ColorStateList f4190f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private PorterDuff.Mode f4191g;

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    private boolean f4192h;

    /* JADX INFO: renamed from: i, reason: collision with root package name */
    private boolean f4193i;

    C0251z(SeekBar seekBar) {
        super(seekBar);
        this.f4190f = null;
        this.f4191g = null;
        this.f4192h = false;
        this.f4193i = false;
        this.f4188d = seekBar;
    }

    private void f() {
        Drawable drawable = this.f4189e;
        if (drawable != null) {
            if (this.f4192h || this.f4193i) {
                Drawable drawableJ = androidx.core.graphics.drawable.a.j(drawable.mutate());
                this.f4189e = drawableJ;
                if (this.f4192h) {
                    androidx.core.graphics.drawable.a.g(drawableJ, this.f4190f);
                }
                if (this.f4193i) {
                    androidx.core.graphics.drawable.a.h(this.f4189e, this.f4191g);
                }
                if (this.f4189e.isStateful()) {
                    this.f4189e.setState(this.f4188d.getDrawableState());
                }
            }
        }
    }

    @Override // androidx.appcompat.widget.C0246u
    void c(AttributeSet attributeSet, int i3) {
        super.c(attributeSet, i3);
        g0 g0VarU = g0.u(this.f4188d.getContext(), attributeSet, d.j.f9021T, i3, 0);
        SeekBar seekBar = this.f4188d;
        androidx.core.view.V.V(seekBar, seekBar.getContext(), d.j.f9021T, attributeSet, g0VarU.q(), i3, 0);
        Drawable drawableG = g0VarU.g(d.j.f9024U);
        if (drawableG != null) {
            this.f4188d.setThumb(drawableG);
        }
        j(g0VarU.f(d.j.f9027V));
        if (g0VarU.r(d.j.f9033X)) {
            this.f4191g = O.d(g0VarU.j(d.j.f9033X, -1), this.f4191g);
            this.f4193i = true;
        }
        if (g0VarU.r(d.j.f9030W)) {
            this.f4190f = g0VarU.c(d.j.f9030W);
            this.f4192h = true;
        }
        g0VarU.w();
        f();
    }

    void g(Canvas canvas) {
        if (this.f4189e != null) {
            int max = this.f4188d.getMax();
            if (max > 1) {
                int intrinsicWidth = this.f4189e.getIntrinsicWidth();
                int intrinsicHeight = this.f4189e.getIntrinsicHeight();
                int i3 = intrinsicWidth >= 0 ? intrinsicWidth / 2 : 1;
                int i4 = intrinsicHeight >= 0 ? intrinsicHeight / 2 : 1;
                this.f4189e.setBounds(-i3, -i4, i3, i4);
                float width = ((this.f4188d.getWidth() - this.f4188d.getPaddingLeft()) - this.f4188d.getPaddingRight()) / max;
                int iSave = canvas.save();
                canvas.translate(this.f4188d.getPaddingLeft(), this.f4188d.getHeight() / 2);
                for (int i5 = 0; i5 <= max; i5++) {
                    this.f4189e.draw(canvas);
                    canvas.translate(width, 0.0f);
                }
                canvas.restoreToCount(iSave);
            }
        }
    }

    void h() {
        Drawable drawable = this.f4189e;
        if (drawable != null && drawable.isStateful() && drawable.setState(this.f4188d.getDrawableState())) {
            this.f4188d.invalidateDrawable(drawable);
        }
    }

    void i() {
        Drawable drawable = this.f4189e;
        if (drawable != null) {
            drawable.jumpToCurrentState();
        }
    }

    void j(Drawable drawable) {
        Drawable drawable2 = this.f4189e;
        if (drawable2 != null) {
            drawable2.setCallback(null);
        }
        this.f4189e = drawable;
        if (drawable != null) {
            drawable.setCallback(this.f4188d);
            androidx.core.graphics.drawable.a.e(drawable, this.f4188d.getLayoutDirection());
            if (drawable.isStateful()) {
                drawable.setState(this.f4188d.getDrawableState());
            }
            f();
        }
        this.f4188d.invalidate();
    }
}
