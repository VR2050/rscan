package androidx.appcompat.widget;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.text.InputFilter;
import android.util.AttributeSet;
import android.widget.RadioButton;
import d.AbstractC0502a;
import e.AbstractC0510a;

/* JADX INFO: renamed from: androidx.appcompat.widget.v, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0247v extends RadioButton {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final C0236j f4182b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final C0231e f4183c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final C f4184d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private C0240n f4185e;

    public C0247v(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, AbstractC0502a.f8782C);
    }

    private C0240n getEmojiTextViewHelper() {
        if (this.f4185e == null) {
            this.f4185e = new C0240n(this);
        }
        return this.f4185e;
    }

    @Override // android.widget.CompoundButton, android.widget.TextView, android.view.View
    protected void drawableStateChanged() {
        super.drawableStateChanged();
        C0231e c0231e = this.f4183c;
        if (c0231e != null) {
            c0231e.b();
        }
        C c3 = this.f4184d;
        if (c3 != null) {
            c3.b();
        }
    }

    public ColorStateList getSupportBackgroundTintList() {
        C0231e c0231e = this.f4183c;
        if (c0231e != null) {
            return c0231e.c();
        }
        return null;
    }

    public PorterDuff.Mode getSupportBackgroundTintMode() {
        C0231e c0231e = this.f4183c;
        if (c0231e != null) {
            return c0231e.d();
        }
        return null;
    }

    public ColorStateList getSupportButtonTintList() {
        C0236j c0236j = this.f4182b;
        if (c0236j != null) {
            return c0236j.b();
        }
        return null;
    }

    public PorterDuff.Mode getSupportButtonTintMode() {
        C0236j c0236j = this.f4182b;
        if (c0236j != null) {
            return c0236j.c();
        }
        return null;
    }

    public ColorStateList getSupportCompoundDrawablesTintList() {
        return this.f4184d.j();
    }

    public PorterDuff.Mode getSupportCompoundDrawablesTintMode() {
        return this.f4184d.k();
    }

    @Override // android.widget.TextView
    public void setAllCaps(boolean z3) {
        super.setAllCaps(z3);
        getEmojiTextViewHelper().d(z3);
    }

    @Override // android.view.View
    public void setBackgroundDrawable(Drawable drawable) {
        super.setBackgroundDrawable(drawable);
        C0231e c0231e = this.f4183c;
        if (c0231e != null) {
            c0231e.f(drawable);
        }
    }

    @Override // android.view.View
    public void setBackgroundResource(int i3) {
        super.setBackgroundResource(i3);
        C0231e c0231e = this.f4183c;
        if (c0231e != null) {
            c0231e.g(i3);
        }
    }

    @Override // android.widget.CompoundButton
    public void setButtonDrawable(Drawable drawable) {
        super.setButtonDrawable(drawable);
        C0236j c0236j = this.f4182b;
        if (c0236j != null) {
            c0236j.e();
        }
    }

    @Override // android.widget.TextView
    public void setCompoundDrawables(Drawable drawable, Drawable drawable2, Drawable drawable3, Drawable drawable4) {
        super.setCompoundDrawables(drawable, drawable2, drawable3, drawable4);
        C c3 = this.f4184d;
        if (c3 != null) {
            c3.p();
        }
    }

    @Override // android.widget.TextView
    public void setCompoundDrawablesRelative(Drawable drawable, Drawable drawable2, Drawable drawable3, Drawable drawable4) {
        super.setCompoundDrawablesRelative(drawable, drawable2, drawable3, drawable4);
        C c3 = this.f4184d;
        if (c3 != null) {
            c3.p();
        }
    }

    public void setEmojiCompatEnabled(boolean z3) {
        getEmojiTextViewHelper().e(z3);
    }

    @Override // android.widget.TextView
    public void setFilters(InputFilter[] inputFilterArr) {
        super.setFilters(getEmojiTextViewHelper().a(inputFilterArr));
    }

    public void setSupportBackgroundTintList(ColorStateList colorStateList) {
        C0231e c0231e = this.f4183c;
        if (c0231e != null) {
            c0231e.i(colorStateList);
        }
    }

    public void setSupportBackgroundTintMode(PorterDuff.Mode mode) {
        C0231e c0231e = this.f4183c;
        if (c0231e != null) {
            c0231e.j(mode);
        }
    }

    public void setSupportButtonTintList(ColorStateList colorStateList) {
        C0236j c0236j = this.f4182b;
        if (c0236j != null) {
            c0236j.f(colorStateList);
        }
    }

    public void setSupportButtonTintMode(PorterDuff.Mode mode) {
        C0236j c0236j = this.f4182b;
        if (c0236j != null) {
            c0236j.g(mode);
        }
    }

    public void setSupportCompoundDrawablesTintList(ColorStateList colorStateList) {
        this.f4184d.w(colorStateList);
        this.f4184d.b();
    }

    public void setSupportCompoundDrawablesTintMode(PorterDuff.Mode mode) {
        this.f4184d.x(mode);
        this.f4184d.b();
    }

    public C0247v(Context context, AttributeSet attributeSet, int i3) {
        super(d0.b(context), attributeSet, i3);
        c0.a(this, getContext());
        C0236j c0236j = new C0236j(this);
        this.f4182b = c0236j;
        c0236j.d(attributeSet, i3);
        C0231e c0231e = new C0231e(this);
        this.f4183c = c0231e;
        c0231e.e(attributeSet, i3);
        C c3 = new C(this);
        this.f4184d = c3;
        c3.m(attributeSet, i3);
        getEmojiTextViewHelper().c(attributeSet, i3);
    }

    @Override // android.widget.CompoundButton
    public void setButtonDrawable(int i3) {
        setButtonDrawable(AbstractC0510a.b(getContext(), i3));
    }
}
