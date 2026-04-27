package androidx.appcompat.widget;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import android.view.ActionMode;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputConnection;
import android.widget.CheckedTextView;
import d.AbstractC0502a;
import e.AbstractC0510a;

/* JADX INFO: renamed from: androidx.appcompat.widget.h, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0234h extends CheckedTextView {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final C0235i f4075b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final C0231e f4076c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final C f4077d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private C0240n f4078e;

    public C0234h(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, AbstractC0502a.f8804p);
    }

    private C0240n getEmojiTextViewHelper() {
        if (this.f4078e == null) {
            this.f4078e = new C0240n(this);
        }
        return this.f4078e;
    }

    @Override // android.widget.CheckedTextView, android.widget.TextView, android.view.View
    protected void drawableStateChanged() {
        super.drawableStateChanged();
        C c3 = this.f4077d;
        if (c3 != null) {
            c3.b();
        }
        C0231e c0231e = this.f4076c;
        if (c0231e != null) {
            c0231e.b();
        }
        C0235i c0235i = this.f4075b;
        if (c0235i != null) {
            c0235i.a();
        }
    }

    @Override // android.widget.TextView
    public ActionMode.Callback getCustomSelectionActionModeCallback() {
        return androidx.core.widget.i.n(super.getCustomSelectionActionModeCallback());
    }

    public ColorStateList getSupportBackgroundTintList() {
        C0231e c0231e = this.f4076c;
        if (c0231e != null) {
            return c0231e.c();
        }
        return null;
    }

    public PorterDuff.Mode getSupportBackgroundTintMode() {
        C0231e c0231e = this.f4076c;
        if (c0231e != null) {
            return c0231e.d();
        }
        return null;
    }

    public ColorStateList getSupportCheckMarkTintList() {
        C0235i c0235i = this.f4075b;
        if (c0235i != null) {
            return c0235i.b();
        }
        return null;
    }

    public PorterDuff.Mode getSupportCheckMarkTintMode() {
        C0235i c0235i = this.f4075b;
        if (c0235i != null) {
            return c0235i.c();
        }
        return null;
    }

    public ColorStateList getSupportCompoundDrawablesTintList() {
        return this.f4077d.j();
    }

    public PorterDuff.Mode getSupportCompoundDrawablesTintMode() {
        return this.f4077d.k();
    }

    @Override // android.widget.TextView, android.view.View
    public InputConnection onCreateInputConnection(EditorInfo editorInfo) {
        return AbstractC0241o.a(super.onCreateInputConnection(editorInfo), editorInfo, this);
    }

    @Override // android.widget.TextView
    public void setAllCaps(boolean z3) {
        super.setAllCaps(z3);
        getEmojiTextViewHelper().d(z3);
    }

    @Override // android.view.View
    public void setBackgroundDrawable(Drawable drawable) {
        super.setBackgroundDrawable(drawable);
        C0231e c0231e = this.f4076c;
        if (c0231e != null) {
            c0231e.f(drawable);
        }
    }

    @Override // android.view.View
    public void setBackgroundResource(int i3) {
        super.setBackgroundResource(i3);
        C0231e c0231e = this.f4076c;
        if (c0231e != null) {
            c0231e.g(i3);
        }
    }

    @Override // android.widget.CheckedTextView
    public void setCheckMarkDrawable(Drawable drawable) {
        super.setCheckMarkDrawable(drawable);
        C0235i c0235i = this.f4075b;
        if (c0235i != null) {
            c0235i.e();
        }
    }

    @Override // android.widget.TextView
    public void setCompoundDrawables(Drawable drawable, Drawable drawable2, Drawable drawable3, Drawable drawable4) {
        super.setCompoundDrawables(drawable, drawable2, drawable3, drawable4);
        C c3 = this.f4077d;
        if (c3 != null) {
            c3.p();
        }
    }

    @Override // android.widget.TextView
    public void setCompoundDrawablesRelative(Drawable drawable, Drawable drawable2, Drawable drawable3, Drawable drawable4) {
        super.setCompoundDrawablesRelative(drawable, drawable2, drawable3, drawable4);
        C c3 = this.f4077d;
        if (c3 != null) {
            c3.p();
        }
    }

    @Override // android.widget.TextView
    public void setCustomSelectionActionModeCallback(ActionMode.Callback callback) {
        super.setCustomSelectionActionModeCallback(androidx.core.widget.i.o(this, callback));
    }

    public void setEmojiCompatEnabled(boolean z3) {
        getEmojiTextViewHelper().e(z3);
    }

    public void setSupportBackgroundTintList(ColorStateList colorStateList) {
        C0231e c0231e = this.f4076c;
        if (c0231e != null) {
            c0231e.i(colorStateList);
        }
    }

    public void setSupportBackgroundTintMode(PorterDuff.Mode mode) {
        C0231e c0231e = this.f4076c;
        if (c0231e != null) {
            c0231e.j(mode);
        }
    }

    public void setSupportCheckMarkTintList(ColorStateList colorStateList) {
        C0235i c0235i = this.f4075b;
        if (c0235i != null) {
            c0235i.f(colorStateList);
        }
    }

    public void setSupportCheckMarkTintMode(PorterDuff.Mode mode) {
        C0235i c0235i = this.f4075b;
        if (c0235i != null) {
            c0235i.g(mode);
        }
    }

    public void setSupportCompoundDrawablesTintList(ColorStateList colorStateList) {
        this.f4077d.w(colorStateList);
        this.f4077d.b();
    }

    public void setSupportCompoundDrawablesTintMode(PorterDuff.Mode mode) {
        this.f4077d.x(mode);
        this.f4077d.b();
    }

    @Override // android.widget.TextView
    public void setTextAppearance(Context context, int i3) {
        super.setTextAppearance(context, i3);
        C c3 = this.f4077d;
        if (c3 != null) {
            c3.q(context, i3);
        }
    }

    public C0234h(Context context, AttributeSet attributeSet, int i3) {
        super(d0.b(context), attributeSet, i3);
        c0.a(this, getContext());
        C c3 = new C(this);
        this.f4077d = c3;
        c3.m(attributeSet, i3);
        c3.b();
        C0231e c0231e = new C0231e(this);
        this.f4076c = c0231e;
        c0231e.e(attributeSet, i3);
        C0235i c0235i = new C0235i(this);
        this.f4075b = c0235i;
        c0235i.d(attributeSet, i3);
        getEmojiTextViewHelper().c(attributeSet, i3);
    }

    @Override // android.widget.CheckedTextView
    public void setCheckMarkDrawable(int i3) {
        setCheckMarkDrawable(AbstractC0510a.b(getContext(), i3));
    }
}
