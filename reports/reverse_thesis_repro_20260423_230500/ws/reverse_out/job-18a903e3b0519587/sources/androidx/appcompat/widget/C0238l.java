package androidx.appcompat.widget;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.text.Editable;
import android.text.method.KeyListener;
import android.util.AttributeSet;
import android.view.ActionMode;
import android.view.DragEvent;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputConnection;
import android.view.inputmethod.InputMethodManager;
import android.view.textclassifier.TextClassifier;
import android.widget.EditText;
import androidx.core.view.C0258d;
import d.AbstractC0502a;
import u.AbstractC0701c;

/* JADX INFO: renamed from: androidx.appcompat.widget.l, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0238l extends EditText implements androidx.core.view.G {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final C0231e f4125b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final C f4126c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final B f4127d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final androidx.core.widget.j f4128e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final C0239m f4129f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private a f4130g;

    /* JADX INFO: renamed from: androidx.appcompat.widget.l$a */
    class a {
        a() {
        }

        public TextClassifier a() {
            return C0238l.super.getTextClassifier();
        }

        public void b(TextClassifier textClassifier) {
            C0238l.super.setTextClassifier(textClassifier);
        }
    }

    public C0238l(Context context) {
        this(context, null);
    }

    private a getSuperCaller() {
        if (this.f4130g == null) {
            this.f4130g = new a();
        }
        return this.f4130g;
    }

    @Override // androidx.core.view.G
    public C0258d a(C0258d c0258d) {
        return this.f4128e.a(this, c0258d);
    }

    void d(C0239m c0239m) {
        KeyListener keyListener = getKeyListener();
        if (c0239m.b(keyListener)) {
            boolean zIsFocusable = super.isFocusable();
            boolean zIsClickable = super.isClickable();
            boolean zIsLongClickable = super.isLongClickable();
            int inputType = super.getInputType();
            KeyListener keyListenerA = c0239m.a(keyListener);
            if (keyListenerA == keyListener) {
                return;
            }
            super.setKeyListener(keyListenerA);
            super.setRawInputType(inputType);
            super.setFocusable(zIsFocusable);
            super.setClickable(zIsClickable);
            super.setLongClickable(zIsLongClickable);
        }
    }

    @Override // android.widget.TextView, android.view.View
    protected void drawableStateChanged() {
        super.drawableStateChanged();
        C0231e c0231e = this.f4125b;
        if (c0231e != null) {
            c0231e.b();
        }
        C c3 = this.f4126c;
        if (c3 != null) {
            c3.b();
        }
    }

    @Override // android.widget.TextView
    public ActionMode.Callback getCustomSelectionActionModeCallback() {
        return androidx.core.widget.i.n(super.getCustomSelectionActionModeCallback());
    }

    public ColorStateList getSupportBackgroundTintList() {
        C0231e c0231e = this.f4125b;
        if (c0231e != null) {
            return c0231e.c();
        }
        return null;
    }

    public PorterDuff.Mode getSupportBackgroundTintMode() {
        C0231e c0231e = this.f4125b;
        if (c0231e != null) {
            return c0231e.d();
        }
        return null;
    }

    public ColorStateList getSupportCompoundDrawablesTintList() {
        return this.f4126c.j();
    }

    public PorterDuff.Mode getSupportCompoundDrawablesTintMode() {
        return this.f4126c.k();
    }

    @Override // android.widget.TextView
    public TextClassifier getTextClassifier() {
        B b3;
        return (Build.VERSION.SDK_INT >= 28 || (b3 = this.f4127d) == null) ? getSuperCaller().a() : b3.a();
    }

    @Override // android.widget.TextView, android.view.View
    public InputConnection onCreateInputConnection(EditorInfo editorInfo) {
        String[] strArrU;
        InputConnection inputConnectionOnCreateInputConnection = super.onCreateInputConnection(editorInfo);
        this.f4126c.r(this, inputConnectionOnCreateInputConnection, editorInfo);
        InputConnection inputConnectionA = AbstractC0241o.a(inputConnectionOnCreateInputConnection, editorInfo, this);
        if (inputConnectionA != null && Build.VERSION.SDK_INT <= 30 && (strArrU = androidx.core.view.V.u(this)) != null) {
            AbstractC0701c.d(editorInfo, strArrU);
            inputConnectionA = u.e.c(this, inputConnectionA, editorInfo);
        }
        return this.f4129f.d(inputConnectionA, editorInfo);
    }

    @Override // android.view.View
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        int i3 = Build.VERSION.SDK_INT;
        if (i3 < 30 || i3 >= 33) {
            return;
        }
        ((InputMethodManager) getContext().getSystemService("input_method")).isActive(this);
    }

    @Override // android.widget.TextView, android.view.View
    public boolean onDragEvent(DragEvent dragEvent) {
        if (AbstractC0249x.a(this, dragEvent)) {
            return true;
        }
        return super.onDragEvent(dragEvent);
    }

    @Override // android.widget.EditText, android.widget.TextView
    public boolean onTextContextMenuItem(int i3) {
        if (AbstractC0249x.b(this, i3)) {
            return true;
        }
        return super.onTextContextMenuItem(i3);
    }

    @Override // android.view.View
    public void setBackgroundDrawable(Drawable drawable) {
        super.setBackgroundDrawable(drawable);
        C0231e c0231e = this.f4125b;
        if (c0231e != null) {
            c0231e.f(drawable);
        }
    }

    @Override // android.view.View
    public void setBackgroundResource(int i3) {
        super.setBackgroundResource(i3);
        C0231e c0231e = this.f4125b;
        if (c0231e != null) {
            c0231e.g(i3);
        }
    }

    @Override // android.widget.TextView
    public void setCompoundDrawables(Drawable drawable, Drawable drawable2, Drawable drawable3, Drawable drawable4) {
        super.setCompoundDrawables(drawable, drawable2, drawable3, drawable4);
        C c3 = this.f4126c;
        if (c3 != null) {
            c3.p();
        }
    }

    @Override // android.widget.TextView
    public void setCompoundDrawablesRelative(Drawable drawable, Drawable drawable2, Drawable drawable3, Drawable drawable4) {
        super.setCompoundDrawablesRelative(drawable, drawable2, drawable3, drawable4);
        C c3 = this.f4126c;
        if (c3 != null) {
            c3.p();
        }
    }

    @Override // android.widget.TextView
    public void setCustomSelectionActionModeCallback(ActionMode.Callback callback) {
        super.setCustomSelectionActionModeCallback(androidx.core.widget.i.o(this, callback));
    }

    public void setEmojiCompatEnabled(boolean z3) {
        this.f4129f.e(z3);
    }

    @Override // android.widget.TextView
    public void setKeyListener(KeyListener keyListener) {
        super.setKeyListener(this.f4129f.a(keyListener));
    }

    public void setSupportBackgroundTintList(ColorStateList colorStateList) {
        C0231e c0231e = this.f4125b;
        if (c0231e != null) {
            c0231e.i(colorStateList);
        }
    }

    public void setSupportBackgroundTintMode(PorterDuff.Mode mode) {
        C0231e c0231e = this.f4125b;
        if (c0231e != null) {
            c0231e.j(mode);
        }
    }

    public void setSupportCompoundDrawablesTintList(ColorStateList colorStateList) {
        this.f4126c.w(colorStateList);
        this.f4126c.b();
    }

    public void setSupportCompoundDrawablesTintMode(PorterDuff.Mode mode) {
        this.f4126c.x(mode);
        this.f4126c.b();
    }

    @Override // android.widget.TextView
    public void setTextAppearance(Context context, int i3) {
        super.setTextAppearance(context, i3);
        C c3 = this.f4126c;
        if (c3 != null) {
            c3.q(context, i3);
        }
    }

    @Override // android.widget.TextView
    public void setTextClassifier(TextClassifier textClassifier) {
        B b3;
        if (Build.VERSION.SDK_INT >= 28 || (b3 = this.f4127d) == null) {
            getSuperCaller().b(textClassifier);
        } else {
            b3.b(textClassifier);
        }
    }

    public C0238l(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, AbstractC0502a.f8813y);
    }

    @Override // android.widget.EditText, android.widget.TextView
    public Editable getText() {
        return Build.VERSION.SDK_INT >= 28 ? super.getText() : super.getEditableText();
    }

    public C0238l(Context context, AttributeSet attributeSet, int i3) {
        super(d0.b(context), attributeSet, i3);
        c0.a(this, getContext());
        C0231e c0231e = new C0231e(this);
        this.f4125b = c0231e;
        c0231e.e(attributeSet, i3);
        C c3 = new C(this);
        this.f4126c = c3;
        c3.m(attributeSet, i3);
        c3.b();
        this.f4127d = new B(this);
        this.f4128e = new androidx.core.widget.j();
        C0239m c0239m = new C0239m(this);
        this.f4129f = c0239m;
        c0239m.c(attributeSet, i3);
        d(c0239m);
    }
}
