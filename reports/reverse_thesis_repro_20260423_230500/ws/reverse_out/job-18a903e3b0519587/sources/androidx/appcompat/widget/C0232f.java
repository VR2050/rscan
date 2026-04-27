package androidx.appcompat.widget;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.text.InputFilter;
import android.util.AttributeSet;
import android.view.ActionMode;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;
import android.widget.Button;
import d.AbstractC0502a;

/* JADX INFO: renamed from: androidx.appcompat.widget.f, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0232f extends Button {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final C0231e f4064b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final C f4065c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private C0240n f4066d;

    public C0232f(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, AbstractC0502a.f8802n);
    }

    private C0240n getEmojiTextViewHelper() {
        if (this.f4066d == null) {
            this.f4066d = new C0240n(this);
        }
        return this.f4066d;
    }

    @Override // android.widget.TextView, android.view.View
    protected void drawableStateChanged() {
        super.drawableStateChanged();
        C0231e c0231e = this.f4064b;
        if (c0231e != null) {
            c0231e.b();
        }
        C c3 = this.f4065c;
        if (c3 != null) {
            c3.b();
        }
    }

    @Override // android.widget.TextView
    public int getAutoSizeMaxTextSize() {
        if (r0.f4172c) {
            return super.getAutoSizeMaxTextSize();
        }
        C c3 = this.f4065c;
        if (c3 != null) {
            return c3.e();
        }
        return -1;
    }

    @Override // android.widget.TextView
    public int getAutoSizeMinTextSize() {
        if (r0.f4172c) {
            return super.getAutoSizeMinTextSize();
        }
        C c3 = this.f4065c;
        if (c3 != null) {
            return c3.f();
        }
        return -1;
    }

    @Override // android.widget.TextView
    public int getAutoSizeStepGranularity() {
        if (r0.f4172c) {
            return super.getAutoSizeStepGranularity();
        }
        C c3 = this.f4065c;
        if (c3 != null) {
            return c3.g();
        }
        return -1;
    }

    @Override // android.widget.TextView
    public int[] getAutoSizeTextAvailableSizes() {
        if (r0.f4172c) {
            return super.getAutoSizeTextAvailableSizes();
        }
        C c3 = this.f4065c;
        return c3 != null ? c3.h() : new int[0];
    }

    @Override // android.widget.TextView
    public int getAutoSizeTextType() {
        if (r0.f4172c) {
            return super.getAutoSizeTextType() == 1 ? 1 : 0;
        }
        C c3 = this.f4065c;
        if (c3 != null) {
            return c3.i();
        }
        return 0;
    }

    @Override // android.widget.TextView
    public ActionMode.Callback getCustomSelectionActionModeCallback() {
        return androidx.core.widget.i.n(super.getCustomSelectionActionModeCallback());
    }

    public ColorStateList getSupportBackgroundTintList() {
        C0231e c0231e = this.f4064b;
        if (c0231e != null) {
            return c0231e.c();
        }
        return null;
    }

    public PorterDuff.Mode getSupportBackgroundTintMode() {
        C0231e c0231e = this.f4064b;
        if (c0231e != null) {
            return c0231e.d();
        }
        return null;
    }

    public ColorStateList getSupportCompoundDrawablesTintList() {
        return this.f4065c.j();
    }

    public PorterDuff.Mode getSupportCompoundDrawablesTintMode() {
        return this.f4065c.k();
    }

    @Override // android.view.View
    public void onInitializeAccessibilityEvent(AccessibilityEvent accessibilityEvent) {
        super.onInitializeAccessibilityEvent(accessibilityEvent);
        accessibilityEvent.setClassName(Button.class.getName());
    }

    @Override // android.view.View
    public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo accessibilityNodeInfo) {
        super.onInitializeAccessibilityNodeInfo(accessibilityNodeInfo);
        accessibilityNodeInfo.setClassName(Button.class.getName());
    }

    @Override // android.widget.TextView, android.view.View
    protected void onLayout(boolean z3, int i3, int i4, int i5, int i6) {
        super.onLayout(z3, i3, i4, i5, i6);
        C c3 = this.f4065c;
        if (c3 != null) {
            c3.o(z3, i3, i4, i5, i6);
        }
    }

    @Override // android.widget.TextView
    protected void onTextChanged(CharSequence charSequence, int i3, int i4, int i5) {
        super.onTextChanged(charSequence, i3, i4, i5);
        C c3 = this.f4065c;
        if (c3 == null || r0.f4172c || !c3.l()) {
            return;
        }
        this.f4065c.c();
    }

    @Override // android.widget.TextView
    public void setAllCaps(boolean z3) {
        super.setAllCaps(z3);
        getEmojiTextViewHelper().d(z3);
    }

    @Override // android.widget.TextView
    public void setAutoSizeTextTypeUniformWithConfiguration(int i3, int i4, int i5, int i6) {
        if (r0.f4172c) {
            super.setAutoSizeTextTypeUniformWithConfiguration(i3, i4, i5, i6);
            return;
        }
        C c3 = this.f4065c;
        if (c3 != null) {
            c3.t(i3, i4, i5, i6);
        }
    }

    @Override // android.widget.TextView
    public void setAutoSizeTextTypeUniformWithPresetSizes(int[] iArr, int i3) {
        if (r0.f4172c) {
            super.setAutoSizeTextTypeUniformWithPresetSizes(iArr, i3);
            return;
        }
        C c3 = this.f4065c;
        if (c3 != null) {
            c3.u(iArr, i3);
        }
    }

    @Override // android.widget.TextView
    public void setAutoSizeTextTypeWithDefaults(int i3) {
        if (r0.f4172c) {
            super.setAutoSizeTextTypeWithDefaults(i3);
            return;
        }
        C c3 = this.f4065c;
        if (c3 != null) {
            c3.v(i3);
        }
    }

    @Override // android.view.View
    public void setBackgroundDrawable(Drawable drawable) {
        super.setBackgroundDrawable(drawable);
        C0231e c0231e = this.f4064b;
        if (c0231e != null) {
            c0231e.f(drawable);
        }
    }

    @Override // android.view.View
    public void setBackgroundResource(int i3) {
        super.setBackgroundResource(i3);
        C0231e c0231e = this.f4064b;
        if (c0231e != null) {
            c0231e.g(i3);
        }
    }

    @Override // android.widget.TextView
    public void setCustomSelectionActionModeCallback(ActionMode.Callback callback) {
        super.setCustomSelectionActionModeCallback(androidx.core.widget.i.o(this, callback));
    }

    public void setEmojiCompatEnabled(boolean z3) {
        getEmojiTextViewHelper().e(z3);
    }

    @Override // android.widget.TextView
    public void setFilters(InputFilter[] inputFilterArr) {
        super.setFilters(getEmojiTextViewHelper().a(inputFilterArr));
    }

    public void setSupportAllCaps(boolean z3) {
        C c3 = this.f4065c;
        if (c3 != null) {
            c3.s(z3);
        }
    }

    public void setSupportBackgroundTintList(ColorStateList colorStateList) {
        C0231e c0231e = this.f4064b;
        if (c0231e != null) {
            c0231e.i(colorStateList);
        }
    }

    public void setSupportBackgroundTintMode(PorterDuff.Mode mode) {
        C0231e c0231e = this.f4064b;
        if (c0231e != null) {
            c0231e.j(mode);
        }
    }

    public void setSupportCompoundDrawablesTintList(ColorStateList colorStateList) {
        this.f4065c.w(colorStateList);
        this.f4065c.b();
    }

    public void setSupportCompoundDrawablesTintMode(PorterDuff.Mode mode) {
        this.f4065c.x(mode);
        this.f4065c.b();
    }

    @Override // android.widget.TextView
    public void setTextAppearance(Context context, int i3) {
        super.setTextAppearance(context, i3);
        C c3 = this.f4065c;
        if (c3 != null) {
            c3.q(context, i3);
        }
    }

    @Override // android.widget.TextView
    public void setTextSize(int i3, float f3) {
        if (r0.f4172c) {
            super.setTextSize(i3, f3);
            return;
        }
        C c3 = this.f4065c;
        if (c3 != null) {
            c3.A(i3, f3);
        }
    }

    public C0232f(Context context, AttributeSet attributeSet, int i3) {
        super(d0.b(context), attributeSet, i3);
        c0.a(this, getContext());
        C0231e c0231e = new C0231e(this);
        this.f4064b = c0231e;
        c0231e.e(attributeSet, i3);
        C c3 = new C(this);
        this.f4065c = c3;
        c3.m(attributeSet, i3);
        c3.b();
        getEmojiTextViewHelper().c(attributeSet, i3);
    }
}
