package androidx.appcompat.widget;

import android.content.res.TypedArray;
import android.text.InputFilter;
import android.text.method.TransformationMethod;
import android.util.AttributeSet;
import android.widget.TextView;

/* JADX INFO: renamed from: androidx.appcompat.widget.n, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
class C0240n {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final TextView f4135a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final z.f f4136b;

    C0240n(TextView textView) {
        this.f4135a = textView;
        this.f4136b = new z.f(textView, false);
    }

    InputFilter[] a(InputFilter[] inputFilterArr) {
        return this.f4136b.a(inputFilterArr);
    }

    public boolean b() {
        return this.f4136b.b();
    }

    void c(AttributeSet attributeSet, int i3) {
        TypedArray typedArrayObtainStyledAttributes = this.f4135a.getContext().obtainStyledAttributes(attributeSet, d.j.f9067g0, i3, 0);
        try {
            boolean z3 = typedArrayObtainStyledAttributes.hasValue(d.j.f9123u0) ? typedArrayObtainStyledAttributes.getBoolean(d.j.f9123u0, true) : true;
            typedArrayObtainStyledAttributes.recycle();
            e(z3);
        } catch (Throwable th) {
            typedArrayObtainStyledAttributes.recycle();
            throw th;
        }
    }

    void d(boolean z3) {
        this.f4136b.c(z3);
    }

    void e(boolean z3) {
        this.f4136b.d(z3);
    }

    public TransformationMethod f(TransformationMethod transformationMethod) {
        return this.f4136b.e(transformationMethod);
    }
}
