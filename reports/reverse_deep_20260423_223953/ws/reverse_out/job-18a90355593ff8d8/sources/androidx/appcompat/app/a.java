package androidx.appcompat.app;

import android.content.Context;
import android.content.res.Configuration;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.view.KeyEvent;
import android.view.ViewGroup;
import androidx.appcompat.view.b;

/* JADX INFO: loaded from: classes.dex */
public abstract class a {
    public boolean g() {
        return false;
    }

    public abstract boolean h();

    public abstract void i(boolean z3);

    public abstract int j();

    public abstract Context k();

    public boolean l() {
        return false;
    }

    public abstract void m(Configuration configuration);

    void n() {
    }

    public abstract boolean o(int i3, KeyEvent keyEvent);

    public boolean p(KeyEvent keyEvent) {
        return false;
    }

    public boolean q() {
        return false;
    }

    public abstract void r(boolean z3);

    public abstract void s(boolean z3);

    public abstract void t(CharSequence charSequence);

    public abstract androidx.appcompat.view.b u(b.a aVar);

    /* JADX INFO: renamed from: androidx.appcompat.app.a$a, reason: collision with other inner class name */
    public static class C0049a extends ViewGroup.MarginLayoutParams {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        public int f3124a;

        public C0049a(Context context, AttributeSet attributeSet) {
            super(context, attributeSet);
            this.f3124a = 0;
            TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, d.j.f9118t);
            this.f3124a = typedArrayObtainStyledAttributes.getInt(d.j.f9122u, 0);
            typedArrayObtainStyledAttributes.recycle();
        }

        public C0049a(int i3, int i4) {
            super(i3, i4);
            this.f3124a = 8388627;
        }

        public C0049a(C0049a c0049a) {
            super((ViewGroup.MarginLayoutParams) c0049a);
            this.f3124a = 0;
            this.f3124a = c0049a.f3124a;
        }

        public C0049a(ViewGroup.LayoutParams layoutParams) {
            super(layoutParams);
            this.f3124a = 0;
        }
    }
}
