package s0;

import android.graphics.drawable.Drawable;

/* JADX INFO: renamed from: s0.e, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0685e {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final C0685e f10009a = new C0685e();

    private C0685e() {
    }

    public static final void a(Drawable drawable, Drawable drawable2) {
        if (drawable2 == null || drawable == null || drawable == drawable2) {
            return;
        }
        drawable.setBounds(drawable2.getBounds());
        drawable.setChangingConfigurations(drawable2.getChangingConfigurations());
        drawable.setLevel(drawable2.getLevel());
        drawable.setVisible(drawable2.isVisible(), false);
        drawable.setState(drawable2.getState());
    }

    public static final int b(int i3) {
        int i4 = i3 >>> 24;
        if (i4 != 0) {
            return i4 != 255 ? -3 : -1;
        }
        return -2;
    }

    public static final int c(int i3, int i4) {
        if (i4 == 255) {
            return i3;
        }
        if (i4 == 0) {
            return i3 & 16777215;
        }
        return (i3 & 16777215) | ((((i3 >>> 24) * (i4 + (i4 >> 7))) >> 8) << 24);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static final void d(Drawable drawable, Drawable.Callback callback, D d3) {
        if (drawable == 0) {
            return;
        }
        drawable.setCallback(callback);
        C c3 = drawable instanceof C ? (C) drawable : null;
        if (c3 != null) {
            c3.i(d3);
        }
    }

    public static final void e(Drawable drawable, C0684d c0684d) {
        if (drawable == null || c0684d == null) {
            return;
        }
        c0684d.a(drawable);
    }
}
