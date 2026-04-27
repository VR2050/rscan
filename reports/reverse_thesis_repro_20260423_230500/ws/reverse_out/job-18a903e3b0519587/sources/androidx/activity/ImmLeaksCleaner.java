package androidx.activity;

import android.app.Activity;
import android.view.View;
import android.view.inputmethod.InputMethodManager;
import androidx.lifecycle.f;
import java.lang.reflect.Field;

/* JADX INFO: loaded from: classes.dex */
final class ImmLeaksCleaner implements androidx.lifecycle.i {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static int f2959b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private static Field f2960c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private static Field f2961d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private static Field f2962e;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private Activity f2963a;

    private static void h() {
        try {
            f2959b = 2;
            Field declaredField = InputMethodManager.class.getDeclaredField("mServedView");
            f2961d = declaredField;
            declaredField.setAccessible(true);
            Field declaredField2 = InputMethodManager.class.getDeclaredField("mNextServedView");
            f2962e = declaredField2;
            declaredField2.setAccessible(true);
            Field declaredField3 = InputMethodManager.class.getDeclaredField("mH");
            f2960c = declaredField3;
            declaredField3.setAccessible(true);
            f2959b = 1;
        } catch (NoSuchFieldException unused) {
        }
    }

    @Override // androidx.lifecycle.i
    public void d(androidx.lifecycle.k kVar, f.a aVar) {
        if (aVar != f.a.ON_DESTROY) {
            return;
        }
        if (f2959b == 0) {
            h();
        }
        if (f2959b == 1) {
            InputMethodManager inputMethodManager = (InputMethodManager) this.f2963a.getSystemService("input_method");
            try {
                Object obj = f2960c.get(inputMethodManager);
                if (obj == null) {
                    return;
                }
                synchronized (obj) {
                    try {
                        try {
                            try {
                                View view = (View) f2961d.get(inputMethodManager);
                                if (view == null) {
                                    return;
                                }
                                if (view.isAttachedToWindow()) {
                                    return;
                                }
                                try {
                                    f2962e.set(inputMethodManager, null);
                                    inputMethodManager.isActive();
                                } catch (IllegalAccessException unused) {
                                }
                            } catch (ClassCastException unused2) {
                            }
                        } catch (IllegalAccessException unused3) {
                        }
                    } catch (Throwable th) {
                        throw th;
                    }
                }
            } catch (IllegalAccessException unused4) {
            }
        }
    }
}
