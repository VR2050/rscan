package com.facebook.react.uimanager;

import android.content.Context;
import android.util.DisplayMetrics;
import android.view.WindowManager;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.bridge.WritableNativeMap;

/* JADX INFO: renamed from: com.facebook.react.uimanager.x, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0478x {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final C0478x f7761a = new C0478x();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static DisplayMetrics f7762b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private static DisplayMetrics f7763c;

    private C0478x() {
    }

    public static final WritableMap a(double d3) {
        if (f7762b == null) {
            throw new IllegalStateException("DisplayMetricsHolder must be initialized with initDisplayMetricsIfNotInitialized or initDisplayMetrics");
        }
        if (f7763c == null) {
            throw new IllegalStateException("DisplayMetricsHolder must be initialized with initDisplayMetricsIfNotInitialized or initDisplayMetrics");
        }
        WritableNativeMap writableNativeMap = new WritableNativeMap();
        C0478x c0478x = f7761a;
        DisplayMetrics displayMetrics = f7762b;
        t2.j.d(displayMetrics, "null cannot be cast to non-null type android.util.DisplayMetrics");
        writableNativeMap.putMap("windowPhysicalPixels", c0478x.b(displayMetrics, d3));
        DisplayMetrics displayMetrics2 = f7763c;
        t2.j.d(displayMetrics2, "null cannot be cast to non-null type android.util.DisplayMetrics");
        writableNativeMap.putMap("screenPhysicalPixels", c0478x.b(displayMetrics2, d3));
        return writableNativeMap;
    }

    private final WritableMap b(DisplayMetrics displayMetrics, double d3) {
        WritableNativeMap writableNativeMap = new WritableNativeMap();
        writableNativeMap.putInt("width", displayMetrics.widthPixels);
        writableNativeMap.putInt("height", displayMetrics.heightPixels);
        writableNativeMap.putDouble("scale", displayMetrics.density);
        writableNativeMap.putDouble("fontScale", d3);
        writableNativeMap.putDouble("densityDpi", displayMetrics.densityDpi);
        return writableNativeMap;
    }

    public static final DisplayMetrics c() {
        DisplayMetrics displayMetrics = f7763c;
        if (displayMetrics == null) {
            throw new IllegalStateException("DisplayMetricsHolder must be initialized with initDisplayMetricsIfNotInitialized or initDisplayMetrics");
        }
        t2.j.d(displayMetrics, "null cannot be cast to non-null type android.util.DisplayMetrics");
        return displayMetrics;
    }

    public static final DisplayMetrics d() {
        DisplayMetrics displayMetrics = f7762b;
        if (displayMetrics == null) {
            throw new IllegalStateException("DisplayMetricsHolder must be initialized with initDisplayMetricsIfNotInitialized or initDisplayMetrics");
        }
        t2.j.d(displayMetrics, "null cannot be cast to non-null type android.util.DisplayMetrics");
        return displayMetrics;
    }

    public static final void e(Context context) {
        t2.j.f(context, "context");
        DisplayMetrics displayMetrics = context.getResources().getDisplayMetrics();
        f7762b = displayMetrics;
        DisplayMetrics displayMetrics2 = new DisplayMetrics();
        displayMetrics2.setTo(displayMetrics);
        Object systemService = context.getSystemService("window");
        t2.j.d(systemService, "null cannot be cast to non-null type android.view.WindowManager");
        ((WindowManager) systemService).getDefaultDisplay().getRealMetrics(displayMetrics2);
        f7763c = displayMetrics2;
    }

    public static final void f(Context context) {
        t2.j.f(context, "context");
        if (f7763c != null) {
            return;
        }
        e(context);
    }
}
