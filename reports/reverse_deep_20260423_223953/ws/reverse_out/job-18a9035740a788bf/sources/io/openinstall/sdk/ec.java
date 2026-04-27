package io.openinstall.sdk;

import android.util.Log;

/* JADX INFO: loaded from: classes3.dex */
public class ec {
    public static boolean a = true;

    public static void a(String str, Object... objArr) {
        Log.d("OpenInstall", String.format(str, objArr));
    }

    public static void b(String str, Object... objArr) {
        Log.w("OpenInstall", String.format(str, objArr));
    }

    public static void c(String str, Object... objArr) {
        Log.e("OpenInstall", String.format(str, objArr));
    }
}
