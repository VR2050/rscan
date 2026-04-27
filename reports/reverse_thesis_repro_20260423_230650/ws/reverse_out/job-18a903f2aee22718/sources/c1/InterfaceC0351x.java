package c1;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import o1.InterfaceC0638a;

/* JADX INFO: renamed from: c1.x, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public interface InterfaceC0351x {
    InterfaceC0638a a(Context context, String str, Bundle bundle);

    void b(Activity activity, A1.a aVar);

    j1.e c();

    void d(Context context);

    void e(Activity activity);

    void f(Activity activity);

    boolean g();

    void h(Activity activity);

    void onActivityResult(Activity activity, int i3, int i4, Intent intent);

    void onNewIntent(Intent intent);

    void onWindowFocusChange(boolean z3);
}
