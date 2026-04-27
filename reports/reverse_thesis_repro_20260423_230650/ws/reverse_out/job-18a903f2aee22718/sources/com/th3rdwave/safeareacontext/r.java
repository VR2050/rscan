package com.th3rdwave.safeareacontext;

import android.content.Context;
import android.view.View;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.uimanager.H0;

/* JADX INFO: loaded from: classes.dex */
public abstract class r {
    public static final ReactContext a(View view) {
        t2.j.f(view, "view");
        ReactContext reactContextD = H0.d(view);
        t2.j.e(reactContextD, "getReactContext(...)");
        return reactContextD;
    }

    public static final int b(Context context) {
        t2.j.f(context, "context");
        return H0.e(context);
    }
}
