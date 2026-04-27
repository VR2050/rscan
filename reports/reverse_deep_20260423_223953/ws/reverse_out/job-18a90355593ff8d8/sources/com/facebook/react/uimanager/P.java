package com.facebook.react.uimanager;

import android.view.View;
import com.facebook.react.bridge.JSApplicationCausedNativeException;

/* JADX INFO: loaded from: classes.dex */
public class P extends JSApplicationCausedNativeException {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private View f7481b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public P(String str) {
        super(str);
        t2.j.f(str, "msg");
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public P(String str, View view, Throwable th) {
        super(str, th);
        t2.j.f(str, "msg");
        t2.j.f(th, "cause");
        this.f7481b = view;
    }
}
