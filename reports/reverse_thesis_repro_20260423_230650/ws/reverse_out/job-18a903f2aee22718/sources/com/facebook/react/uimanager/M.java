package com.facebook.react.uimanager;

import android.view.Choreographer;
import com.facebook.react.bridge.JSExceptionHandler;
import com.facebook.react.bridge.ReactContext;

/* JADX INFO: loaded from: classes.dex */
public abstract class M implements Choreographer.FrameCallback {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final JSExceptionHandler f7384a;

    protected M(JSExceptionHandler jSExceptionHandler) {
        t2.j.f(jSExceptionHandler, "exceptionHandler");
        this.f7384a = jSExceptionHandler;
    }

    protected abstract void a(long j3);

    @Override // android.view.Choreographer.FrameCallback
    public void doFrame(long j3) {
        try {
            a(j3);
        } catch (RuntimeException e3) {
            this.f7384a.handleException(e3);
        }
    }

    /* JADX WARN: Illegal instructions before constructor call */
    protected M(ReactContext reactContext) {
        t2.j.f(reactContext, "reactContext");
        JSExceptionHandler exceptionHandler = reactContext.getExceptionHandler();
        t2.j.e(exceptionHandler, "getExceptionHandler(...)");
        this(exceptionHandler);
    }
}
