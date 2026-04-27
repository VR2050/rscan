package com.facebook.react.runtime;

import android.app.Activity;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.common.LifecycleState;

/* JADX INFO: loaded from: classes.dex */
class c0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    LifecycleState f7293a = LifecycleState.f6642b;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final C0410c f7294b;

    c0(C0410c c0410c) {
        this.f7294b = c0410c;
    }

    public LifecycleState a() {
        return this.f7293a;
    }

    public void b(ReactContext reactContext) {
        if (reactContext != null) {
            LifecycleState lifecycleState = this.f7293a;
            if (lifecycleState == LifecycleState.f6643c) {
                this.f7294b.a("ReactContext.onHostDestroy()");
                reactContext.onHostDestroy();
            } else if (lifecycleState == LifecycleState.f6644d) {
                this.f7294b.a("ReactContext.onHostPause()");
                reactContext.onHostPause();
                this.f7294b.a("ReactContext.onHostDestroy()");
                reactContext.onHostDestroy();
            }
        }
        this.f7293a = LifecycleState.f6642b;
    }

    public void c(ReactContext reactContext, Activity activity) {
        if (reactContext != null) {
            LifecycleState lifecycleState = this.f7293a;
            if (lifecycleState == LifecycleState.f6642b) {
                this.f7294b.a("ReactContext.onHostResume()");
                reactContext.onHostResume(activity);
                this.f7294b.a("ReactContext.onHostPause()");
                reactContext.onHostPause();
            } else if (lifecycleState == LifecycleState.f6644d) {
                this.f7294b.a("ReactContext.onHostPause()");
                reactContext.onHostPause();
            }
        }
        this.f7293a = LifecycleState.f6643c;
    }

    public void d(ReactContext reactContext, Activity activity) {
        LifecycleState lifecycleState = this.f7293a;
        LifecycleState lifecycleState2 = LifecycleState.f6644d;
        if (lifecycleState == lifecycleState2) {
            return;
        }
        if (reactContext != null) {
            this.f7294b.a("ReactContext.onHostResume()");
            reactContext.onHostResume(activity);
        }
        this.f7293a = lifecycleState2;
    }

    public void e(ReactContext reactContext, Activity activity) {
        if (this.f7293a == LifecycleState.f6644d) {
            this.f7294b.a("ReactContext.onHostResume()");
            reactContext.onHostResume(activity);
        }
    }
}
