package com.facebook.react.runtime;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import com.facebook.react.bridge.JavaScriptExecutorFactory;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.modules.core.DeviceEventManagerModule;

/* JADX INFO: loaded from: classes.dex */
public final class W implements com.facebook.react.devsupport.c0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final ReactHostImpl f7269a;

    public W(ReactHostImpl reactHostImpl) {
        t2.j.f(reactHostImpl, "delegate");
        this.f7269a = reactHostImpl;
    }

    @Override // com.facebook.react.devsupport.c0
    public View a(String str) {
        t2.j.f(str, "appKey");
        Activity activityI = i();
        if (activityI == null || this.f7269a.C0(str)) {
            return null;
        }
        e0 e0VarF = e0.f(activityI, str, new Bundle());
        t2.j.e(e0VarF, "createWithView(...)");
        e0VarF.c(this.f7269a);
        e0VarF.start();
        return e0VarF.a();
    }

    @Override // com.facebook.react.devsupport.c0
    public void b(View view) {
        t2.j.f(view, "rootView");
    }

    @Override // com.facebook.react.devsupport.c0
    public void g() {
        DeviceEventManagerModule.RCTDeviceEventEmitter rCTDeviceEventEmitter;
        ReactContext reactContextF0 = this.f7269a.f0();
        if (reactContextF0 == null || (rCTDeviceEventEmitter = (DeviceEventManagerModule.RCTDeviceEventEmitter) reactContextF0.getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter.class)) == null) {
            return;
        }
        rCTDeviceEventEmitter.emit("toggleElementInspector", null);
    }

    @Override // com.facebook.react.devsupport.c0
    public Activity i() {
        return this.f7269a.l0();
    }

    @Override // com.facebook.react.devsupport.c0
    public void j(String str) {
        t2.j.f(str, "s");
        this.f7269a.x1(str);
    }

    @Override // com.facebook.react.devsupport.c0
    public JavaScriptExecutorFactory k() {
        throw new IllegalStateException("Not implemented for bridgeless mode");
    }
}
