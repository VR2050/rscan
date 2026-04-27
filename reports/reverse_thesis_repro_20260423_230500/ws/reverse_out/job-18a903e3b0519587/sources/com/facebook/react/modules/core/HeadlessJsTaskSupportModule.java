package com.facebook.react.modules.core;

import com.facebook.fbreact.specs.NativeHeadlessJsTaskSupportSpec;
import com.facebook.react.bridge.BaseJavaModule;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import t1.C0696c;
import t2.j;
import u1.InterfaceC0703a;

/* JADX INFO: loaded from: classes.dex */
@InterfaceC0703a(name = NativeHeadlessJsTaskSupportSpec.NAME)
public class HeadlessJsTaskSupportModule extends NativeHeadlessJsTaskSupportSpec {
    public HeadlessJsTaskSupportModule(ReactApplicationContext reactApplicationContext) {
        super(reactApplicationContext);
    }

    @Override // com.facebook.fbreact.specs.NativeHeadlessJsTaskSupportSpec
    public void notifyTaskFinished(double d3) {
        int i3 = (int) d3;
        C0696c.a aVar = C0696c.f10181g;
        ReactApplicationContext reactApplicationContext = getReactApplicationContext();
        j.e(reactApplicationContext, "getReactApplicationContext(...)");
        C0696c c0696cA = aVar.a(reactApplicationContext);
        if (c0696cA.g(i3)) {
            c0696cA.d(i3);
        } else {
            Y.a.G(HeadlessJsTaskSupportModule.class, "Tried to finish non-active task with id %d. Did it time out?", Integer.valueOf(i3));
        }
    }

    @Override // com.facebook.fbreact.specs.NativeHeadlessJsTaskSupportSpec
    public void notifyTaskRetry(double d3, Promise promise) {
        j.f(promise, BaseJavaModule.METHOD_TYPE_PROMISE);
        int i3 = (int) d3;
        C0696c.a aVar = C0696c.f10181g;
        ReactApplicationContext reactApplicationContext = getReactApplicationContext();
        j.e(reactApplicationContext, "getReactApplicationContext(...)");
        C0696c c0696cA = aVar.a(reactApplicationContext);
        if (c0696cA.g(i3)) {
            promise.resolve(Boolean.valueOf(c0696cA.j(i3)));
        } else {
            Y.a.G(HeadlessJsTaskSupportModule.class, "Tried to retry non-active task with id %d. Did it time out?", Integer.valueOf(i3));
            promise.resolve(Boolean.FALSE);
        }
    }
}
