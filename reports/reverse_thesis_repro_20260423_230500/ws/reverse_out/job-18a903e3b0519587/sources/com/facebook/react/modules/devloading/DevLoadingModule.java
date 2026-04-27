package com.facebook.react.modules.devloading;

import com.facebook.fbreact.specs.NativeDevLoadingViewSpec;
import com.facebook.react.bridge.JSExceptionHandler;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.UiThreadUtil;
import com.facebook.react.devsupport.E;
import com.facebook.react.modules.devloading.DevLoadingModule;
import j1.InterfaceC0594c;
import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;
import u1.InterfaceC0703a;

/* JADX INFO: loaded from: classes.dex */
@InterfaceC0703a(name = "DevLoadingView")
public final class DevLoadingModule extends NativeDevLoadingViewSpec {
    public static final a Companion = new a(null);
    public static final String NAME = "DevLoadingView";
    private InterfaceC0594c devLoadingViewManager;
    private final JSExceptionHandler jsExceptionHandler;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public DevLoadingModule(ReactApplicationContext reactApplicationContext) {
        super(reactApplicationContext);
        j.f(reactApplicationContext, "reactContext");
        JSExceptionHandler jSExceptionHandler = reactApplicationContext.getJSExceptionHandler();
        this.jsExceptionHandler = jSExceptionHandler;
        if (jSExceptionHandler == null || !(jSExceptionHandler instanceof E)) {
            return;
        }
        this.devLoadingViewManager = ((E) jSExceptionHandler).e0();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void hide$lambda$1(DevLoadingModule devLoadingModule) {
        InterfaceC0594c interfaceC0594c = devLoadingModule.devLoadingViewManager;
        if (interfaceC0594c != null) {
            interfaceC0594c.c();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void showMessage$lambda$0(DevLoadingModule devLoadingModule, String str) {
        InterfaceC0594c interfaceC0594c = devLoadingModule.devLoadingViewManager;
        if (interfaceC0594c != null) {
            interfaceC0594c.a(str);
        }
    }

    @Override // com.facebook.fbreact.specs.NativeDevLoadingViewSpec
    public void hide() {
        UiThreadUtil.runOnUiThread(new Runnable() { // from class: C1.a
            @Override // java.lang.Runnable
            public final void run() {
                DevLoadingModule.hide$lambda$1(this.f575b);
            }
        });
    }

    @Override // com.facebook.fbreact.specs.NativeDevLoadingViewSpec
    public void showMessage(final String str, Double d3, Double d4) {
        j.f(str, "message");
        UiThreadUtil.runOnUiThread(new Runnable() { // from class: C1.b
            @Override // java.lang.Runnable
            public final void run() {
                DevLoadingModule.showMessage$lambda$0(this.f576b, str);
            }
        });
    }
}
