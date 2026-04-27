package com.facebook.react.defaults;

import android.app.Application;
import android.content.Context;
import c1.EnumC0334f;
import c1.InterfaceC0351x;
import c1.K;
import c1.Q;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.UIManager;
import com.facebook.react.bridge.UIManagerProvider;
import com.facebook.react.defaults.DefaultTurboModuleManagerDelegate;
import com.facebook.react.fabric.ComponentFactory;
import com.facebook.react.runtime.JSCInstance;
import com.facebook.react.runtime.JSRuntimeFactory;
import com.facebook.react.runtime.hermes.HermesInstance;
import com.facebook.react.uimanager.U0;
import com.facebook.react.uimanager.V0;
import com.facebook.react.uimanager.ViewManager;
import f1.C0527a;
import h2.C0562h;
import i2.AbstractC0586n;
import java.util.Collection;
import java.util.List;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public abstract class f extends K {

    public static final class a implements V0 {
        a() {
        }

        @Override // com.facebook.react.uimanager.V0
        public ViewManager a(String str) {
            j.f(str, "viewManagerName");
            return f.this.o().z(str);
        }

        @Override // com.facebook.react.uimanager.V0
        public Collection b() {
            return f.this.o().H();
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    protected f(Application application) {
        super(application);
        j.f(application, "application");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final UIManager x(f fVar, ReactApplicationContext reactApplicationContext) {
        j.f(reactApplicationContext, "reactApplicationContext");
        ComponentFactory componentFactory = new ComponentFactory();
        DefaultComponentsRegistry.register(componentFactory);
        return new com.facebook.react.fabric.f(componentFactory, fVar.l() ? new U0(fVar.new a()) : new U0(fVar.o().G(reactApplicationContext))).createUIManager(reactApplicationContext);
    }

    public final InterfaceC0351x A(Context context, JSRuntimeFactory jSRuntimeFactory) {
        j.f(context, "context");
        if (jSRuntimeFactory == null) {
            jSRuntimeFactory = j.b(y(), Boolean.FALSE) ? new JSCInstance() : new HermesInstance();
        }
        JSRuntimeFactory jSRuntimeFactory2 = jSRuntimeFactory;
        List listM = m();
        j.e(listM, "getPackages(...)");
        String strJ = j();
        j.e(strJ, "getJSMainModuleName(...)");
        String strC = c();
        if (strC == null) {
            strC = "index";
        }
        return d.c(context, listM, (128 & 4) != 0 ? "index" : strJ, (128 & 8) == 0 ? strC : "index", (128 & 16) != 0 ? null : g(), (128 & 32) == 0 ? jSRuntimeFactory2 : null, (128 & 64) != 0 ? C0527a.f9198b : u(), (128 & 128) != 0 ? AbstractC0586n.g() : null);
    }

    @Override // c1.K
    protected EnumC0334f h() {
        Boolean boolY = y();
        if (j.b(boolY, Boolean.TRUE)) {
            return EnumC0334f.f5564c;
        }
        if (j.b(boolY, Boolean.FALSE)) {
            return EnumC0334f.f5563b;
        }
        if (boolY == null) {
            return null;
        }
        throw new C0562h();
    }

    @Override // c1.K
    protected Q.a p() {
        if (z()) {
            return new DefaultTurboModuleManagerDelegate.a();
        }
        return null;
    }

    @Override // c1.K
    protected UIManagerProvider t() {
        if (z()) {
            return new UIManagerProvider() { // from class: com.facebook.react.defaults.e
                @Override // com.facebook.react.bridge.UIManagerProvider
                public final UIManager createUIManager(ReactApplicationContext reactApplicationContext) {
                    return f.x(this.f6697a, reactApplicationContext);
                }
            };
        }
        return null;
    }

    protected abstract Boolean y();

    protected abstract boolean z();
}
