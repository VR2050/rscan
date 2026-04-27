package com.th3rdwave.safeareacontext;

import c1.AbstractC0329a;
import com.facebook.react.bridge.NativeModule;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.module.model.ReactModuleInfo;
import i2.AbstractC0586n;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import u1.InterfaceC0703a;
import v1.InterfaceC0708a;

/* JADX INFO: loaded from: classes.dex */
public final class e extends AbstractC0329a {
    /* JADX INFO: Access modifiers changed from: private */
    public static final Map l(Map map) {
        return map;
    }

    @Override // c1.AbstractC0329a, c1.L
    public List f(ReactApplicationContext reactApplicationContext) {
        t2.j.f(reactApplicationContext, "reactContext");
        return AbstractC0586n.i(new SafeAreaProviderManager(), new SafeAreaViewManager());
    }

    @Override // c1.AbstractC0329a
    public NativeModule g(String str, ReactApplicationContext reactApplicationContext) {
        t2.j.f(str, "name");
        t2.j.f(reactApplicationContext, "reactContext");
        if (t2.j.b(str, "RNCSafeAreaContext")) {
            return new SafeAreaContextModule(reactApplicationContext);
        }
        return null;
    }

    @Override // c1.AbstractC0329a
    public InterfaceC0708a i() {
        final HashMap map = new HashMap();
        Class cls = new Class[]{SafeAreaContextModule.class}[0];
        InterfaceC0703a interfaceC0703a = (InterfaceC0703a) cls.getAnnotation(InterfaceC0703a.class);
        if (interfaceC0703a != null) {
            String strName = interfaceC0703a.name();
            String strName2 = interfaceC0703a.name();
            String name = cls.getName();
            t2.j.e(name, "getName(...)");
            map.put(strName, new ReactModuleInfo(strName2, name, true, interfaceC0703a.needsEagerInit(), interfaceC0703a.isCxxModule(), true));
        }
        return new InterfaceC0708a() { // from class: com.th3rdwave.safeareacontext.d
            @Override // v1.InterfaceC0708a
            public final Map a() {
                return e.l(map);
            }
        };
    }
}
