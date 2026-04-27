package com.facebook.react.runtime;

import c1.AbstractC0329a;
import com.facebook.react.bridge.NativeModule;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.devsupport.LogBoxModule;
import com.facebook.react.module.model.ReactModuleInfo;
import com.facebook.react.modules.core.DeviceEventManagerModule;
import com.facebook.react.modules.core.ExceptionsManagerModule;
import com.facebook.react.modules.debug.DevMenuModule;
import com.facebook.react.modules.debug.DevSettingsModule;
import com.facebook.react.modules.debug.SourceCodeModule;
import com.facebook.react.modules.deviceinfo.DeviceInfoModule;
import com.facebook.react.modules.systeminfo.AndroidInfoModule;
import d1.C0505a;
import java.util.HashMap;
import java.util.Map;
import u1.InterfaceC0703a;
import v1.InterfaceC0708a;

/* JADX INFO: renamed from: com.facebook.react.runtime.e, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
class C0412e extends AbstractC0329a {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final j1.e f7297a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final A1.a f7298b;

    public C0412e(j1.e eVar, A1.a aVar) {
        this.f7297a = eVar;
        this.f7298b = aVar;
    }

    private InterfaceC0708a l() {
        Class[] clsArr = {AndroidInfoModule.class, DeviceInfoModule.class, SourceCodeModule.class, DevMenuModule.class, DevSettingsModule.class, DeviceEventManagerModule.class, LogBoxModule.class, ExceptionsManagerModule.class};
        final HashMap map = new HashMap();
        for (int i3 = 0; i3 < 8; i3++) {
            Class cls = clsArr[i3];
            InterfaceC0703a interfaceC0703a = (InterfaceC0703a) cls.getAnnotation(InterfaceC0703a.class);
            if (interfaceC0703a != null) {
                map.put(interfaceC0703a.name(), new ReactModuleInfo(interfaceC0703a.name(), cls.getName(), interfaceC0703a.canOverrideExistingModule(), interfaceC0703a.needsEagerInit(), interfaceC0703a.isCxxModule(), ReactModuleInfo.b(cls)));
            }
        }
        return new InterfaceC0708a() { // from class: com.facebook.react.runtime.d
            @Override // v1.InterfaceC0708a
            public final Map a() {
                return C0412e.m(map);
            }
        };
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static /* synthetic */ Map m(Map map) {
        return map;
    }

    @Override // c1.AbstractC0329a
    public NativeModule g(String str, ReactApplicationContext reactApplicationContext) {
        str.hashCode();
        switch (str) {
            case "LogBox":
                return new LogBoxModule(reactApplicationContext, this.f7297a);
            case "DevSettings":
                return new DevSettingsModule(reactApplicationContext, this.f7297a);
            case "DeviceInfo":
                return new DeviceInfoModule(reactApplicationContext);
            case "DevMenu":
                return new DevMenuModule(reactApplicationContext, this.f7297a);
            case "DeviceEventManager":
                return new DeviceEventManagerModule(reactApplicationContext, this.f7298b);
            case "PlatformConstants":
                return new AndroidInfoModule(reactApplicationContext);
            case "ExceptionsManager":
                return new ExceptionsManagerModule(this.f7297a);
            case "SourceCode":
                return new SourceCodeModule(reactApplicationContext);
            default:
                return null;
        }
    }

    @Override // c1.AbstractC0329a
    public InterfaceC0708a i() {
        if (!C0505a.a()) {
            return l();
        }
        try {
            return (InterfaceC0708a) ((Class) Z0.a.c(C0505a.b(C0412e.class.getName() + "$$ReactModuleInfoProvider"))).newInstance();
        } catch (ClassNotFoundException unused) {
            return l();
        } catch (IllegalAccessException e3) {
            throw new RuntimeException("No ReactModuleInfoProvider for " + C0412e.class.getName() + "$$ReactModuleInfoProvider", e3);
        } catch (InstantiationException e4) {
            throw new RuntimeException("No ReactModuleInfoProvider for " + C0412e.class.getName() + "$$ReactModuleInfoProvider", e4);
        }
    }
}
