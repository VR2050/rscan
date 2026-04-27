package com.reactnativecommunity.asyncstorage;

import c1.X;
import com.facebook.react.bridge.NativeModule;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.module.model.ReactModuleInfo;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import u1.InterfaceC0703a;
import v1.InterfaceC0708a;

/* JADX INFO: loaded from: classes.dex */
public class i extends X {

    class a implements InterfaceC0708a {
        a() {
        }

        @Override // v1.InterfaceC0708a
        public Map a() {
            HashMap map = new HashMap();
            Class cls = new Class[]{AsyncStorageModule.class}[0];
            InterfaceC0703a interfaceC0703a = (InterfaceC0703a) cls.getAnnotation(InterfaceC0703a.class);
            map.put(interfaceC0703a.name(), new ReactModuleInfo(interfaceC0703a.name(), cls.getName(), interfaceC0703a.canOverrideExistingModule(), interfaceC0703a.needsEagerInit(), interfaceC0703a.hasConstants(), interfaceC0703a.isCxxModule(), true));
            return map;
        }
    }

    @Override // c1.AbstractC0329a, c1.L
    public List f(ReactApplicationContext reactApplicationContext) {
        return Collections.emptyList();
    }

    @Override // c1.AbstractC0329a
    public NativeModule g(String str, ReactApplicationContext reactApplicationContext) {
        str.hashCode();
        if (str.equals("RNCAsyncStorage")) {
            return new AsyncStorageModule(reactApplicationContext);
        }
        return null;
    }

    @Override // c1.AbstractC0329a
    public InterfaceC0708a i() {
        try {
            return (InterfaceC0708a) Class.forName("com.reactnativecommunity.asyncstorage.AsyncStoragePackage$$ReactModuleInfoProvider").newInstance();
        } catch (ClassNotFoundException unused) {
            return new a();
        } catch (IllegalAccessException e3) {
            e = e3;
            throw new RuntimeException("No ReactModuleInfoProvider for com.reactnativecommunity.asyncstorage.AsyncStoragePackage$$ReactModuleInfoProvider", e);
        } catch (InstantiationException e4) {
            e = e4;
            throw new RuntimeException("No ReactModuleInfoProvider for com.reactnativecommunity.asyncstorage.AsyncStoragePackage$$ReactModuleInfoProvider", e);
        }
    }
}
