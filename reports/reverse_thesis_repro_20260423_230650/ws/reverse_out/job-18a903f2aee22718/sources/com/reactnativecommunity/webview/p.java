package com.reactnativecommunity.webview;

import c1.X;
import com.facebook.react.bridge.NativeModule;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.module.model.ReactModuleInfo;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import v1.InterfaceC0708a;

/* JADX INFO: loaded from: classes.dex */
public class p extends X {
    /* JADX INFO: Access modifiers changed from: private */
    public static /* synthetic */ Map l() {
        HashMap map = new HashMap();
        map.put(NativeRNCWebViewModuleSpec.NAME, new ReactModuleInfo(NativeRNCWebViewModuleSpec.NAME, NativeRNCWebViewModuleSpec.NAME, false, false, true, false, true));
        return map;
    }

    @Override // c1.AbstractC0329a, c1.L
    public List f(ReactApplicationContext reactApplicationContext) {
        ArrayList arrayList = new ArrayList();
        arrayList.add(new RNCWebViewManager());
        return arrayList;
    }

    @Override // c1.AbstractC0329a
    public NativeModule g(String str, ReactApplicationContext reactApplicationContext) {
        if (str.equals(NativeRNCWebViewModuleSpec.NAME)) {
            return new RNCWebViewModule(reactApplicationContext);
        }
        return null;
    }

    @Override // c1.AbstractC0329a
    public InterfaceC0708a i() {
        return new InterfaceC0708a() { // from class: com.reactnativecommunity.webview.o
            @Override // v1.InterfaceC0708a
            public final Map a() {
                return p.l();
            }
        };
    }
}
